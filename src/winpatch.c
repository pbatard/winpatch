/*
 * winpatch - Windows system file patcher
 *
 * Copyright © 2020 Pete Batard <pete@akeo.ie>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef _DEBUG
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <accctrl.h>
#include <aclapi.h>
#include <imagehlp.h>
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>

#include "msapi_utf8.h"

#pragma comment(lib, "imagehlp.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma intrinsic(_byteswap_uint64)

#define _STRINGIFY(x)               #x
#define STRINGIFY(x)                _STRINGIFY(x)
#define MIN_CHUNK_SIZE              2
#define MAX_CHUNK_SIZE              128
#define MAX_HEX_VALUES              32
#define HEX_SPLIT                   64
#ifndef IMAGE_FILE_MACHINE_RISCV64
#define IMAGE_FILE_MACHINE_RISCV64  0x5064
#endif
#ifndef APP_VERSION
#define APP_VERSION_STR             "[DEV]"
#else
#define APP_VERSION_STR             STRINGIFY(APP_VERSION)
#endif

#define pout(fmt, ...) do {fprintf(stdout, fmt, __VA_ARGS__);} while(0)
#define spout(fmt, ...) do {if (!silent) pout(fmt, __VA_ARGS__);} while(0)
#define vpout(fmt, ...) do {if (verbose) pout(fmt, __VA_ARGS__);} while(0)
#define perr(fmt, ...) fprintf(stderr, fmt, __VA_ARGS__)

#define safe_free(p) do {free((void*)p); p = NULL;} while(0)
#define safe_min(a, b) min((size_t)(a), (size_t)(b))
#define safe_strcp(dst, dst_max, src, count) do {memcpy(dst, src, safe_min(count, dst_max)); \
	((char*)dst)[safe_min(count, dst_max)-1] = 0;} while(0)
#define safe_strcpy(dst, dst_max, src) safe_strcp(dst, dst_max, src, safe_strlen(src)+1)
#define static_strcpy(dst, src) safe_strcpy(dst, sizeof(dst), src)
#define safe_strcat(dst, dst_max, src) safe_strncat(dst, dst_max, src, safe_strlen(src)+1)
#define static_strcat(dst, src) safe_strcat(dst, sizeof(dst), src)
#define safe_closehandle(h) do {if ((h != INVALID_HANDLE_VALUE) && (h != NULL)) {CloseHandle(h); h = INVALID_HANDLE_VALUE;}} while(0)
#define safe_strlen(str) ((((char*)str)==NULL)?0:strlen(str))
#define safe_sprintf(dst, count, ...) do {_snprintf_s(dst, count, _TRUNCATE, __VA_ARGS__); (dst)[(count)-1] = 0; } while(0)
#define static_sprintf(dst, ...) safe_sprintf(dst, sizeof(dst), __VA_ARGS__)

typedef struct {
	size_t size;
	uint8_t* org;
	uint8_t* new;
	int patched;
} chunk;

extern BOOL SelfSignFile(LPCSTR szFileName, LPCSTR szCertSubject);
BOOL silent = FALSE, verbose = FALSE;

static DWORD ReadRegistryKey32(HKEY root, const char* key_name)
{
	char long_key_name[MAX_PATH] = { 0 };
	DWORD val = 0;
	HKEY hApp = NULL;
	size_t i;
	LONG s;
	DWORD dwType = -1, dwSize = sizeof(DWORD);

	if (key_name == NULL)
		return 0;

	for (i = safe_strlen(key_name); i > 0; i--) {
		if (key_name[i] == '\\')
			break;
	}

	if (i >= sizeof(long_key_name))
		return 0;

	static_strcpy(long_key_name, key_name);
	long_key_name[i++] = 0;

	if (RegOpenKeyExA(root, long_key_name, 0, KEY_READ, &hApp) != ERROR_SUCCESS)
		return 0;

	s = RegQueryValueExA(hApp, &key_name[i], NULL, &dwType, (LPBYTE)&val, &dwSize);
	if ((s != ERROR_SUCCESS) || (dwType != REG_DWORD) || (dwSize == 0))
		val = 0;

	RegCloseKey(hApp);
	return val;
}


static __inline char* appname(const char* path)
{
	static char appname[128];
	_splitpath_s(path, NULL, 0, NULL, 0, appname, sizeof(appname), NULL, 0);
	return appname;
}

/*
 * Returns true if:
 * 1. The OS supports UAC, UAC is on, and the current process runs elevated, or
 * 2. The OS doesn't support UAC or UAC is off, and the process is being run by a member of the admin group
 */
BOOL IsCurrentProcessElevated(void)
{
	BOOL r = FALSE;
	DWORD size;
	HANDLE token = INVALID_HANDLE_VALUE;
	TOKEN_ELEVATION te;
	SID_IDENTIFIER_AUTHORITY auth = { SECURITY_NT_AUTHORITY };
	PSID psid;

	if (ReadRegistryKey32(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA") == 1) {
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
			perr("Could not get current process token: Error %u\n", GetLastError());
			goto out;
		}
		if (!GetTokenInformation(token, TokenElevation, &te, sizeof(te), &size)) {
			perr("Could not get token information: Error %u\n", GetLastError());
			goto out;
		}
		r = (te.TokenIsElevated != 0);
	} else {
		if (!AllocateAndInitializeSid(&auth, 2, SECURITY_BUILTIN_DOMAIN_RID,
			DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &psid))
			goto out;
		if (!CheckTokenMembership(NULL, psid, &r))
			r = FALSE;
		FreeSid(psid);
	}

out:
	safe_closehandle(token);
	return r;
}

/*
 * https://docs.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--
 */
static BOOL SetPrivilege(
	HANDLE hToken,              // access token handle
	const char* lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege       // to enable or disable privilege
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValueA(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))          // receives LUID of privilege
	{
		perr("LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.
	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL)) {
		perr("AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		perr("The token does not have the specified privilege.\n");
		return FALSE;
	}

	return TRUE;
}

/*
 * https://docs.microsoft.com/en-us/windows/win32/secauthz/taking-object-ownership-in-c--
 */
static BOOL TakeOwnership(const char* filename)
{
	BOOL bRetval = FALSE;
	HANDLE hToken = NULL;
	PSID pSIDAdmin = NULL;
	PSID pSIDEveryone = NULL;
	PACL pACL = NULL;
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
	SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
	EXPLICIT_ACCESS ea[2];
	DWORD dwRes;
	wchar_t* pszFilename = utf8_to_wchar(filename);

	if (pszFilename == NULL) {
		perr("Could not convert filename '%s'\n", filename);
		goto Cleanup;
	}

	// Specify the DACL to use.
	// Create a SID for the Everyone group.
	if (!AllocateAndInitializeSid(&SIDAuthWorld, 1,
		SECURITY_WORLD_RID,
		0,
		0, 0, 0, 0, 0, 0,
		&pSIDEveryone)) {
		perr("AllocateAndInitializeSid (Everyone): Error %u\n", GetLastError());
		goto Cleanup;
	}

	// Create a SID for the BUILTIN\Administrators group.
	if (!AllocateAndInitializeSid(&SIDAuthNT, 2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&pSIDAdmin)) {
		perr("AllocateAndInitializeSid (Admin): Error %u\n", GetLastError());
		goto Cleanup;
	}

	ZeroMemory(&ea, 2 * sizeof(EXPLICIT_ACCESS));

	// Set read access for Everyone.
	ea[0].grfAccessPermissions = GENERIC_READ;
	ea[0].grfAccessMode = SET_ACCESS;
	ea[0].grfInheritance = NO_INHERITANCE;
	ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ea[0].Trustee.ptstrName = (LPTSTR)pSIDEveryone;

	// Set full control for Administrators.
	ea[1].grfAccessPermissions = GENERIC_ALL;
	ea[1].grfAccessMode = SET_ACCESS;
	ea[1].grfInheritance = NO_INHERITANCE;
	ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	ea[1].Trustee.ptstrName = (LPTSTR)pSIDAdmin;

	if (SetEntriesInAcl(2, ea, NULL, &pACL) != ERROR_SUCCESS) {
		perr("Failed SetEntriesInAcl\n");
		goto Cleanup;
	}

	// Try to modify the object's DACL.
	dwRes = SetNamedSecurityInfoW(
		pszFilename,                 // name of the object
		SE_FILE_OBJECT,              // type of object
		DACL_SECURITY_INFORMATION,   // change only the object's DACL
		NULL, NULL,                  // do not change owner or group
		pACL,                        // DACL specified
		NULL);                       // do not change SACL

	if (dwRes == ERROR_SUCCESS) {
		bRetval = TRUE;
		// No more processing needed.
		goto Cleanup;
	}
	if (dwRes != ERROR_ACCESS_DENIED) {
		printf("First SetNamedSecurityInfo call failed: %u\n", dwRes);
		goto Cleanup;
	}

	// If the preceding call failed because access was denied, 
	// enable the SE_TAKE_OWNERSHIP_NAME privilege, create a SID for 
	// the Administrators group, take ownership of the object, and 
	// disable the privilege. Then try again to set the object's DACL.

	// Open a handle to the access token for the calling process.
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		perr("OpenProcessToken failed: Error %u\n", GetLastError());
		goto Cleanup;
	}

	// Enable the SE_TAKE_OWNERSHIP_NAME privilege.
	if (!SetPrivilege(hToken, "SeTakeOwnershipPrivilege", TRUE)) {
		perr("You must be logged on as Administrator.\n");
		goto Cleanup;
	}

	// Set the owner in the object's security descriptor.
	dwRes = SetNamedSecurityInfoW(
		pszFilename,                 // name of the object
		SE_FILE_OBJECT,              // type of object
		OWNER_SECURITY_INFORMATION,  // change only the object's owner
		pSIDAdmin,                   // SID of Administrator group
		NULL,
		NULL,
		NULL);

	if (dwRes != ERROR_SUCCESS) {
		perr("Could not set owner: Error %u\n", dwRes);
		goto Cleanup;
	}

	// Disable the SE_TAKE_OWNERSHIP_NAME privilege.
	if (!SetPrivilege(hToken, "SeTakeOwnershipPrivilege", FALSE)) {
		perr("SetPrivilege call failed unexpectedly.\n");
		goto Cleanup;
	}

	// Try again to modify the object's DACL, now that we are the owner.
	dwRes = SetNamedSecurityInfoW(
		(LPWSTR)pszFilename,         // name of the object
		SE_FILE_OBJECT,              // type of object
		DACL_SECURITY_INFORMATION,   // change only the object's DACL
		NULL, NULL,                  // do not change owner or group
		pACL,                        // DACL specified
		NULL);                       // do not change SACL

	if (dwRes == ERROR_SUCCESS)
		bRetval = TRUE;
	else
		perr("Second SetNamedSecurityInfo call failed: Error %u\n", dwRes);

Cleanup:
	if (pSIDAdmin)
		FreeSid(pSIDAdmin);
	if (pSIDEveryone)
		FreeSid(pSIDEveryone);
	if (pACL)
		LocalFree(pACL);
	if (hToken)
		CloseHandle(hToken);
	free(pszFilename);
	return bRetval;
}

BOOL CreateBackup(const char* filename, BOOL use_backup)
{
	BOOL bRet = FALSE;
	struct _stat64 st;
	size_t size = safe_strlen(filename) + 5;
	char* backup_path = NULL;

	if (_stat64U(filename, &st) != 0)
		return FALSE;

	backup_path = malloc(size);
	if (backup_path == NULL)
		return FALSE;
	strcpy_s(backup_path, size, filename);
	strcat_s(backup_path, size, ".bak");
	if (_stat64U(backup_path, &st) == 0) {
		if (use_backup) {
			spout("Using backup copy of '%s' as source\n", backup_path);
			bRet = CopyFileU(backup_path, filename, FALSE);
		} else {
			spout("Backup '%s' already exists - keeping it\n", backup_path);
			bRet = TRUE;
		}
		free(backup_path);
		return TRUE;
	}
	bRet = CopyFileU(filename, backup_path, TRUE);
	if (bRet)
		spout("Saved backup as '%s'\n", backup_path);
	free(backup_path);
	return bRet;
}

static DWORD RemoveDigitalSignature(const char* filename)
{
	DWORD dwNumCerts = -1;
	HANDLE hFile = NULL;

	hFile = CreateFileU(filename, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == NULL) {
		perr("Could not open file to remove digital signature: Error %u\n", GetLastError());
		return -1;
	}

	if (ImageEnumerateCertificates(hFile, CERT_SECTION_TYPE_ANY, &dwNumCerts, NULL, 0)) {
		switch(dwNumCerts) {
		case 0:
			break;
		case 1:
			if (!ImageRemoveCertificate(hFile, 0)) {
				perr("Could not delete digital signatures: Error %u\n", GetLastError());
				dwNumCerts = -1;
			}
			break;
		default:
			perr("Unexpected number of signatures!\n");
			dwNumCerts = -1;
			break;
		}
	}

	safe_closehandle(hFile);
	return dwNumCerts;
}

static BOOL UpdateChecksum(const char* filename, DWORD* dwCheckSum)
{
	BOOL bRet = FALSE;
	HANDLE hFile = NULL, hFileMapping = NULL;
	PIMAGE_DOS_HEADER pImageDOSHeader = NULL;
	PIMAGE_NT_HEADERS32 pImageNTHeader32 = NULL;
	PIMAGE_NT_HEADERS64 pImageNTHeader64 = NULL;

	hFile = CreateFileU(filename, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == NULL) {
		perr("Could not open file to update checksum: %u\n", GetLastError());
		return FALSE;
	}

	hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
	if (hFileMapping == NULL) {
		perr("Could not create file mapping to update checksum: Error %u\n", GetLastError());
		goto out;
	}

	pImageDOSHeader = (PIMAGE_DOS_HEADER)MapViewOfFile(hFileMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (pImageDOSHeader == NULL) {
		perr("Could not get mapped view address to update checksum: Error %u\n", GetLastError());
		goto out;
	}
	if (pImageDOSHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		perr("DOS header not found\n");
		goto out;
	}
	pImageNTHeader32 = (PIMAGE_NT_HEADERS32)((uintptr_t)pImageDOSHeader + pImageDOSHeader->e_lfanew);
	if (pImageNTHeader32->Signature != IMAGE_NT_SIGNATURE) {
		perr("NT header not found\n");
		goto out;
	}

	switch (pImageNTHeader32->FileHeader.Machine) {
	case IMAGE_FILE_MACHINE_IA64:
	case IMAGE_FILE_MACHINE_ALPHA64:
	case IMAGE_FILE_MACHINE_AMD64:
	case IMAGE_FILE_MACHINE_ARM64:
	case IMAGE_FILE_MACHINE_RISCV64:
		pImageNTHeader64 = (PIMAGE_NT_HEADERS64)pImageNTHeader32;
		if (pImageNTHeader64->OptionalHeader.CheckSum != dwCheckSum[0]) {
			perr("Old checksum does not match! Is this a 64-bit executable?");
			goto out;
		}
		pImageNTHeader64->OptionalHeader.CheckSum = dwCheckSum[1];
		vpout("64-bit checksum updated\n");
		break;
	default:
		if (pImageNTHeader32->OptionalHeader.CheckSum != dwCheckSum[0]) {
			perr("Old checksum does not match! Is this a 32-bit executable?");
			goto out;
		}
		pImageNTHeader32->OptionalHeader.CheckSum = dwCheckSum[1];
		vpout("32-bit checksum updated\n");
		break;
	}
	bRet = TRUE;

out:
	if (pImageDOSHeader != NULL)
		UnmapViewOfFile(pImageDOSHeader);
	safe_closehandle(hFileMapping);
	safe_closehandle(hFile);
	return bRet;
}

static void FreeChunkList(chunk* list, size_t size)
{
	size_t i;
	for (i = 0; i < size; i++) {
		free(list[i].org);
		free(list[i].new);
	}
	free(list);
}

static uint8_t* HexStringToBin(const char* str)
{
	size_t i, len = safe_strlen(str);
	uint8_t val = 0, * ret = NULL;
	char c;

	if ((len < 2) || (len % 2))
		return NULL;
	ret = malloc(len / 2);
	if (ret == NULL)
		return NULL;

	for (i = 0; i < len; i++) {
		val <<= 4;
		c = (char)tolower(str[i]);
		if (c < '0' || (c > '9' && c < 'a') || c > 'f') {
			perr("Invalid hex character '%c' in string '%s'\n", str[i], str);
			return NULL;
		}
		val |= ((c - '0') < 0xa) ? (c - '0') : (c - 'a' + 0xa);
		if (i % 2)
			ret[i / 2] = val;
	}

	return ret;
}

static SplitHexString(const char* fmt1, const char* fmt2, char* hex_value)
{
	char c;
	size_t j;

	for (j = 0; j < strlen(hex_value); j += HEX_SPLIT) {
		c = 0;
		if (strlen(&hex_value[j]) > HEX_SPLIT) {
			c = (&hex_value[j])[HEX_SPLIT];
			(&hex_value[j])[HEX_SPLIT] = 0;
		}
		spout(((j == 0) || (fmt2 == NULL)) ? fmt1 : fmt2, &hex_value[j]);
		if (c != 0)
			(&hex_value[j])[HEX_SPLIT] = c;
	}
}

static int main_utf8(int argc, char** argv)
{
	FILE* file = NULL;
	DWORD r, dwCheckSum[2];
	int i , patched = 0;
	uint64_t pos;
	uint8_t val[MAX_CHUNK_SIZE];
	chunk* chunk_list;
	char system_dir[128], short_arg[32] = { 0 }, *filename = NULL;
	char format[64], *hex_value[MAX_HEX_VALUES] = { 0 };
	size_t chunk_list_size, min_chunk_size = MAX_CHUNK_SIZE, max_chunk_size = 0;
	size_t val_size, short_arg_size = 0, hex_value_size = 0;
	bool help, ignore_patch, overwrite_source, warn_on_multiple, use_backup;

	// Parse options
	for (i = 1; i < argc; i++) {
		if (((argv[i][0] == '/') || (argv[i][0] == '-')) && ((argv[i][1] != 0) && (argv[i][2] == 0)))
			short_arg[short_arg_size++] = (char)tolower(argv[i][1]);
		else if (filename == NULL)
			filename = argv[i];
		else
			hex_value[hex_value_size++] = argv[i];
		if ((short_arg_size >= sizeof(short_arg) - 1) || (hex_value_size >= ARRAYSIZE(hex_value))) {
			perr("Too many arguments.\n");
			return -1;
		}
	}

	use_backup = (strchr(short_arg, 'b') == NULL);
	help = (strchr(short_arg, 'h') != NULL) || (strchr(short_arg, '?') != NULL);
	ignore_patch = (strchr(short_arg, 'i') != NULL);
	overwrite_source = (strchr(short_arg, 'o') != NULL);
	silent = (strchr(short_arg, 's') != NULL);
	verbose = (strchr(short_arg, 'v') != NULL);
	warn_on_multiple = (strchr(short_arg, 'w') == NULL);
	if (overwrite_source && !use_backup) {
		perr("Option -o cannot be used with option -b\n");
		return -1;
	}

	spout("\n%s %s © 2020 Pete Batard <pete@akeo.ie>\n\n", appname(argv[0]), APP_VERSION_STR);
	if ((!ignore_patch && (hex_value_size < 2)) || help) {
		pout("DESCRIPTION\n  Take ownership, patch, update checksum and update digital\n");
		pout("  signature (self-sign) of a PE executable.\n\n");
		pout("USAGE\n  %s [-bhiosvw] FILE [HEXVAL HEXVAL [HEXVAL HEXVAL [...]]\n\n", appname(argv[0]));
		pout("  Where HEXVALs are paired values containing the hexadecimal data to\n");
		pout("  search for, followed by the data you want to replace it with.\n\n");
		pout("  HEXVAL can be of any size between %d and %d bytes. You can mix and\n",
			MIN_CHUNK_SIZE, MAX_CHUNK_SIZE);
		pout("  match sizes, as long the value sizes in each pair are the same.\n\n");
		pout("  No specific alignment is required for the HEXVALs, meaning that\n");
		pout("  %s can match a word value starting at an odd address.\n\n",
			appname(argv[0]));
		pout("  Values should be provided in big-endian mode i.e. in the same byte\n");
		pout("  order as the one they appear with in the hex-dump of the file.\n\n");
		pout("  Unless you use option -w, %s will warn (once) if multiple\n",
			appname(argv[0]));
		pout("  instances of a specific HEXVAL pair are patched.\n\n");
		pout("OPTIONS\n  -h: This help text.\n");
		pout("  -b: DON'T create a backup before patching the file (DANGEROUS).\n");
		pout("  -i: Ignore patch values. Update the digital signature only.\n");
		pout("  -o: Overwrite the source with the backup (if any) before patching.\n");
		pout("  -s: Silent mode. No output except for errors.\n");
		pout("  -v: Slightly more verbose output.\n");
		pout("  -w: Don't warn when multiple instances of a patch are applied.\n");
		return -2;
	}

	spout("This program is free software; you can redistribute it and/or modify it under \n");
	spout("the terms of the GNU General Public License as published by the Free Software \n");
	spout("Foundation; either version 3 of the License or any later version.\n\n");
	spout("Official project and latest downloads: https://github.com/pbatard/winpatch.\n\n");

	if (!IsCurrentProcessElevated()) {
		perr("This command must be run from an elevated prompt.\n");
		return -1;
	}

	if (GetSystemDirectoryU(system_dir, sizeof(system_dir)) == 0)
		static_strcpy(system_dir, "C:\\Windows\\System32");
	if (_strnicmp(filename, system_dir, strlen(system_dir)) == 0) {
		perr("Patching of active system files is prohibited!\n");
		return -1;
	}

	// Sanity checks
	if (!PathFileExistsU(filename)) {
		perr("File '%s' doesn't exist\n", filename);
		return -1;
	}

	if (!TakeOwnership(filename)) {
		perr("Could not take ownership of '%s'\n", filename);
		return -1;
	}

	if (use_backup) {
		if (!CreateBackup(filename, overwrite_source)) {
			perr("Could not create backup of '%s'\n", filename);
			return -1;
		}
	}

	if (ignore_patch)
		goto skip_patch;

	if (hex_value_size % 2) {
		perr("Values must be provided in [<SEARCH> <REPLACE>] pairs\n");
		return -1;
	}

	// Parse hex values
	chunk_list_size = hex_value_size / 2;
	chunk_list = calloc(chunk_list_size, sizeof(chunk));
	if (chunk_list == NULL) {
		perr("Memory allocation error\n");
		return -1;
	}

	for (i = 0; i < (int)chunk_list_size; i++) {
		chunk_list[i].size = strlen(hex_value[2 * i]);
		if (chunk_list[i].size % 2) {
			perr("The number of hex digits for '%s' must be a multiple of 2\n",
				hex_value[2 * i]);
			FreeChunkList(chunk_list, chunk_list_size);
			return -1;
		}
		if (chunk_list[i].size != strlen(hex_value[2 * i + 1])) {
			perr("'%s' and '%s' are not the same length\n",
				hex_value[2 * i], hex_value[2 * i + 1]);
			FreeChunkList(chunk_list, chunk_list_size);
			return -1;
		}
		chunk_list[i].size /= 2;
		if ((chunk_list[i].size < MIN_CHUNK_SIZE) || (chunk_list[i].size > MAX_CHUNK_SIZE)) {
			perr("A value can not be smaller than %d bytes or larger than %d bytes\n",
				MIN_CHUNK_SIZE, MAX_CHUNK_SIZE);
			FreeChunkList(chunk_list, chunk_list_size);
			return -1;
		}
		min_chunk_size = min(min_chunk_size, chunk_list[i].size);
		max_chunk_size = max(max_chunk_size, chunk_list[i].size);
		chunk_list[i].org = HexStringToBin(hex_value[2 * i]);
		chunk_list[i].new = HexStringToBin(hex_value[2 * i + 1]);
		if (chunk_list[i].org == NULL || chunk_list[i].new == NULL) {
			perr("Could not convert hex string\n");
			FreeChunkList(chunk_list, chunk_list_size);
			return -1;
		}
	}

	// Patch target file
	file = fopenU(filename, "rb+");
	if (file == NULL) {
		perr("Could not open '%s'\n", filename);
		return -1;
	}

	val_size = min_chunk_size - 1;
	if (fread(val, 1, val_size, file) != val_size) {
		perr("Could not read '%s'\n", filename);
		FreeChunkList(chunk_list, chunk_list_size);
		fclose(file);
		return -1;
	}

	spout("Patching data...\n");
	for (pos = 0; ; pos++) {
		assert(val_size < max_chunk_size);
		if (fread(&val[val_size++], 1, 1, file) != 1)
			// Note: If we have a patch smaller than max_chunk_size at the very end,
			// it won't be applied because we break too soon. But we don't care about
			// this in this patcher because the end should be the digital signature...
			break;
		for (i = 0; i < (int)chunk_list_size; i++) {
			if ((chunk_list[i].size <= val_size) && (memcmp(chunk_list[i].org, val, chunk_list[i].size) == 0)) {
				if ((chunk_list[i].patched++ == 1) && warn_on_multiple) {
					perr("WARNING: More than one section with data %s is being patched!\n", hex_value[2 * i]);
				}
				static_sprintf(format, "%08llX - %%s\n", pos - val_size + chunk_list[i].size);
				SplitHexString(format, "         - %s\n", hex_value[2 * i]);
				memcpy(val, chunk_list[i].new, chunk_list[i].size);
				fseek(file, (long)(pos - val_size + chunk_list[i].size), SEEK_SET);
				if (fwrite(&val, 1, chunk_list[i].size, file) != chunk_list[i].size) {
					SplitHexString("         = %s [FAILED!]\n", "         = %s\n", hex_value[2 * i]);
				} else {
					SplitHexString("         + %s\n", NULL, hex_value[2 * i + 1]);
					patched++;
				}
				fflush(file);
				// Now reposition ourselves to the next byte to read...
				fseek(file, (long)(pos + val_size), SEEK_SET);
				// ...and prevent patch overlap by removing our data
				val_size -= chunk_list[i].size;
				memmove(val, &val[chunk_list[i].size], val_size);
				break;
			}
		}
		if (val_size == max_chunk_size)
			memmove(val, &val[1], --val_size);
	}

	FreeChunkList(chunk_list, chunk_list_size);
	fclose(file);
	if (patched == 0) {
		spout("No elements were patched - aborting\n");
		return 0;
	}

	// Update checksum and digital signature
skip_patch:
	spout("Removing existing digital signature...\n");
	r = RemoveDigitalSignature(filename);
	switch (r) {
	case 0:
		spout("WARNING: No digital signature to remove.\n");
		break;
	case 1:
		break;
	default:
		perr("Could not remove digital signature\n");
		return -1;
	}

	spout("Computing PE checksum...\n");
	r = MapFileAndCheckSumU(filename, &dwCheckSum[0], &dwCheckSum[1]);
	if (r != CHECKSUM_SUCCESS) {
		perr("Could not compute checksum: Error %u\n", r);
		return -1;
	}
	vpout("New checksum: %08X\n", dwCheckSum[1]);

	spout("Updating PE checksum...\n");
	if (dwCheckSum[0] != dwCheckSum[1] && !UpdateChecksum(filename, dwCheckSum)) {
		perr("Could not update checksum\n");
		return -1;
	}

	spout("Applying self-signed digital signature...\n");
	if (!SelfSignFile(filename, "CN = Test Signing Certificate")) {
		perr("Could not sign file\n");
		return -1;
	}

	spout("Successfully patched %d section%s in '%s'\n",
		patched, (patched > 1) ? "s" : "", filename);

	return patched;
}

int wmain(int argc, wchar_t** argv16)
{
	fflush(stdin);
	fflush(stdout);
	SetConsoleOutputCP(CP_UTF8);
	char** argv = calloc(argc, sizeof(char*));
	if (argv == NULL)
		return -1;
	for (int i = 0; i < argc; i++)
		argv[i] = wchar_to_utf8(argv16[i]);
	int r = main_utf8(argc, argv);
	for (int i = 0; i < argc; i++)
		free(argv[i]);
	free(argv);
#ifdef _DEBUG
	_CrtDumpMemoryLeaks();
#endif
	return r;
}
