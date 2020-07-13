/*
 * libwdi: Library for automated Windows Driver Installation - PKI part
 * Copyright (c) 2011-2020 Pete Batard <pete@akeo.ie>
 * For more info, please visit https://libwdi.akeo.ie
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/* Memory leaks detection - define _CRTDBG_MAP_ALLOC as preprocessor macro */
#ifdef _DEBUG
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdint.h>

#include "mssign32.h"
#include "msapi_utf8.h"

#pragma comment(lib, "crypt32.lib")

#define safe_sprintf(dst, count, ...) do {_snprintf_s(dst, count, _TRUNCATE, __VA_ARGS__); (dst)[(count)-1] = 0; } while(0)
#define static_sprintf(dst, ...) safe_sprintf(dst, sizeof(dst), __VA_ARGS__)

/* Helper functions to access DLLs */
static __inline HMODULE GetLibraryHandle(char* szDLLName)
{
	HANDLE h = GetModuleHandleA(szDLLName);
	if (h == NULL)
		h = LoadLibraryA(szDLLName);
	return h;
}

#define PF_DECL_LIBRARY(name) HANDLE h##name = NULL
#define PF_LOAD_LIBRARY(name) h##name = LoadLibraryA(#name)
#define PF_DECL_LOAD_LIBRARY(name) HANDLE PF_LOAD_LIBRARY(name)
#define PF_FREE_LIBRARY(name) FreeLibrary(h##name); h##name = NULL
#define PF_TYPE(api, ret, proc, args) typedef ret (api *proc##_t)args
#define PF_DECL(proc) proc##_t pf##proc = NULL
#define PF_TYPE_DECL(api, ret, proc, args) PF_TYPE(api, ret, proc, args); PF_DECL(proc)
#define PF_INIT(proc, name) if (h##name == NULL) h##name = GetLibraryHandle(#name); \
	pf##proc = (proc##_t) GetProcAddress(h##name, #proc)
#define PF_INIT_OR_OUT(proc, name) PF_INIT(proc, name); if (pf##proc == NULL) { \
	fprintf(stderr, "Unable to locate %s() in %s\n", #proc, #name); goto out; }

#define KEY_CONTAINER L"winpatch key container"

static char* winpki_error_str(void)
{
	static char error_string[64];
	uint32_t error_code = GetLastError();

	if (error_code == 0x800706D9)
		return "This system is missing required cryptographic services";
	if (error_code == 0x80070020)
		return "Some data handles to this file have not been properly closed";

	if ((error_code >> 16) != 0x8009) {
		static_sprintf(error_string, "Windows error 0x%08X", error_code);
		return error_string;
	}

	switch (error_code) {
	case NTE_BAD_UID:
		return "Bad UID.";
	case NTE_BAD_KEYSET:
		return "The key container could not be opened.";
	case NTE_KEYSET_ENTRY_BAD:
		return "The requested key container is corrupted.";
	case NTE_BAD_FLAGS:
	case NTE_BAD_KEYSET_PARAM:
	case NTE_BAD_PROV_TYPE:
	case NTE_EXISTS:
		return "Invalid parameter.";
	case NTE_BAD_SIGNATURE:
		return "This system's cryptographic DLL has been tampered with.";
	case NTE_PROVIDER_DLL_FAIL:
	case NTE_SIGNATURE_FILE_BAD:
	case NTE_PROV_DLL_NOT_FOUND:
		return "This system's cryptographic DLL can not be loaded.";
	case NTE_KEYSET_NOT_DEF:
		return "The requested provider does not exist.";
	case NTE_NO_MEMORY:
		return "Out of memory.";
	case CRYPT_E_MSG_ERROR:
		return "An error occurred while performing an operation on a cryptographic message.";
	case CRYPT_E_UNKNOWN_ALGO:
		return "Unknown cryptographic algorithm.";
	case CRYPT_E_INVALID_MSG_TYPE:
		return "Invalid cryptographic message type.";
	case CRYPT_E_HASH_VALUE:
		return "The hash value is not correct";
	case CRYPT_E_ISSUER_SERIALNUMBER:
		return "Invalid issuer and/or serial number.";
	case CRYPT_E_BAD_LEN:
		return "The length specified for the output data was insufficient.";
	case CRYPT_E_BAD_ENCODE:
		return "An error occurred during encode or decode operation.";
	case CRYPT_E_FILE_ERROR:
		return "An error occurred while reading or writing to a file.";
	case CRYPT_E_NOT_FOUND:
		return "Cannot find object or property.";
	case CRYPT_E_EXISTS:
		return "The object or property already exists.";
	case CRYPT_E_NO_PROVIDER:
		return "No provider was specified for the store or object.";
	case CRYPT_E_DELETED_PREV:
		return "The previous certificate or CRL context was deleted.";
	case CRYPT_E_NO_MATCH:
		return "Cannot find the requested object.";
	case CRYPT_E_UNEXPECTED_MSG_TYPE:
	case CRYPT_E_NO_KEY_PROPERTY:
	case CRYPT_E_NO_DECRYPT_CERT:
		return "Private key or certificate issue";
	case CRYPT_E_BAD_MSG:
		return "Not a cryptographic message.";
	case CRYPT_E_NO_SIGNER:
		return "The signed cryptographic message does not have a signer for the specified signer index.";
	case CRYPT_E_REVOKED:
		return "The certificate is revoked.";
	case CRYPT_E_NO_REVOCATION_DLL:
	case CRYPT_E_NO_REVOCATION_CHECK:
	case CRYPT_E_REVOCATION_OFFLINE:
	case CRYPT_E_NOT_IN_REVOCATION_DATABASE:
		return "Cannot check certificate revocation.";
	case CRYPT_E_INVALID_NUMERIC_STRING:
	case CRYPT_E_INVALID_PRINTABLE_STRING:
	case CRYPT_E_INVALID_IA5_STRING:
	case CRYPT_E_INVALID_X500_STRING:
	case CRYPT_E_NOT_CHAR_STRING:
		return "Invalid string.";
	case CRYPT_E_SECURITY_SETTINGS:
		return "The cryptographic operation failed due to a local security option setting.";
	case CRYPT_E_NO_VERIFY_USAGE_CHECK:
	case CRYPT_E_VERIFY_USAGE_OFFLINE:
		return "Cannot complete usage check.";
	case CRYPT_E_NO_TRUSTED_SIGNER:
		return "None of the signers of the cryptographic message or certificate trust list is trusted.";
	default:
		static_sprintf(error_string, "Unknown PKI error 0x%08X", error_code);
		return error_string;
	}
}

/*
 * Parts of the following functions are based on:
 * http://blogs.msdn.com/b/alejacma/archive/2009/03/16/how-to-create-a-self-signed-certificate-with-cryptoapi-c.aspx
 * http://blogs.msdn.com/b/alejacma/archive/2008/12/11/how-to-sign-exe-files-with-an-authenticode-certificate-part-2.aspx
 * http://www.jensign.com/hash/index.html
 */

/*
 * Create a self signed certificate for code signing
 */
PCCERT_CONTEXT CreateSelfSignedCert(LPCSTR szCertSubject)
{
	DWORD dwSize = 0;
	HCRYPTPROV hCSP = 0;
	HCRYPTKEY hKey = 0;
	PCCERT_CONTEXT pCertContext = NULL;
	CERT_NAME_BLOB SubjectIssuerBlob = {0, NULL};
	CRYPT_KEY_PROV_INFO KeyProvInfo;
	CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
	LPWSTR wszKeyContainer = KEY_CONTAINER;
	LPBYTE pbEnhKeyUsage = NULL, pbAltNameInfo = NULL, pbCPSNotice = NULL, pbPolicyInfo = NULL;
	SYSTEMTIME sExpirationDate = { 2040, 01, 01, 01, 00, 00, 00, 000 };
	CERT_EXTENSION certExtension[3];
	CERT_EXTENSIONS certExtensionsArray;
	// Code Signing Enhanced Key Usage
	LPSTR szCertPolicyElementId = "1.3.6.1.5.5.7.3.3"; // szOID_PKIX_KP_CODE_SIGNING;
	CERT_ENHKEY_USAGE certEnhKeyUsage = { 1, &szCertPolicyElementId };
	// Abuse Alt Name to insert ourselves in the e-mail field
	CERT_ALT_NAME_ENTRY certAltNameEntry = { CERT_ALT_NAME_RFC822_NAME,
		{ (PCERT_OTHER_NAME)L"Created by winpatch (https://github.com/pbatard/winpatch)" } };
	CERT_ALT_NAME_INFO certAltNameInfo = { 1, &certAltNameEntry };
	// Certificate Policies
	CERT_POLICY_QUALIFIER_INFO certPolicyQualifier;
	CERT_POLICY_INFO certPolicyInfo = { "1.3.6.1.5.5.7.2.1", 1, &certPolicyQualifier };
	CERT_POLICIES_INFO certPolicyInfoArray = { 1, &certPolicyInfo };
	CHAR szCPSName[] = "https://github.com/pbatard/winpatch";
	CERT_NAME_VALUE certCPSValue;

	// Set Enhanced Key Usage extension to Code Signing only
	if ( (!CryptEncodeObject(X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE, (LPVOID)&certEnhKeyUsage, NULL, &dwSize))
	  || ((pbEnhKeyUsage = (BYTE*)malloc(dwSize)) == NULL)
	  || (!CryptEncodeObject(X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE, (LPVOID)&certEnhKeyUsage, pbEnhKeyUsage, &dwSize)) ) {
		fprintf(stderr, "Could not setup EKU for code signing: %s\n", winpki_error_str());
		goto out;
	}
	certExtension[0].pszObjId = szOID_ENHANCED_KEY_USAGE;
	certExtension[0].fCritical = TRUE;		// only allow code signing
	certExtension[0].Value.cbData = dwSize;
	certExtension[0].Value.pbData = pbEnhKeyUsage;

	// Set Alt Name parameter
	if ( (!CryptEncodeObject(X509_ASN_ENCODING, X509_ALTERNATE_NAME, (LPVOID)&certAltNameInfo, NULL, &dwSize))
	  || ((pbAltNameInfo = (BYTE*)malloc(dwSize)) == NULL)
	  || (!CryptEncodeObject(X509_ASN_ENCODING, X509_ALTERNATE_NAME, (LPVOID)&certAltNameInfo, pbAltNameInfo, &dwSize)) ) {
		fprintf(stderr, "Could not set Alt Name: %s\n", winpki_error_str());
		goto out;
	}
	certExtension[1].pszObjId = szOID_SUBJECT_ALT_NAME;
	certExtension[1].fCritical = FALSE;
	certExtension[1].Value.cbData = dwSize;
	certExtension[1].Value.pbData = pbAltNameInfo;

	// Set the CPS Certificate Policies field - this enables the "Issuer Statement" button on the cert
	certCPSValue.dwValueType = CERT_RDN_IA5_STRING;
	certCPSValue.Value.cbData = sizeof(szCPSName);
	certCPSValue.Value.pbData = (BYTE*)szCPSName;
	if ( (!CryptEncodeObject(X509_ASN_ENCODING, X509_NAME_VALUE, (LPVOID)&certCPSValue, NULL, &dwSize))
		|| ((pbCPSNotice = (BYTE*)malloc(dwSize)) == NULL)
		|| (!CryptEncodeObject(X509_ASN_ENCODING, X509_NAME_VALUE, (LPVOID)&certCPSValue, pbCPSNotice, &dwSize)) ) {
		fprintf(stderr, "Could not setup CPS: %s\n", winpki_error_str());
		goto out;
	}

	certPolicyQualifier.pszPolicyQualifierId = szOID_PKIX_POLICY_QUALIFIER_CPS;
	certPolicyQualifier.Qualifier.cbData = dwSize;
	certPolicyQualifier.Qualifier.pbData = pbCPSNotice;
	if ( (!CryptEncodeObject(X509_ASN_ENCODING, X509_CERT_POLICIES, (LPVOID)&certPolicyInfoArray, NULL, &dwSize))
		|| ((pbPolicyInfo = (BYTE*)malloc(dwSize)) == NULL)
		|| (!CryptEncodeObject(X509_ASN_ENCODING, X509_CERT_POLICIES, (LPVOID)&certPolicyInfoArray, pbPolicyInfo, &dwSize)) ) {
		fprintf(stderr, "Could not setup Certificate Policies: %s\n", winpki_error_str());
		goto out;
	}
	certExtension[2].pszObjId = szOID_CERT_POLICIES;
	certExtension[2].fCritical = FALSE;
	certExtension[2].Value.cbData = dwSize;
	certExtension[2].Value.pbData = pbPolicyInfo;

	certExtensionsArray.cExtension = ARRAYSIZE(certExtension);
	certExtensionsArray.rgExtension = certExtension;

	if (CryptAcquireContextW(&hCSP, wszKeyContainer, NULL, PROV_RSA_FULL, CRYPT_MACHINE_KEYSET|CRYPT_SILENT)) {
		fprintf(stderr, "Acquired existing key container\n");
	} else if ( (GetLastError() != NTE_BAD_KEYSET)
			 || (!CryptAcquireContextW(&hCSP, wszKeyContainer, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET|CRYPT_MACHINE_KEYSET|CRYPT_SILENT)) ) {
		fprintf(stderr, "Could not obtain a key container: %s\n", winpki_error_str());
		goto out;
	}

	// Generate key pair using RSA 4096
	// (Key_size <<16) because key size is in upper 16 bits
	if (!CryptGenKey(hCSP, AT_SIGNATURE, (4096U<<16) | CRYPT_EXPORTABLE, &hKey)) {
		fprintf(stderr, "Could not generate keypair: %s\n", winpki_error_str());
		goto out;
	}

	// Set the subject
	if ( (!CertStrToNameA(X509_ASN_ENCODING, szCertSubject, CERT_X500_NAME_STR, NULL, NULL, &SubjectIssuerBlob.cbData, NULL))
	  || ((SubjectIssuerBlob.pbData = (BYTE*)malloc(SubjectIssuerBlob.cbData)) == NULL)
	  || (!CertStrToNameA(X509_ASN_ENCODING, szCertSubject, CERT_X500_NAME_STR, NULL, SubjectIssuerBlob.pbData, &SubjectIssuerBlob.cbData, NULL)) ) {
		fprintf(stderr, "Could not encode subject name for self signed cert: %s\n", winpki_error_str());
		goto out;
	}

	// Prepare key provider structure for self-signed certificate
	memset(&KeyProvInfo, 0, sizeof(KeyProvInfo));
	KeyProvInfo.pwszContainerName = wszKeyContainer;
	KeyProvInfo.pwszProvName = NULL;
	KeyProvInfo.dwProvType = PROV_RSA_FULL;
	KeyProvInfo.dwFlags = CRYPT_MACHINE_KEYSET;
	KeyProvInfo.cProvParam = 0;
	KeyProvInfo.rgProvParam = NULL;
	KeyProvInfo.dwKeySpec = AT_SIGNATURE;

	// Prepare algorithm structure for self-signed certificate
	memset(&SignatureAlgorithm, 0, sizeof(SignatureAlgorithm));
	SignatureAlgorithm.pszObjId = szOID_RSA_SHA256RSA;

	// Create self-signed certificate
	pCertContext = CertCreateSelfSignCertificate((ULONG_PTR)NULL,
		&SubjectIssuerBlob, 0, &KeyProvInfo, &SignatureAlgorithm, NULL, &sExpirationDate, &certExtensionsArray);
	if (pCertContext == NULL) {
		fprintf(stderr, "Could not create self signed certificate: %s\n", winpki_error_str());
		goto out;
	}

out:
	free(pbEnhKeyUsage);
	free(pbAltNameInfo);
	free(pbCPSNotice);
	free(pbPolicyInfo);
	free(SubjectIssuerBlob.pbData);
	if (hKey)
		CryptDestroyKey(hKey);
	if (hCSP)
		CryptReleaseContext(hCSP, 0);
	return pCertContext;
}

/*
 * Delete the private key associated with a specific cert
 */
BOOL DeletePrivateKey(PCCERT_CONTEXT pCertContext)
{
	LPWSTR wszKeyContainer = KEY_CONTAINER;
	HCRYPTPROV hCSP = 0;
	DWORD dwKeySpec;
	BOOL bFreeCSP = FALSE, r = FALSE;
	HCERTSTORE hSystemStore;
	LPCSTR szStoresToUpdate[2] = { "Root", "TrustedPublisher" };
	CRYPT_DATA_BLOB libwdiNameBlob = {14, (BYTE*)L"libwdi"};
	PCCERT_CONTEXT pCertContextUpdate = NULL;
	int i;

	if (!CryptAcquireCertificatePrivateKey(pCertContext, CRYPT_ACQUIRE_SILENT_FLAG, NULL, &hCSP, &dwKeySpec, &bFreeCSP)) {
		fprintf(stderr, "Error getting CSP: %s\n", winpki_error_str());
		goto out;
	}

	if (!CryptAcquireContextW(&hCSP, wszKeyContainer, NULL, PROV_RSA_FULL, CRYPT_MACHINE_KEYSET|CRYPT_SILENT|CRYPT_DELETEKEYSET)) {
		fprintf(stderr, "Failed to delete private key: %s\n", winpki_error_str());
	}

	// This is optional, but unless we reimport the cert data after having deleted the key
	// end users will still see a "You have a private key that corresponds to this certificate" message.
	for (i=0; i<ARRAYSIZE(szStoresToUpdate); i++) {
		hSystemStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, X509_ASN_ENCODING,
			0, CERT_SYSTEM_STORE_LOCAL_MACHINE, szStoresToUpdate[i]);
		if (hSystemStore == NULL) continue;

		if ( (CertAddEncodedCertificateToStore(hSystemStore, X509_ASN_ENCODING, pCertContext->pbCertEncoded,
			pCertContext->cbCertEncoded, CERT_STORE_ADD_REPLACE_EXISTING, &pCertContextUpdate)) && (pCertContextUpdate != NULL) ) {
			// The friendly name is lost in this operation - restore it
			if (!CertSetCertificateContextProperty(pCertContextUpdate, CERT_FRIENDLY_NAME_PROP_ID, 0, &libwdiNameBlob)) {
				fprintf(stderr, "Could not set friendly name: %s\n", winpki_error_str());
			}
			CertFreeCertificateContext(pCertContextUpdate);
		} else {
			fprintf(stderr, "Failed to update '%s': %s\n", szStoresToUpdate[i], winpki_error_str());
		}
		CertCloseStore(hSystemStore, 0);
	}

	r= TRUE;

out:
	if ((bFreeCSP) && (hCSP)) {
		CryptReleaseContext(hCSP, 0);
	}
	return r;
}

/*
 * Digitally sign a file by:
 * - creating a self signed certificate for code signing
 * - signing the file provided
 * - deleting the self signed certificate private key
 */
BOOL SelfSignFile(LPCSTR szFileName, LPCSTR szCertSubject)
{
	PF_DECL_LOAD_LIBRARY(MSSign32);
	PF_DECL(SignerSignEx);
	PF_DECL(SignerFreeSignerContext);

	BOOL r = FALSE;
	HRESULT hResult = S_OK;
	PCCERT_CONTEXT pCertContext = NULL;
	DWORD dwIndex;
	SIGNER_FILE_INFO signerFileInfo = { 0 };
	SIGNER_SUBJECT_INFO signerSubjectInfo;
	SIGNER_CERT_STORE_INFO signerCertStoreInfo;
	SIGNER_CERT signerCert;
	SIGNER_SIGNATURE_INFO signerSignatureInfo;
	PSIGNER_CONTEXT pSignerContext = NULL;
	CRYPT_ATTRIBUTES_ARRAY cryptAttributesArray;
	CRYPT_ATTRIBUTE cryptAttribute[2];
	CRYPT_INTEGER_BLOB oidSpOpusInfoBlob, oidStatementTypeBlob;
	BYTE pbOidSpOpusInfo[] = SP_OPUS_INFO_DATA;
	BYTE pbOidStatementType[] = STATEMENT_TYPE_DATA;

	PF_INIT_OR_OUT(SignerSignEx, MSSign32);
	PF_INIT_OR_OUT(SignerFreeSignerContext, MSSign32);

	pCertContext = CreateSelfSignedCert(szCertSubject);
	if (pCertContext == NULL) {
		goto out;
	}

	// Setup SIGNER_FILE_INFO struct
	signerFileInfo.cbSize = sizeof(SIGNER_FILE_INFO);
	signerFileInfo.pwszFileName = utf8_to_wchar(szFileName);
	if (signerFileInfo.pwszFileName == NULL) {
		fprintf(stderr, "Unable to convert '%s' to UTF16\n", szFileName);
		goto out;
	}
	signerFileInfo.hFile = NULL;

	// Prepare SIGNER_SUBJECT_INFO struct
	signerSubjectInfo.cbSize = sizeof(SIGNER_SUBJECT_INFO);
	dwIndex = 0;
	signerSubjectInfo.pdwIndex = &dwIndex;
	signerSubjectInfo.dwSubjectChoice = SIGNER_SUBJECT_FILE;
	signerSubjectInfo.pSignerFileInfo = &signerFileInfo;

	// Prepare SIGNER_CERT_STORE_INFO struct
	signerCertStoreInfo.cbSize = sizeof(SIGNER_CERT_STORE_INFO);
	signerCertStoreInfo.pSigningCert = pCertContext;
	signerCertStoreInfo.dwCertPolicy = SIGNER_CERT_POLICY_CHAIN;
	signerCertStoreInfo.hCertStore = NULL;

	// Prepare SIGNER_CERT struct
	signerCert.cbSize = sizeof(SIGNER_CERT);
	signerCert.dwCertChoice = SIGNER_CERT_STORE;
	signerCert.pCertStoreInfo = &signerCertStoreInfo;
	signerCert.hwnd = NULL;

	// Prepare the additional Authenticode OIDs
	oidSpOpusInfoBlob.cbData = sizeof(pbOidSpOpusInfo);
	oidSpOpusInfoBlob.pbData = pbOidSpOpusInfo;
	oidStatementTypeBlob.cbData = sizeof(pbOidStatementType);
	oidStatementTypeBlob.pbData = pbOidStatementType;
	cryptAttribute[0].cValue = 1;
	cryptAttribute[0].rgValue = &oidSpOpusInfoBlob;
	cryptAttribute[0].pszObjId = "1.3.6.1.4.1.311.2.1.12"; // SPC_SP_OPUS_INFO_OBJID in wintrust.h
	cryptAttribute[1].cValue = 1;
	cryptAttribute[1].rgValue = &oidStatementTypeBlob;
	cryptAttribute[1].pszObjId = "1.3.6.1.4.1.311.2.1.11"; // SPC_STATEMENT_TYPE_OBJID in wintrust.h
	cryptAttributesArray.cAttr = 2;
	cryptAttributesArray.rgAttr = cryptAttribute;

	// Prepare SIGNER_SIGNATURE_INFO struct
	signerSignatureInfo.cbSize = sizeof(SIGNER_SIGNATURE_INFO);
	signerSignatureInfo.algidHash = CALG_SHA_256;
	signerSignatureInfo.dwAttrChoice = SIGNER_NO_ATTR;
	signerSignatureInfo.pAttrAuthcode = NULL;
	signerSignatureInfo.psAuthenticated = &cryptAttributesArray;
	signerSignatureInfo.psUnauthenticated = NULL;

	// Sign file with cert
	hResult = pfSignerSignEx(0, &signerSubjectInfo, &signerCert, &signerSignatureInfo, NULL, NULL, NULL, NULL, &pSignerContext);
	if (hResult != S_OK) {
		SetLastError(hResult);
		fprintf(stderr, "SignerSignEx failed: %s\n", winpki_error_str());
		goto out;
	}
	r = TRUE;

out:
	if (pCertContext != NULL)
		DeletePrivateKey(pCertContext);
	free((void*)signerFileInfo.pwszFileName);
	if (pSignerContext != NULL)
		pfSignerFreeSignerContext(pSignerContext);
	if (pCertContext != NULL)
		CertFreeCertificateContext(pCertContext);
	PF_FREE_LIBRARY(MSSign32);
	return r;
}
