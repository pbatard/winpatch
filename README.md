winpatch: Windows system file patcher
=====================================

[![Build status](https://img.shields.io/appveyor/ci/pbatard/winpatch.svg?style=flat-square)](https://ci.appveyor.com/project/pbatard/winpatch)
[![Release](https://img.shields.io/github/release-pre/pbatard/winpatch.svg?style=flat-square)](https://github.com/pbatard/winpatch/releases)
[![Github stats](https://img.shields.io/github/downloads/pbatard/winpatch/total.svg?style=flat-square)](https://github.com/pbatard/winpatch/releases)
[![Licence](https://img.shields.io/badge/license-GPLv3-blue.svg?style=flat-square)](https://www.gnu.org/licenses/gpl-3.0.en.html)

Description
-----------

This commandline utility is intended to binary patch protected system files, such as drivers or DLLs,
that reside in a Windows system directory.

This is primarily meant to be used to apply necessary fixes to the drivers of a newly created system,
such as a Windows To Go drive or a directory where a Windows 10 image has been applied.

Compatibility
-------------

Windows 7 or later.

Compilation
-----------

Use Visual Studio 2019 and invoke the `.sln` to compile.

Example
-------

Let's say you want to run Windows 10 ARM64 on a system where xHCI registers must be accessed through two
32-bit accesses (such as the VL805 controller of the Raspberry Pi 4), but the Windows `USBXHCI.SYS` driver
is enforcing 64-bit accesses, which results in a BSOD when trying to boot from an USB 3.0 drive.

Provided that the driver for the system you want to patch resides in `F:\Windows\System32\drivers\`, then,
from an elevated command prompt, you can use `winpatch` as follows:

```
winpatch F:\Windows\System32\drivers\USBXHCI.SYS 910063E8370000EA 910063E8360000EA 3700010AD5033F9F 3600010AD5033F9F
```

Obviously, since you have patched a system file, you also have to disable signature enforcement with
something like (assuming the BCD for that drive resides on an ESP mounted as `S:`):

```
bcdedit /store S:\EFI\Microsoft\Boot\BCD /set {default} testsigning on
bcdedit /store S:\EFI\Microsoft\Boot\BCD /set {default} nointegritychecks on
``` 

How it works
------------

Besides the patching (which currently __must__ be aligned to 64-bit, i.e. winpatch does match
with QWORDs that start at a 32-bit offset in the file), winpatch performs the following:

1. Take ownership of the system file if needed.
2. Delete the existing digital signature, if any.
3. Update the PE32 or PE64 checksum after patching.
4. Apply a new self-signed digital signature.

Each of these steps is required, because:

1. System files are protected by Windows and you cannot alter them without taking ownership.
2. If the file was patched, then the existing digital signature has become invalid.
3. If you don't update the PE checksum, Windows produces BSODs during boot with error `0xc0000221`
   (`STATUS_IMAGE_CHECKSUM_MISMATCH`) for the modified driver or DLL.
4. Even with `testsigning` and `nointegritychecks` active, if a modified system file is not digitally
   signed, Windows boots straight into recovery mode, with error code `0xc000000f` from `winload.exe`.
