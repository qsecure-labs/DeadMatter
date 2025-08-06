# DeadMatter

![Version](https://img.shields.io/badge/Version-0.9.5_Beta-darkblue.svg)
![License](https://img.shields.io/badge/License-BSD3-darkred.svg)
[![Black Hat Arsenal 2025](https://img.shields.io/badge/2025-Black%20Hat%20Arsenal-lightgrey.svg)](https://www.qsecure.global/presenting-deadmatter-a-new-approach-to-credential-extraction-at-black-hat-usa-2025)
![GitHub stars](https://img.shields.io/github/stars/qsecure-labs/DeadMatter)

DeadMatter is a specialized tool written in C#, designed to extract sensitive information, such as password hashes of active logon sessions, from memory dumps. It employs carving techniques to retrieve credentials from various file types, such as process or full memory dumps, either in raw or minidump format, decompressed hibernation files, virtual machine memory files, or other types of files that may contain logon credentials. 

This tool is particularly useful for penetration testers, red teamers, and forensic investigators, as it facilitates the analysis of system security vulnerabilities and aids in digital forensic investigations. DeadMatter can be very useful to pentesters and red teamers during their engagements, since they often have to deal with EDR and AV software detecting and/or blocking their attempts to dump the LSASS process memory in the minidump format. The alternative of dumping and exfiltrating a full memory dump is often not an option. As a result, DeadMatter was created to fill the gap and allow the offensive team to parse the memory dump files directly on the victim machine, in order to extract NTLM hashes, DPAPI keys and other useful information on the spot.

The tool has been presented at Black Hat USA 2025 Arsenal. 



### Usage

```
Extract credentials from a full memory dump file in raw format using both Mimikatz structure and carving techniques
--------------------------------------------------------------------------------------------------------------
C:\> Deadmatter.exe -f=memory_dump.raw


Extract credentials from a full memory dump file in raw format using carving techniques only
---------------------------------------------------------------------------------------
C:\> Deadmatter.exe -f=memory_dump.raw -m=carve


Identify the OS version based on the MSV structure details
----------------------------------------------------------
C:\> Deadmatter.exe -f=memory_dump.raw -m=none -i=on


Extract credentials from a minidump file using Windows 10 version 1507 Mimikatz structure technique with verbose output
----------------------------------------------------------------------------------------------------------------------
C:\> Deadmatter.exe -f=lsass.dmp -m=mimikatz -w=WIN_10_1507 -v=on


Extract credentials and DPAPI keys from a full memory dump file in raw format and brute-force search for the IV
----------------------------------------------------------------------------------------------------------------------
C:\> Deadmatter.exe -f memory_dump.raw -b -d
```



### Supported Credentials

* Msv
* Dpapi



### Todo

* SAM (coming soon)
* Kerberos tickets
* Security questions
* Bitlocker keys
* Cached credentials
* WDigest credentials
* Process file from STDIN



## Acknowledgements

Special thanks to [cube0x0](https://twitter.com/cube0x0) as DeadMatter is heavily based on the code of [MiniDump](https://github.com/cube0x0/MiniDump)

Special thanks to [theodoros997](https://github.com/theodoros997/theodoros997) for setting up the test infrastructure and for his Google Chrome decryptor tool 

Shout-outs to the following people for their projects and great work, without which our own project wouldn't have been possible. 

* [pypykatz](https://github.com/skelsec/pypykatz) by [skelsec](https://twitter.com/SkelSec)
* [mimikatz](https://github.com/gentilkiwi/mimikatz/) by [gentilkiwi](https://twitter.com/gentilkiwi)
* [sharpkatz](https://github.com/b4rtik/SharpKatz) by [b4rtik](https://twitter.com/b4rtik)

# Disclaimer

DeadMatter is provided “as is” without any warranty. It is intended solely for use by qualified information-security professionals during authorized penetration tests, red team engagements, or forensic investigations. The developers of DeadMatter and QSecure accept no liability or responsibility for misuse of the tool or for any unlawful or malicious activities carried out with it.
