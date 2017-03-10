.. :changelog:

Release History
---------------

0.2.1 (2017-03-10)
++++++++++++++++++

**Improvements**

- Updated third-party software and tools

**Bug Fixes**

- Fixed smali file to hook logic to properly handle shorthand class names in activity elements in the APK manifest
- Fixed smali file to hook logic to handle cases where a super class must be hooked

0.2.0 (2017-02-17)
++++++++++++++++++

**Bug Fixes**

- Fixed smali file to hook logic to handle multidex APK files

0.1.9 (2016-12-30)
++++++++++++++++++

**Improvements**

- Dynamic obfuscation of const-string values in RAT smali code

**Bug Fixes**

- Fixed invalid date bug in the original cert info extraction logic

0.1.8 (2016-12-20)
++++++++++++++++++

**Improvements**

- The generated signing cert uses the valid from date and validity value from the original APK cert

**Bug Fixes**

- Fixed various issues with the original cert info extraction logic
- Fixed minor issue with the proguard configuration file
- Fixed namelist values that include dashes causing Apktool recompilation errors

0.1.7 (2016-11-30)
++++++++++++++++++

**Improvements**

- Automatic generation of Metasploit resource script to handle selected payload (credit to John Troony for the suggestion)

**Bug Fixes**

- Fixed persistence hook breakage caused by upstream changes in Metasploit

0.1.6 (2016-11-29)
++++++++++++++++++

**Bug Fixes**

- Fixed breakage caused by upstream changes in Metasploit

0.1.5 (2016-10-17)
++++++++++++++++++

**Bug Fixes**

- The logic used to extract the original certificate dname value no longer breaks with non-English versions of keytool

0.1.4 (2016-09-20)
++++++++++++++++++

**Improvements**

- New UI enhancements allow selecting Android payloads and entering LHOST and LPORT values
- New ascii art is displayed on script execution
- First attempt at improving the readability of logging output
- Apktool is no longer provided as a third-party tool, backdoor-apk.sh now expects apktool to be properly setup on the system

**Miscellaneous**

- README and HISTORY file updates

0.1.3 (2016-07-29)
++++++++++++++++++

**Bug Fixes**

- Proguard processing no longer breaks the Metasploit android/meterpreter/reverse_https payload in repackaged APKs

0.1.2 (2016-07-25)
++++++++++++++++++

**Bug Fixes**

- Placeholder logic no longer fails on Linux systems configured for 32 bit long values

**Miscellaneous**

- Added AUTHORS and HISTORY files

0.1.1 (2016-06-30) [moar-sneaky]
++++++++++++++++++++++++++++++++

**Improvements**

- Added obfuscation of const-string values in smali files obtained via msfvenom Android payload generation
- Improved proguard obfuscation of smali files obtained via msfvenom Android payload generation
- Minor code refactoring

**Miscellaneous**

- README file updates

**Notes**

- First time repackaged APKs avoid detection by all mobile antivirus vendors on virus total

0.1.0 (2016-06-25) [persistence]
++++++++++++++++++++++++++++++++

**Improvements**

- Added persistence hook via broadcast receiver
- Cleaned up persistence logic code

**Miscellaneous**

- README file updates

0.0.7 (2016-06-24) [multi-payload]
++++++++++++++++++++++++++++++++++

**Improvements**

- Added multi (metasploit/msfvenom Android) payload support
- Changed how payload details are displayed in console output

**Miscellaneous**

- README file updates

0.0.6 (2016-06-23)
++++++++++++++++++

**Bug Fixes**

- Fixed the smali file to hook locator logic

0.0.5 (2016-06-22)
++++++++++++++++++

**Improvements**

- General error detection and handling enhancements

0.0.4 (2016-06-15)
++++++++++++++++++

**Improvements**

- A new RSA key and self-signed cert is created with dname info from original APK on each script run

**Miscellaneous**

- README file updates

0.0.3 (2016-06-13)
++++++++++++++++++

**Improvements**

- Now using proguard to obfuscate smali files obtained via msfvenom Android payload generation
- Removed dependency on openssl

**Miscellaneous**

- README file updates

0.0.2 (2016-04-11)
++++++++++++++++++

**Bug Fixes**

- Fixed bad smali file to hook locator logic

**Miscellaneous**

- README file updates

0.0.1 (2016-04-04)
++++++++++++++++++

* Birth

0.0.1a (2016-03-20)
+++++++++++++++++++

* Conception
