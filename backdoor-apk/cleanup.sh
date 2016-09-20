#!/bin/bash

# cleanup.sh

# usage: ./cleanup.sh

function rmdirz {
  if [ -d $1 ]; then
    rm -rf $1
  fi
}

function rmfilez {
  if [ -f $1 ]; then
    rm $1
  fi
}

rmdirz bin
rmdirz libs
rmdirz original
rmdirz payload

rmfilez Rat.apk
rmfilez perms.tmp
rmfilez persistence.hook
rmfilez obfuscate.method
rmfilez signing.keystore

exit 0
