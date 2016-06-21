#!/bin/bash

# cleanup.sh

# usage: ./cleanup.sh

rm -vrf bin
rm -vrf libs
rm -vrf original
rm -vrf payload
rm -v Rat.apk
rm -v perms.tmp
rm -v signing.keystore

exit 0
