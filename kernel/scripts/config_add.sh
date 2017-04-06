#!/bin/bash

function help {
	echo "Add hash config of the file to the 'fsintegr' module."
	echo "Usage: $0 FILE [ALG]"
	echo -e "\nOptions:"
	echo "    [ALG] - sha1 or md5 (default is sha1)"
}

TOOL=sha1sum
ALG="sha1"
FILE=""

if [ "$#" -eq  "0" ]
then
	help;
fi

if [ "$#" -eq  "1" ]
then
	FILE=$1;
fi

if [ "$#" -eq  "2" ]
then
	FILE=$1;
        ALG=$2;	
fi

if [ "$ALG" ==  "md5" ]
then
        TOOL=md5sum;	
fi

HASH=$($TOOL $FILE | awk '{ print $1}')

echo "add:$ALG:$HASH:file:$FILE" > /sys/kernel/security/fsintegr/config
