#!/bin/bash

function help {
	echo "Del config of the file from the 'fsintegr' module."
	echo "Usage: $0 FILE"
}

FILE=""

if [ "$#" -eq  "0" ]
then
	help;
fi

if [ "$#" -eq  "1" ]
then
	FILE=$1;
fi

echo "del:$FILE" > /sys/kernel/security/fsintegr/config

