#!/bin/bash
system_disk=`fdisk  -l |  grep  -A 1 'Device Boot' | grep 'Linux' | awk '{print $1}' | awk -F "[0-9/]" '{print $3}'`
if [[ $system_disk == *$1* ]];then
    echo  $1 "is system disk,can not format it"
    exit 1
fi


