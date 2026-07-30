#!/bin/bash
if [ $1 == "https" ] && [ $2 == "True" ];then
       echo "the proxy_mode field configuration in hosts file and the lb_mode field configuration in group_vars/all file have conflict"
       exit 1
fi





