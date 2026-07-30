#!/bin/bash
declare swift_proc_num=0
declare rsync_proc_num=0
swift_proc_num=$(ps aux | grep swift | grep -E "proxy|account|container|object"|wc -l)
rsync_proc_num=$(ps aux | grep rsync | grep -v grep|wc -l)
if [[ $swift_proc_num  != 0 ]]; then 
  ps aux | grep swift | grep -E "proxy|account|container|object" | awk '{print $2}' | xargs kill -9 2>/dev/null
fi
if [[ $rsync_proc_num  != 0 ]]; then
  systemctl stop rsyncd
fi

