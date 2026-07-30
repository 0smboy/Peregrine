#!/bin/bash

if [ $(ps -C  haproxy --no-headers| wc -l) -eq 0 ]; then
    systemctl start haproxy
    systemctl stop  keepalived
fi

