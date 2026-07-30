#!/bin/bash

if [ $(ps -C  openstack-swift-proxy  | wc -l) -eq 0 ]; then
    systemctl start openstack-swift-proxy
    systemctl stop  keepalived
fi

