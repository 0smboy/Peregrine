#!/bin/bash

mkdir -p /etc/yum.repos.d/backup
mv /etc/yum.repos.d/*.repo /etc/yum.repos.d/backup | echo
yum clean all | echo
