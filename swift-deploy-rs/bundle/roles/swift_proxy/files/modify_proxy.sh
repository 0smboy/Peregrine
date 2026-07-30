#!/bin/bash
BASE_DIR="/etc/swift"
cd $BASE_DIR && git init > /dev/null
# 使用git对"/etc/swift"目录进行管理
git add . 
git config --global user.email "ostorage@ostorage.com.cn"
git config --global user.name "ostorage"
git commit -m "swift" > /dev/null
# 切换到keystone s3api分支，并使用sed把prox-server.conf进行修改
git checkout -B "keystone_s3api" "master" 2> /dev/null
sed -i 's/authtoken keystoneauth/authtoken s3api s3token keystoneauth/;' /etc/swift/proxy-server.conf
git add .
git commit -m "keystone_s3api"  > /dev/null
# 切换到oss分支，并使用sed把prox-server.conf进行修改
git checkout -B "oss" "master" 2> /dev/null
sed -i 's/ratelimit swauth/ratelimit oss2swift swauth/; /\[filter:swauth\]/i [filter:oss2swift]\nuse = egg:oss2swift#oss2swift\n' /etc/swift/proxy-server.conf
sed -i '/default_swift_cluster/a s3_support = on'  /etc/swift/proxy-server.conf
git add .
git commit -m "oss"  > /dev/null
git checkout master 2> /dev/null
chown root.swift /etc/swift/proxy-server.conf
