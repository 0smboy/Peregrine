#!/bin/bash
#输出信息
echo -e "请根据部署情况选择:\n创建新的集群请输入:1\n添加节点请输入:2"
while read a
do
if [[ $a == "1" || $a == "2" ]]
then
break
else
echo -e "请根据部署情况选择:\n创建新的集群请输入:1\n添加节点请输入:2"
fi
done

if [ $a == "1" ]
then
# 获取swift_hosts里的所有节点IP,并输出到peregrine_host文件中。
grep "ansible_ssh_user" ../swift_hosts | grep "^[1-9]" | awk '{print $1}' > peregrine_host
else
# 获取add_nodes里的所有节点IP,并输出到peregrine_host文件中。
grep "ansible_ssh_user" ../add_nodes | grep "^[1-9]" | awk '{print $1}' > peregrine_host
fi

# 把192.168.2.[51:53]连续的IP转换成单独的IP,并追加到peregrine_host文件中。
a=`grep "\[.*\]" peregrine_host`
for i in $a
do
test1=`echo $i | awk -F [ '{print $1}'`
test2=`echo $i | grep -o '\[.*\]'  | sed 's/\[//;s/:.*//'`
test3=`echo $i | grep -o '\[.*\]'  | sed 's/.*://;s/\]//'`
for j in $(seq ${test2} ${test3})
do
echo $test1$j >> peregrine_host
done
done

# 删除192.168.2.[51:53]此类型的IP删除，并使用重定向生成以主机命名的host_vars文件,最后删除peregrine_host文件
sed -i '/\[.*\]/d' peregrine_host
all_hosts=`cat peregrine_host`
for i in $all_hosts
do
echo "---
# 配置当前主机的存储网络,复制网络ip
# 几个网络使用同一地址的话也需要配置
#
# 管理网络,即 ssh, zabbix, elasticsearch, grafana 的绑定ip
management_network_address: $i

# 存储网络,即account, container, object, rsyncd 的绑定ip
storage_network_address: $i

# 业务网络,即 swift endpoint, keystone 绑定ip
business_network_address: $i

# 是否为 keystone, mariadb 节点
keystone_node: false
mariadb_node: false

# 自定义盘符（适用于非 /dev/sdx 开头的磁盘，例如 /dev/vda）
custom_disks: []
# hdd or ssd
disk_type: ''

# 添加不需要格式化的盘，包括系统盘，如果系统盘不是sda请把正确的系统盘添加到下面列表！
exclude_disks: ['sda']

# 如果有需要添加新的盘，则填入下面列表，没有则忽略以下行
# new_disks_to_format: ['sdd']
" > $i
done

rm -rf peregrine_host
