#!/bin/bash

controller_pro=`jps | grep Main | wc -l`
if [[ $controller_pro > 0 ]];then
   jps | grep  Main | awk '{print $1}' | xargs kill -9 2>/dev/null
fi
