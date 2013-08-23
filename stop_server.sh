#!/bin/bash
for i in `ps augx | grep -i 'script/server' | grep -v grep | awk '{print $2}'`
do 
    sudo kill -9 $i
done
