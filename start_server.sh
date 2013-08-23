#!/bin/bash

# Rotate nohup.out
mv nohup.out nohup-$(date '+%d%m%y%H%M%S') 2>&1 &
# Run server in production mode in background.
sudo nohup script/server -e production 2>&1 &
