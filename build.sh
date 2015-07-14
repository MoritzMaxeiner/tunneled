#!/bin/sh

cython_freeze tunneled FileLock > /tmp/tunneled_launcher.c
cython tunneled.py -o /tmp/tunneled.c
cython FileLock.py -o /tmp/FileLock.c
gcc -c -I /usr/include/python3.4 /tmp/tunneled_launcher.c -o /tmp/tunneled_launcher.o
gcc -c -I /usr/include/python3.4 /tmp/tunneled.c -o /tmp/tunneled.o
gcc -c -I /usr/include/python3.4 /tmp/FileLock.c -o /tmp/FileLock.o
gcc /tmp/tunneled_launcher.o /tmp/tunneled.o /tmp/FileLock.o -o tunneled -lpython3.4 -lm -ldl -lpthread -lutil
rm -f /tmp/tunneled_launcher.* /tmp/tunneled.* /tmp/FileLock.*
sudo chown root tunneled
sudo chmod u+s tunneled
