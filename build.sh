#!/bin/sh

cython tunneled.py --embed -o /tmp/tunneled.c
gcc -I /usr/include/python3.4 /tmp/tunneled.c -o tunneled -lpython3.4 -lm -ldl -lpthread -lutil
rm -f /tmp/tunneled.c
sudo chown root tunneled
sudo chmod u+s tunneled
