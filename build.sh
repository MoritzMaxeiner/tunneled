#!/bin/sh

gcc -std=c11 tunneled.c -o tunneled -lpthread -lrt
sudo chown root tunneled
sudo chmod u+s tunneled
