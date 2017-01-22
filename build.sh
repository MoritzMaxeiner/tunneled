#!/bin/sh

dmd tunneled.d
sudo chown root tunneled
sudo chmod u+s tunneled
