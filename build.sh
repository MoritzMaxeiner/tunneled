#! /bin/sh

dub build --build=release
sudo chown root tunneled
sudo chmod u+s tunneled
