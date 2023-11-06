#!/bin/bash
#install required libraries on Debian 10
apt-get -y install build-essential libssl-dev
gcc cryptolandi.c -o bin/c3  -lssl -lcrypto
cp bin/c3 /usr/bin/
	
