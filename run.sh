#!/bin/bash

# Run the command and pass the output to the script
./ento-scan -dir ./ -entropy 7.5 -md5 -elf >> /usr/local/maldetect/sigs/custom.md5.dat
maldet -a /home/kali/Downloads
