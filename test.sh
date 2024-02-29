#!/bin/bash

echo "Creating high entropy random executable-like file in current directory."
echo -en "\x7f\x45\x4c\x46" > ./high.entropy.test
head -c 50000 </dev/urandom >> ./high.entropy.test

echo "Creating low entropy executable-like file in current directory."
echo -en "\x7f\x45\x4c\x46" > ./low.entropy.test
head -c 50000 </dev/zero >> ./low.entropy.test

echo "Running sandfly-ento-scan to generate entropy and hash values."
./ento-scan -dir . -elf