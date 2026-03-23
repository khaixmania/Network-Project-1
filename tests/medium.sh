#!/bin/bash
echo "Test 2: Fichier binaire de 5000 octets"
head -c 5000 </dev/urandom > medium.bin

python3 ../src/server.py ::1 8080 &
SERVER_PID=$!
sleep 1

python3 ../src/client.py --save alt_medium.bin http://[::1]:8080/medium.bin

kill $SERVER_PID
rm medium.bin alt_medium.bin