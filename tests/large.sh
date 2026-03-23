#!/bin/bash
echo "Test 3: Fichier binaire de 3000000 octets"
head -c 3000000 </dev/urandom > large.bin

python3 ../src/server.py ::1 8080 &
SERVER_PID=$!
sleep 1

python3 ../src/client.py --save alt_large.bin http://[::1]:8080/large.bin

kill $SERVER_PID
rm large.bin alt_large.bin