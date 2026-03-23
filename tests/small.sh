#!/bin/bash
echo "Test 1: Single Packet"
echo "Petit texte pour tester" > hello.txt

python3 ../src/server.py ::1 8080 &
SERVER_PID=$!
sleep 1

python3 ../src/client.py --save alt_hello.txt http://[::1]:8080/hello.txt

#Cleanup
kill $SERVER_PID
rm hello.txt alt_hello.txt