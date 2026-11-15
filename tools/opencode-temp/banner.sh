#!/bin/bash
echo "--- .95:22 ---"
( sleep 2 ) | nc -G 2 -w 3 198.51.100.1 22
echo "--- .95:2222 ---"
( sleep 2 ) | nc -G 2 -w 3 198.51.100.1 2222
echo "--- .108:22 ---"
( sleep 2 ) | nc -G 2 -w 3 198.51.100.1 22
echo DONE
