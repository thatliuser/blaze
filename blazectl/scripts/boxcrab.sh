#!/bin/sh

if [ "$#" -lt 1 ]; then
    echo 'No server endpoint set! exiting'
    exit 1
fi

echo "Using server IP $IP"

IP="$1"
curl -LO "$IP/bin/linux-x64"
chmod +x linux-x64
./linux-x64 --enable-all-crabs true --server-address "$IP"
