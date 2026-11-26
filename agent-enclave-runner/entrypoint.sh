#!/bin/sh
set -e

socat TCP4-LISTEN:443,fork,reuseaddr VSOCK-CONNECT:3:8443 &
socat VSOCK-LISTEN:5000,fork,reuseaddr TCP4:127.0.0.1:5000 &

exec npm start
