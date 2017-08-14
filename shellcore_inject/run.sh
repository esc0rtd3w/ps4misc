#!/bin/sh
cat bin/shellcore_inject | nc $ps4ip 5053
#socat -u FILE:bin/shellcore_inject TCP:192.168.2.2:5053
