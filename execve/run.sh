#!/bin/sh
cat bin/execve | nc $ps4ip 6053
#socat -u FILE:bin/execve TCP:192.168.2.2:6053
