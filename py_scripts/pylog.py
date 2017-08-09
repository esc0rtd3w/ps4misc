#! /usr/bin/env python

# Usage: udpecho -s [port]            (to start a server)

import sys
from socket import *

ECHO_PORT = 9001
BUFSIZE = 4096

def server():
    if len(sys.argv) > 2:
        port = eval(sys.argv[2])
    else:
        port = ECHO_PORT
    s = socket(AF_INET, SOCK_DGRAM)
    s.bind(('0.0.0.0', port))
    print 'udp echo server ready'
    while 1:
        data, addr = s.recvfrom(BUFSIZE)
        #print data
        print(str(data, "utf-8"), end='', flush=True)


server()
