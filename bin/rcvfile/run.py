#! /usr/bin/python

import socket
import os
import sys

# connect to 8099
# sendfilename
# sendfile
# socketclose
if len(sys.argv) < 3:
    print("need more arguments [ip] [localfile] [remotepath]")
    exit()

#print(sys.argv)
localfile = sys.argv[-2]
remotepath = sys.argv[-1]
print("%s -> %s" % (localfile, remotepath))

msg = open(localfile, "rb").read()

#print("cat $ps4misc/bin/rcvfile/bin/rcvfile | nc %s 6053" % (sys.argv[-3],))
os.system("cat $ps4misc/bin/rcvfile/bin/rcvfile | nc %s 6053" % (sys.argv[-3],))

# create an INET, STREAMing socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# now connect to the web server on port 80 - the normal http port
s.connect((sys.argv[-3], 8099))
s.send(remotepath)
s.send("\x00")

MSGLEN = len(msg)

totalsent = 0
while totalsent < MSGLEN:
    sent = s.send(msg[totalsent:])
    if sent == 0:
        raise RuntimeError("socket connection broken")
    totalsent = totalsent + sent

s.close()
