import os
import binascii
import sys

signature = binascii.unhexlify(sys.argv[-1])
def listdir(a):
    for file in os.listdir(a):
        fname = os.path.join(a, file)
        #print(fname)
        try:
            f = open(fname, mode="rb").read()
            #print("readed %s %d" % (fname, len(f)))
            found = f.find(signature, 0)
            if found > -1:
                print("> %s %d" % (fname, found))
        except:
            print("except %s" % fname)
            pass
        try:
            listdir(fname)
        except:
            pass

listdir("./")

