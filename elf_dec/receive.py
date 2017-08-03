'''
    Simple socket server using threads
'''
 
import struct
import socket
import sys
import threading
 
HOST = ''   # Symbolic name meaning all available interfaces
PORT = 9000 # Arbitrary non-privileged port
 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print('Socket created')
 
#Bind socket to local host and port
try:
    s.bind((HOST, PORT))
except socket.error as msg:
    print('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
    sys.exit()
     
print('Socket bind complete')
 
#Start listening on socket
s.listen(10)
print('Socket now listening')
 
#Function for handling connections. This will be used to create threads
def clientthread(conn):
    #Sending message to connected client
    #conn.send('') #send only takes string
    datab = bytes()
    #infinite loop so that function do not terminate and thread do not end.
    while True:
         
        #Receiving from client
        data = conn.recv(1024)
        if not data: 
            break
     
        datab += data

        while True:
            need = 4

            if len(datab) < need:
                break

            cmd = struct.unpack_from("I", datab, 0)

            if cmd == 0x01:
                need += 8
                if len(datab) < need:
                    break

                (offset, bsize) = struct.unpack_from("II", datab, 4)

                need += bsize

                if len(datab) < need:
                    break

                block = datab[12:12+bsize]
                #write block to file

                print("writing block %d" % bsize)

            if (cmd == 0x02):
                if (len(datab) < 8):
                    break
                (fnlen,) = struct.unpack_from("I", datab, 4)
                need += 4 + fnlen
                if len(datab) < need:
                    break
                (name,) = struct.unpack_from("%ds" % fnlen, datab, 8)
                
                print("start file: %s " % name)

            if cmd == 0x03:
                #file closed, no more data needed
                print("end file")

            datab = datab[need:]
     
    #came out of loop
    conn.close()

#now keep talking with the client
while 1:
    #wait to accept a connection - blocking call
    conn, addr = s.accept()
    print('Connected with ' + addr[0] + ':' + str(addr[1]))
     
    #start new thread takes 1st argument as a function name to be run, second is the tuple of arguments to the function.
    threading.Thread(target=clientthread,
            args=(conn,)).start()
 
s.close()