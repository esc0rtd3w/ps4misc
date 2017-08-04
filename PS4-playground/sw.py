from http.server import BaseHTTPRequestHandler, HTTPServer
import time

hostName = "0.0.0.0"
hostPort = 9000 

class MyServer(BaseHTTPRequestHandler):
    def do_GET(self):
        p = self.path
        if p.find("?") != -1:
            p = p[0:p.find("?")]
        print("REQ: %s " % p)
        if self.path == "http://fjp01.ps4.update.playstation.net/update/ps4/list/jp/ps4-updatelist.xml":
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            self.wfile.write(bytes(open("update/ps4/list/jp/ps4-updatelist.xml").read(), "utf-8"))
            return
        if self.path.startswith("http://manuals.playstation.net/document/cs/ps4/"):
            

            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(open(p[47:]).read(), "utf-8"))
            return

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(bytes("<html><head><title>Title goes here.</title></head>", "utf-8"))
        self.wfile.write(bytes("<body><p>This is a test.</p>", "utf-8"))
        self.wfile.write(bytes("<p>You accessed path: %s</p>" % self.path, "utf-8"))
        self.wfile.write(bytes("</body></html>", "utf-8"))

myServer = HTTPServer((hostName, hostPort), MyServer)
print(time.asctime(), "Server Starts - %s:%s" % (hostName, hostPort))

try:
    myServer.serve_forever()
except KeyboardInterrupt:
    pass

myServer.server_close()
print(time.asctime(), "Server Stops - %s:%s" % (hostName, hostPort))
