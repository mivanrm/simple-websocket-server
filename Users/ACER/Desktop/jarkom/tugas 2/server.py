import socketserver
import base64

import hashlib
class TCPhandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.data=self.request.recv(1024).strip().decode()
        headers= self.data.split("\r\n")

        if "Connection: Upgrade" in self.data and "Upgrade: websocket" in self.data:
            for item in headers:
                if "Sec-WebSocket-Key" in item:
                    key= item.split(" ")[1]
            GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
            hash = hashlib.sha1(key.encode() + GUID.encode())
            response_key = base64.standard_b64encode(hash.digest()).strip()
            response_key=response_key.decode('ASCII')
            resp="HTTP/1.1 101 Switching Protocols\r\n" + \
             "Upgrade: websocket\r\n" + \
             "Connection: Upgrade\r\n" + \
             "Sec-WebSocket-Accept: %s\r\n\r\n"%(response_key)
            resp=resp.encode()
            self.request.sendall(resp)
        else:
            self.request.sendall("HTTP/1.1 400 Bad Request\r\n" + \
                                 "Content-Type: text/plain\r\n" + \
                                 "Connection: close\r\n" + \
                                 "\r\n" + \
                                 "Incorrect request")


if __name__ == "__main__":
    HOST, PORT = "localhost", 9999

    # Create the server, binding to localhost on port 9999
    server = socketserver.TCPServer((HOST, PORT), TCPhandler)
    server.serve_forever()