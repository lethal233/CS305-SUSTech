from socket import socket, AF_INET, SOCK_DGRAM, inet_aton, inet_ntoa
import time

sockets = {}
network = ('127.0.0.1', 12345)

def bytes_to_addr(bytes):
    return inet_ntoa(bytes[:4]), int.from_bytes(bytes[4:8], 'big')
    
def addr_to_bytes(addr):
    return inet_aton(addr[0]) + addr[1].to_bytes(4, 'big')

def get_sendto(id, rate=None):
    if rate:
        def sendto(data:bytes, addr):
            time.sleep(len(data)/rate)
            sockets[id].sendto(addr_to_bytes(addr) + data, network)
        return sendto
    else:
        def sendto(data:bytes, addr):
            sockets[id].sendto(addr_to_bytes(addr) + data, network)
        return sendto

class UnreliableSocket:
    def __init__(self, rate=None):
        assert rate==None or rate>0, 'Rate should be positive or None.'
        sockets[id(self)] = socket(AF_INET, SOCK_DGRAM)
        self.sendto = get_sendto(id(self), rate)
        
    def bind(self, address:(str, int)):
        sockets[id(self)].bind(address)
        
    def recvfrom(self, bufsize)->bytes:
        data, frm = sockets[id(self)].recvfrom(bufsize)
        addr = bytes_to_addr(data[:8])
        if frm==network:
            return data[8:], addr
        else:
            return self.recvfrom(bufsize)
    
    def settimeout(self, value):
        sockets[id(self)].settimeout(value)
    
    def gettimeout(self):
        return sockets[id(self)].gettimeout()

    def setblocking(self, flag):
        sockets[id(self)].setblocking(flag)

    def getblocking(self):
        sockets[id(self)].getblocking()

    def getsockname(self):
        return sockets[id(self)].getsockname()

    def close(self):
        sockets[id(self)].close()


