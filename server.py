from rdt import RDTSocket
from socket import socket, AF_INET, SOCK_DGRAM, SOCK_STREAM
import time

if __name__=='__main__':
    # server = RDTSocket()
    server = RDTSocket() # check what python socket does
    server.bind(('127.0.0.1', 9999))
    # server.listen(0) # check what python socket does

    while True:
        conn, client_addr = server.accept()
        start = time.perf_counter()
        while True:
            data = conn.recv(2048)
            if data:
                conn.send(data)
            else:
                break
        '''
        make sure the following is reachable
        '''
        conn.close()
        print(f'connection finished in {time.perf_counter()-start}s')