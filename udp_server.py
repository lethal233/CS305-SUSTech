from socket import *
import dns.resolver


def echo():
    serverPort = 12000
    serverSocket = socket(AF_INET, SOCK_DGRAM)
    serverSocket.bind(('', serverPort))
    print("The server is ready to receive")
    while True:
        message, clientAddress = serverSocket.recvfrom(2048)
        sameMessage = message.decode()
        print(sameMessage.encode())
        lister = sameMessage.split("\t")
        print(lister)
        if lister[2] == "0":
            if lister[1].upper() == 'A':
                A = dns.resolver.query(lister[0], 'A')
                for i in A.response.answer:
                    for j in i.items:
                        print(j.address)
            elif lister[1].upper() == "AAAA":
                AAAA = dns.resolver.query(lister[0], 'AAAA')
                for i in AAAA.response.answer:
                    for j in i.items:
                        print(j)
            elif lister[1].upper() == "CNAME":
                cname = dns.resolver.query(lister[0], 'CNAME')
                for i in cname.response.answer:
                    for j in i.items:
                        print(j.to_text())
            elif lister[1].upper() == "NS":
                ns = dns.resolver.query(lister[0], 'NS')
                for i in ns.response.answer:
                    for j in i.items:
                        print(j.to_text())
            elif lister[1].upper() == 'MX':
                pass
        else:
            pass
        serverSocket.sendto(sameMessage.encode(), clientAddress)
        cache = {}
    serverSocket.close()


if __name__ == "__main__":
    echo()
