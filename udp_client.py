from socket import *


def echo():
    serverName = '127.0.0.1'
    serverPort = 12000
    clientSocket = socket(AF_INET, SOCK_DGRAM)
    website = input('Input the website address: ')
    typeName = input('Input the query types: ')
    rd = input('RD is set or not? (0 is clear, 1 is set): ')
    sendMessage = website + "\t"+typeName+"\t"+rd
    clientSocket.sendto(sendMessage.encode(), (serverName, serverPort))
    modifiedMessage, serverAddress = clientSocket.recvfrom(2048)
    print(modifiedMessage.decode())
    clientSocket.close()


if __name__ == '__main__':
    try:
        echo()
    except KeyboardInterrupt:
        pass
