from socket import *
import socketserver
# from dns.resolve
import dnslib as dl
qtype = {1: 'A', 2: 'NS', 5: 'CNAME', 15: 'MX', 28: 'AAAA'}
ROOT_SERVER_ADDRESS = dl.RR.fromZone("m.root-servers.net.     2275    IN      A       202.12.27.33\
                                     f.root-servers.net.     453     IN      A       192.5.5.241\
                                     c.root-servers.net.     1382    IN      A       192.33.4.12\
                                     k.root-servers.net.     139     IN      A       193.0.14.129\
                                     d.root-servers.net.     756     IN      A       199.7.91.13\
                                     g.root-servers.net.     3302    IN      A       192.112.36.4\
                                     h.root-servers.net.     133     IN      A       198.97.190.53\
                                     a.root-servers.net.     2609    IN      A       198.41.0.4\
                                     i.root-servers.net.     2134    IN      A       192.36.148.17\
                                     j.root-servers.net.     385     IN      A       192.58.128.30\
                                     l.root-servers.net.     47      IN      A       199.7.83.42\
                                     b.root-servers.net.     1589    IN      A       199.9.14.201\
                                     e.root-servers.net.     349     IN      A       192.203.230.10")
AU_SEC = dl.RR.fromZone(".                       2430    IN      NS      f.root-servers.net.\
                        .                       2430    IN      NS      g.root-servers.net.\
                        .                       2430    IN      NS      j.root-servers.net.\
                        .                       2430    IN      NS      k.root-servers.net.\
                        .                       2430    IN      NS      i.root-servers.net.\
                        .                       2430    IN      NS      h.root-servers.net.\
                        .                       2430    IN      NS      m.root-servers.net.\
                        .                       2430    IN      NS      l.root-servers.net.\
                        .                       2430    IN      NS      e.root-servers.net.\
                        .                       2430    IN      NS      b.root-servers.net.\
                        .                       2430    IN      NS      a.root-servers.net.\
                        .                       2430    IN      NS      c.root-servers.net.\
                        .                       2430    IN      NS      d.root-servers.net.")
cache = {}


class SimDNSServer:
    def __init__(self, port=53):
        self.port = port
        self.server = socketserver.UDPServer(
            ('127.0.0.1', self.port), SimDNSHandler)

    def start(self):
        self.server.serve_forever()


class SimDNSHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)

    def handle(self):
        # self.request[1].sendto(answer.pack(),self.client_address)
        # print(self.request[0])
        request = dl.DNSRecord.parse(self.request[0])
        answer = request.reply()  # create answer
        question_string = request.questions[0].toZone()
        if question_string in cache:
            for answer_record in cache[question_string].rr:
                answer.rr.append(answer_record)
            for authority_record in cache[question_string]:
                answer.auth.append(authority_record)
            for additional_record in
            # 将answer RR 加进去

        print(request.questions[0].toZone())

        # if request.questions[0] in

        # request.header.rd = 0 # set rd as 0

        # if

        # if q.header.rd == 1:  # rd flag
        #     pass
        # else:
        #     pass
        # print(q.header.rd)  # rd flag
        # print(q.q.qname)  # q.class q.qtype qname
        # print(q.header.get_opcode())
        # # a, aa,ad,ar,auth,bitmap,cd,id,opcode,q,qr,ra,rcode,rd,tc,z
        # print(q.header.id)
        # print(q.a.rclass)  # a.rclass rdata tdlength rname rtype ttl
        # # print(q)
        # root_server_c = "192.33.4.12"  # france root DNS server
        # # d = DNSRecord.question("")

        """
        如果有cache
        """

        """else:"""

    @staticmethod
    def iterative_search():
        pass

    @staticmethod
    def recursive_search():
        pass


if __name__ == "__main__":
    sev = SimDNSServer()
    # sev.addname('www.aa.com', '192.168.0.1')  # add a A record
    # sev.addname('www.bb.com', '192.168.0.2')  # add a A record
    sev.start()
