from Components.Packet import Packet


class Client:
    def __init__(self, ip):
        self.ip = ip
        self.link = None
        self.msg = ''
        self.trace_route_state = False
        self.path = ''
        self.ping_port = '1111'
        self.timer = 0
        self.response = False

    def connect(self, link):
        """
        :param link: A Hub
        """
        self.link = link

    def receive_pkt(self, pkt):
        # TODO handle received packet
        if pkt.type == 'msg':
            if pkt.receiver == self.ip:
                print("client side : packet received\n", pkt)
                self.msg += pkt.body
                if not pkt.mf:
                    print(self.ip + ":", "msg from", pkt.sender, self.msg)
                    self.msg = ''
        elif pkt.type == 'icmp':
            self.response = True
            if pkt.receiver == self.ip:
                print("client side : packet received\n", pkt)
                code = pkt.body
                if code == '0':  # ping now send ping response
                    self.send_ping_msg('1', pkt.receiver_port, pkt.sender, pkt.sender_port, 1000, 0)
                elif code == '1':   # ping response now print path
                    if self.trace_route_state:
                        self.path += " " + pkt.sender
                        print(self.path)
                        self.path = ''
                        self.trace_route_state = False
                elif code == '2':   # didn't reach the destination
                    if self.trace_route_state:
                        print(self.path, "unreachable")
                        self.path = ''
                        self.trace_route_state = False
                    else:
                        print(self.ip + ":", "unreachable")
                elif code == '3':   # needed fragmentation but couldn't
                    print(self.ip + ":", "fragmentation needed")
                elif code == '4':
                    if self.trace_route_state:
                        self.path += " " + pkt.sender
                    else:
                        print(self.ip + ":", "ttl timeout")
                elif code == '5':
                    if self.trace_route_state:
                        self.path = ''
                        self.trace_route_state = False
                    else:
                        print(self.ip + ":", "NAT dropped")

    def send_msg(self, msg, sndr_port, rcvr, rcvr_port, ttl, df):
        """
        Sends a packet containing a message to another client
        :param msg: the message
        :param sndr_port: sender port
        :param rcvr: receiver ip
        :param rcvr_port: receiver port
        :param ttl: time-to-live
        """

        pkt = Packet(self.ip, sndr_port, rcvr, rcvr_port, 'msg', ttl, False, df, 0, msg)
        if self.link:
            # print("packet sent:\n", pkt)
            self.link.send(pkt, self.ip)

    def trace_rout(self, ip):
        """
        trace rout to ip
        :param ip: destination
        """
        # TODO
        self.trace_route_state = True
        ttl = 0
        self.timer = 3
        self.path += self.ip
        while True:
            if not self.trace_route_state:
                break
            ttl += 1
            self.send_ping_msg('0', self.ping_port, ip, self.ping_port, ttl, 0)
            if not self.response:
                self.response = True
                break
            self.response = False
        pass

    def update(self):
        self.timer -= 1
        if self.timer <= 0 and self.trace_route_state:
            self.trace_route_state = False
            print(self.path, "timeout")
            self.path = ''

    def send_ping_msg(self, msg, sndr_port, rcvr, rcvr_port, ttl, df):
        pkt = Packet(self.ip, sndr_port, rcvr, rcvr_port, 'icmp', ttl, False, df, 0, msg)
        if self.link:
            self.link.send(pkt, self.ip)
