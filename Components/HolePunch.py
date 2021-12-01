from Components.Client import Client
from Components.Packet import Packet


class Server:
    def __init__(self, ip):
        self.ip = ip
        self.link = None
        self.msg = ''

    def connect(self, link):
        """
        :param link: A Hub
        """
        self.link = link

    def receive_pkt(self, pkt):
        # TODO handle received packet
        if pkt.type == 'msg':
            if pkt.receiver == self.ip:
                self.msg += pkt.body
                if not pkt.mf:
                    print(self.ip + ":", "msg from", pkt.sender, self.msg)
                    self.msg = ''
        elif pkt.type == 'icmp':
            if pkt.receiver == self.ip:
                code = pkt.body
                if code == '0':  # ping now send ping response
                    self.send_ping_msg('1', pkt.receiver_port, pkt.sender, pkt.sender_port, 1000, 0)
                elif code == '5':
                    print(self.ip + ":", "NAT dropped")
        else:
            pass

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

    def send_ping_msg(self, msg, sndr_port, rcvr, rcvr_port, ttl, df):
        pkt = Packet(self.ip, sndr_port, rcvr, rcvr_port, 'icmp', ttl, False, df, 0, msg)
        if self.link:
            self.link.send(pkt, self.ip)


def peer_to_peer(server_ip, client1, client2):
    """
    make peer-to-peer connection via UDP hole punching
    :param server_ip: ip of server used in hole punch
    :param client1: first client
    :param client2: second client
    :return:
    """
    pass
