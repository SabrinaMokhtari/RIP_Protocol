import json
from Components.Packet import Packet
from ipaddress import ip_address
from collections import defaultdict


class Router:
    def __init__(self, id):
        self.id = id
        self.interfaces = dict()
        self.dist = dict()
        # self.new_dist = dict()
        self.invalid_timer = dict()
        self.hold_timer = dict()
        self.my_timer = 30
        self.msg = ''
        self.acl = list()
        self.pool = list()
        self.map_acl_to_pool = dict()
        self.map_acl_to_pool_time = dict()
        self.is_overload = False
        self.is_res = False
        self.outside = None
        self.inside = None
        self.connections = defaultdict(list)

    def receive_pkt(self, in_ip, pkt):
        self.msg += pkt.body
        if not pkt.mf:
            pkt.body = self.msg
            # print("packet received", "sender:", pkt.sender, "receiver:", pkt.receiver, "me:", self.id, pkt)
            self.msg = ''
            if pkt.type == 'ad':  # update_distance
                dist_vector = json.loads(pkt.body)
                self.update_distance(dist_vector, pkt.sender, pkt.receiver)
            elif pkt.type == 'msg':  # send to the next router/client
                dest_ip = pkt.receiver
                pkt.ttl -= 1
                if not self.dist.keys().__contains__(dest_ip):  # no rout to dest
                    code = '2'
                    self.send_icmp(code, pkt)
                elif self.dist[dest_ip][0] > 15:  # no rout to dest
                    code = '2'
                    self.send_icmp(code, pkt)
                elif pkt.ttl <= 0:  # ttl finished
                    code = '4'
                    self.send_icmp(code, pkt)
                else:
                    interface = self.dist[dest_ip][1]
                    if self.interfaces[interface].link is not None and len(pkt.body) > self.interfaces[
                        interface].link.mtu:
                        if pkt.df:
                            code = '3'  # needed fragment but can't
                            self.send_icmp(code, pkt)
                        else:
                            if self.interfaces[in_ip].is_outside and self.interfaces[
                                interface].is_inside and pkt.receiver not in self.pool:
                                code = '5'
                                self.send_icmp(code, pkt)
                                return
                            elif self.interfaces[interface].is_outside and self.interfaces[in_ip].is_inside:
                                pkt = self.map(pkt.sender, pkt.sender_port, pkt)
                            elif self.interfaces[in_ip].is_outside and pkt.receiver in self.pool:
                                pkt = self.de_map(pkt.receiver, pkt.receiver_port, pkt)
                                if pkt is not None:
                                    interface = self.dist[pkt.receiver][1]
                            if pkt is not None:
                                self.send_multiple_pck(self.interfaces[interface], pkt)
                    elif self.interfaces[interface].hub is not None and len(pkt.body) > self.interfaces[
                        interface].hub.mtu:
                        if pkt.df:  # needed fragment  but can't
                            code = '3'
                            self.send_icmp(code, pkt)
                        else:
                            if self.interfaces[in_ip].is_outside and self.interfaces[
                                interface].is_inside and pkt.receiver not in self.pool:
                                code = '5'
                                self.send_icmp(code, pkt)
                                return
                            elif self.interfaces[interface].is_outside and self.interfaces[in_ip].is_inside:
                                pkt = self.map(pkt.sender, pkt.sender_port, pkt)
                            elif self.interfaces[in_ip].is_outside and pkt.receiver in self.pool:
                                pkt = self.de_map(pkt.receiver, pkt.receiver_port, pkt)
                                if pkt is not None:
                                    interface = self.dist[pkt.receiver][1]
                            if pkt is not None:
                                self.send_multiple_pck(self.interfaces[interface], pkt)
                    else:
                        if self.interfaces[in_ip].is_outside and self.interfaces[
                            interface].is_inside and pkt.receiver not in self.pool:
                            code = '5'
                            self.send_icmp(code, pkt)
                            return
                        elif self.interfaces[interface].is_outside and self.interfaces[in_ip].is_inside:
                            pkt = self.map(pkt.sender, pkt.sender_port, pkt)
                        elif self.interfaces[in_ip].is_outside and pkt.receiver in self.pool:
                            pkt = self.de_map(pkt.receiver, pkt.receiver_port, pkt)
                            if pkt is not None:
                                interface = self.dist[pkt.receiver][1]
                        if pkt is not None:
                            self.interfaces[interface].send_pkt(pkt)
            else:  # icmp
                receiver = pkt.receiver
                pkt.ttl -= 1
                if pkt.body == '0':  # ping
                    if pkt.ttl <= 0:  # ttl finished
                        code = '4'
                        self.send_icmp(code, pkt)
                    elif self.dist.keys().__contains__(receiver) and self.dist[receiver][0] < 15:
                        interface = self.dist[receiver][1]
                        if self.interfaces[in_ip].is_outside and self.interfaces[
                            interface].is_inside and pkt.receiver not in self.pool:
                            code = '5'
                            self.send_icmp(code, pkt)
                            return
                        elif self.interfaces[interface].is_outside and self.interfaces[in_ip].is_inside:
                            pkt = self.map(pkt.sender, pkt.sender_port, pkt)
                        elif self.interfaces[in_ip].is_outside and pkt.receiver in self.pool:
                            pkt = self.de_map(pkt.receiver, pkt.receiver_port, pkt)
                            if pkt is not None:
                                interface = self.dist[pkt.receiver][1]
                        if pkt is not None:
                            self.interfaces[interface].send_pkt(pkt)
                    else:
                        code = '2'
                        self.send_icmp(code, pkt)
                else:
                    if self.dist.keys().__contains__(receiver) and self.dist[receiver][0] < 15:
                        interface = self.dist[receiver][1]
                        if self.interfaces[in_ip].is_outside and pkt.receiver in self.pool:
                            if self.is_overload:
                                for k in self.map_acl_to_pool.keys():
                                    if self.map_acl_to_pool[k] == (pkt.receiver, pkt.receiver_port):
                                        pkt.receiver, pkt.receiver_port = k
                                        break
                            else:
                                for k in self.map_acl_to_pool.keys():
                                    if self.map_acl_to_pool[k] == pkt.receiver:
                                        pkt.receiver = k
                                        break
                            interface = self.dist[pkt.receiver][1]
                        elif self.interfaces[in_ip].is_inside and self.interfaces[interface].is_outside:
                            if self.is_overload:
                                (pkt.receiver, pkt.receiver_port) = self.map_acl_to_pool[(pkt.sender, pkt.sender_port)]
                            else:
                                # if pkt.sender not in self.map_acl_to_pool.keys():
                                #     return
                                pkt.receiver = self.map_acl_to_pool[pkt.sender]
                            interface = self.dist[pkt.receiver][1]
                        self.interfaces[interface].send_pkt(pkt)
        pass

    def connected(self, ip, mip, is_router):
        """
        to add ip to routing list
        :param ip:
        :return:
        """
        self.dist[ip] = (1, mip)
        # self.new_dist[ip] = (1, mip)
        if is_router:  # neighbor timer
            self.invalid_timer[ip] = 180
        # print("successfully added the new ip", self.dist)
        pass

    def config(self):
        while True:
            cmd = input().split()
            if cmd[0] == 'exit':
                return
            elif cmd[0] == 'add_interface':
                self.interfaces[cmd[1]] = Interface(cmd[1], self)
                self.dist[cmd[1]] = (0, cmd[1])
                # self.new_dist[cmd[1]] = (0, cmd[1])
            elif cmd[0] == 'access_list':
                start = ip_address(cmd[3])
                end = ip_address(cmd[4])
                self.acl.append(start)
                self.acl.append(end)
                pass
            elif cmd[0] == 'nat':
                if cmd[1] == 'inside':
                    self.interfaces[cmd[2]].is_inside = True
                    self.inside = cmd[2]
                    pass
                elif cmd[1] == 'outside':
                    self.interfaces[cmd[2]].is_outside = True
                    self.outside = cmd[2]
                    for i in self.pool:
                        self.dist[i] = (0, self.outside)
                        # self.new_dist[i] = (0, self.outside)
                    pass
                elif cmd[1] == 'pool':
                    new_ips = self.find_Ip(cmd[3], cmd[4])
                    for i in new_ips:
                        self.pool.append(i)
                    pass
                elif cmd[1] == 'set':
                    if cmd.__contains__('res'):
                        self.is_res = True
                    if cmd.__contains__('overload'):
                        self.is_overload = True
                    pass

    def find_Ip(self, start, end):
        start = ip_address(start)
        end = ip_address(end)
        result = []
        while start <= end:
            result.append(str(start))
            start += 1
        return result

    def update_distance(self, dist_vectors, ip, mip):
        if ip in self.hold_timer.keys() and self.hold_timer[mip] > 0:
            return
        self.invalid_timer[ip] = 180
        self.dist[ip] = (1, mip)
        # self.new_dist[ip] = (1, mip)
        for d in dist_vectors.keys():
            if d in self.interfaces.keys():  # it's me so ignore it
                continue
            if d not in self.dist.keys():  # new so add this one might be > 15
                for i in self.interfaces.values():
                    if i.link is None:
                        continue
                    if i.link.right.ip == ip or i.link.left.ip == ip:
                        self.dist[d] = (dist_vectors[d][0] + self.dist[ip][0], i.ip)
                        if self.dist[d][0] > 15:
                            self.hold_timer[self.dist[d][1]] = 60
            else:
                if self.dist[d][0] > dist_vectors[d][0] + self.dist[ip][0]:  # found a better path to a router
                    for i in self.interfaces.values():
                        if i.link is not None:
                            if i.link.right.ip == ip or i.link.left.ip == ip:
                                self.dist[d] = (dist_vectors[d][0] + self.dist[ip][0], i.ip)
                                if self.dist[d][0] > 15:
                                    self.hold_timer[self.dist[d][1]] = 60
        for k in self.dist.keys():
            (d, i) = self.dist[k]
            if k in self.interfaces.keys() or k in self.pool:
                continue
            if self.interfaces[i].link is not None:
                if self.interfaces[i].link.right.ip == ip or self.interfaces[i].link.left.ip == ip:
                    temp = min(dist_vectors[k][0] + self.dist[ip][0], 16)
                    self.dist[k] = (temp, i)
                    if self.dist[k][0] > 15:
                        self.hold_timer[self.dist[k][1]] = 60
        # print(self.id, self.dist)
        return

    def send_advertise(self):
        self.my_timer = 30
        dist_vector = self.dist.copy()
        out_dist_vector = dict()
        for i in self.interfaces.values():
            if i.link is None:
                continue
            if i.is_outside:
                for d in dist_vector.keys():
                    if dist_vector[d][1] != self.inside:
                        out_dist_vector[d] = dist_vector[d]
                self.send_advertise_part_two(i, out_dist_vector)
            else:
                self.send_advertise_part_two(i, dist_vector)
        return

    def send_advertise_part_two(self, i, dist_vector):
        if i.link.left.ip == i.ip:
            receiver = i.link.right.ip
            for k in dist_vector.keys():
                if dist_vector[k][1] == i.ip and k != i.ip and k not in self.pool:
                    dist_vector[k] = (16, i.ip)
            pkt = Packet(i.ip, '', receiver, '', 'ad', 1, False, 1, 0, json.dumps(dist_vector))
            for k in dist_vector.keys():
                if dist_vector[k][1] == i.ip and k != i.ip and k not in self.pool:
                    dist_vector[k] = (self.dist[k][0], self.dist[k][1])
        else:
            receiver = i.link.left.ip
            for k in dist_vector.keys():
                if dist_vector[k][1] == i.ip and k != i.ip and k not in self.pool:
                    dist_vector[k] = (16, i.ip)
            pkt = Packet(i.ip, '', receiver, '', 'ad', 1, False, 1, 0, json.dumps(dist_vector))
            for k in dist_vector.keys():
                if dist_vector[k][1] == i.ip and k != i.ip and k not in self.pool:
                    dist_vector[k] = (self.dist[k][0], self.dist[k][1])
        self.send_multiple_pck(i, pkt)

    def send_icmp(self, code, pkt):
        src_ip = pkt.sender
        pkt.body = code
        if self.dist.keys().__contains__(src_ip) and self.dist[src_ip][0] < 15:
            interface_ip = self.dist[src_ip][1]
            pkt.sender = interface_ip
            pkt.receiver = src_ip
            pkt.receiver_port = pkt.sender_port
            pkt.ttl = 10000
            pkt.type = 'icmp'
            self.interfaces[interface_ip].send_pkt(pkt)
        return

    def send_multiple_pck(self, interface, pkt):
        if interface.link is not None:
            num_of_pkt = (len(pkt.body) // interface.link.mtu)
            if len(pkt.body) % interface.link.mtu != 0:
                num_of_pkt += 1
            body = pkt.body
            size = interface.link.mtu
            pkt.mf = True
            for x in range(num_of_pkt):
                r = min((x * size) + size, len(body))
                pkt.body = body[x * size:r]
                if x == num_of_pkt - 1:
                    pkt.mf = False
                interface.send_pkt(pkt)
        return

    def map(self, sender_ip, sender_port, pkt):
        if self.is_overload:  # we should use tuple
            real_tuple = (sender_ip, sender_port)
            if real_tuple not in self.map_acl_to_pool.keys():  # assign tuples
                start = ip_address(self.pool[0])
                end = ip_address(self.pool[-1])
                while start <= end:
                    if (str(start), '1111') not in self.map_acl_to_pool.values():
                        self.map_acl_to_pool[real_tuple] = (str(start), '1111')
                        self.map_acl_to_pool_time[(str(start), '1111')] = 20
                        break
                    if (str(start), '2222') not in self.map_acl_to_pool.values():
                        self.map_acl_to_pool[real_tuple] = (str(start), '2222')
                        self.map_acl_to_pool_time[(str(start), '2222')] = 20
                        break
                    if (str(start), '3333') not in self.map_acl_to_pool.values():
                        self.map_acl_to_pool[real_tuple] = (str(start), '3333')
                        self.map_acl_to_pool_time[(str(start), '3333')] = 20
                        break
                    if (str(start), '4444') not in self.map_acl_to_pool.values():
                        self.map_acl_to_pool[real_tuple] = (str(start), '4444')
                        self.map_acl_to_pool_time[(str(start), '4444')] = 20
                        break
                    start += 1
            if real_tuple in self.map_acl_to_pool.keys():
                self.connections[real_tuple].append(pkt.receiver)
                out_tuple = self.map_acl_to_pool[real_tuple]
                self.map_acl_to_pool_time[out_tuple] = 20
                pkt.sender = out_tuple[0]
                pkt.sender_port = out_tuple[1]
            else:  # no free ip
                code = '5'
                self.send_icmp(code, pkt)
                return None
        else:  # we should use ip only
            real_ip = sender_ip
            if real_ip not in self.map_acl_to_pool.keys():  # assign tuples
                start = ip_address(self.pool[0])
                end = ip_address(self.pool[-1])
                while start <= end:
                    if str(start) not in self.map_acl_to_pool.values():
                        self.map_acl_to_pool[real_ip] = str(start)
                        self.map_acl_to_pool_time[str(start)] = 20
                        break
                    start += 1
            if real_ip in self.map_acl_to_pool.keys():
                self.connections[real_ip].append(pkt.receiver)
                out_ip = self.map_acl_to_pool[real_ip]
                self.map_acl_to_pool_time[out_ip] = 20
                pkt.sender = out_ip
            else:  # no free ip
                code = '5'
                self.send_icmp(code, pkt)
                return None
        # print("map\n", pkt, "\n", self.map_acl_to_pool)
        return pkt

    def de_map(self, receiver, receiver_port, pkt):
        if self.is_overload:  # we should use tuple
            if (receiver, receiver_port) not in self.map_acl_to_pool.values():  # ip and src not mapped to anything
                code = '5'
                self.send_icmp(code, pkt)
                return None
            else:
                real_tuple = ''
                for k in self.map_acl_to_pool.keys():
                    if self.map_acl_to_pool[k] == (receiver, receiver_port):
                        real_tuple = k
                if self.is_res:
                    if pkt.sender not in self.connections[real_tuple]:
                        code = '5'
                        self.send_icmp(code, pkt)
                        return None
                    else:
                        pkt.receiver = real_tuple[0]
                        pkt.receiver_port = real_tuple[1]
                else:
                    pkt.receiver = real_tuple[0]
                    pkt.receiver_port = real_tuple[1]
        else:  # we should use ip only
            if receiver not in self.map_acl_to_pool.values():
                code = '5'
                self.send_icmp(code, pkt)
                return None
            else:
                real_ip = ''
                for k in self.map_acl_to_pool.keys():
                    if self.map_acl_to_pool[k] == receiver:
                        real_ip = k
                if self.is_res:
                    if pkt.sender not in self.connections[real_ip]:  # inside didn't start the conversation
                        code = '5'
                        self.send_icmp(code, pkt)
                        return None
                    else:
                        pkt.receiver = real_ip
                else:
                    pkt.receiver = real_ip
        # print("de_map\n", pkt, "\n", self.map_acl_to_pool)
        return pkt

    def update(self):
        self.my_timer -= 1
        for k in self.invalid_timer.keys():
            self.invalid_timer[k] -= 1
        for k in self.map_acl_to_pool_time.keys():
            self.map_acl_to_pool_time[k] -= 1
        for k in self.hold_timer.keys():
            self.hold_timer[k] -= 1

        if self.my_timer <= 0:
            self.send_advertise()
            # self.final_update()

        for k in self.invalid_timer.keys():
            if self.invalid_timer[k] < 0:
                interface = ''
                for i in self.interfaces.keys():
                    if self.interfaces[i].link is not None:
                        if self.interfaces[i].link.right.ip == k or self.interfaces[i].link.left.ip == k:
                            interface = i
                            break
                for d in self.dist.keys():
                    if self.dist[d][1] == interface and self.dist[d][0] != 0:
                        self.dist[d] = (16, interface)
                        # self.new_dist[d] = (16, interface)

        values = list()
        for v in self.map_acl_to_pool_time.keys():
            if self.map_acl_to_pool_time[v] <= 0:
                values.append(v)
        keys = list()
        for k in self.map_acl_to_pool.keys():
            if self.map_acl_to_pool[k] in values:
                keys.append(k)
        for k in keys:
            self.map_acl_to_pool.__delitem__(k)
            self.connections[k].clear()
        return

    # def final_update(self):
    #     self.dist.clear()
    #     self.dist = self.new_dist.copy()


class Interface:
    def __init__(self, ip, router):
        """
        :param ip: the ip of the interface
        :param router: the router it is connected to
        """
        self.ip = ip
        self.link = None
        self.router = router
        self.hub = None
        self.is_outside = False
        self.is_inside = False

    def connect(self, link):
        """
        :param link: Link or Hub
        """
        self.link = link

    def connect_hub(self, hub):
        self.hub = hub

    def connected(self, ip, is_router):
        """
        notify the router a new connection
        :param ip: other side ip
        """
        self.router.connected(ip, self.ip, is_router)
        pass

    def send_pkt(self, pkt):
        if self.link:
            # print("sending from interface:", self.ip, self.link.right.ip, self.link.left.ip)
            self.link.send(pkt, self.ip)
        elif self.hub:
            # print("sending from hub:", self.ip)
            self.hub.send(pkt, self.ip)

    def receive_pkt(self, pkt):
        if self.hub:
            s = False
            r = False
            for c in self.hub.connections:
                if c.ip == pkt.sender:
                    s = True
                if c.ip == pkt.receiver:
                    r = True
            if s and r:
                return
        self.router.receive_pkt(self.ip, pkt)
