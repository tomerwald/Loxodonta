from loxodonta.analyzer import data_link, network
from loxodonta.analyzer.fact import Entity, Connection
from loxodonta.analyzer.protocol import Protocol


class ARP(Protocol):
    target_layer = 'arp'

    def analyze(self, packet):
        fact_output = list()
        if packet.arp.opcode == '1':
            src_mac = Entity(data_link.Entities.MAC, packet.eth.src)
            src_ip = Entity(network.Entities.IP, packet.arp.src_proto_ipv4)
            fact_output.append(Connection(data_link.Connections.ArpResolve, src_mac, src_ip))
        elif packet.arp.opcode == '2':
            src_mac = Entity(data_link.Entities.MAC, packet.eth.dst)
            src_ip = Entity(network.Entities.IP, packet.arp.dst_proto_ipv4)
            fact_output.append(Connection(data_link.Connections.ArpResolve, src_mac, src_ip))
        return fact_output
