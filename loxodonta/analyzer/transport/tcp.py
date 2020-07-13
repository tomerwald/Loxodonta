from loxodonta.analyzer.protocol import Protocol
from loxodonta.analyzer.fact import Entity, Connection
from loxodonta.analyzer import transport, network


class TCP(Protocol):
    target_layer = 'tcp'

    @staticmethod
    def _is_syn_ack(packet):
        return int(packet.tcp.flags_syn) and int(packet.tcp.flags_ack)

    def analyze(self, packet):
        fact_output = list()
        if hasattr(packet, "ip"):
            source = Entity(network.Entities.IP, packet.ip.src)
            destination = Entity(network.Entities.IP, packet.ip.dst)
        elif hasattr(packet, "ipv6"):
            source = Entity(network.Entities.IPv6, packet.ipv6.src)
            destination = Entity(network.Entities.IPv6, packet.ipv6.dst)
        else:
            raise AttributeError("No valid network layer found")
        fact_output.append(Connection(transport.Connections.TCPTraffic, source, destination, port=[packet.tcp.dstport]))
        if self._is_syn_ack(packet):
            port = Entity(transport.Entities.Port, packet.tcp.srcport)
            fact_output.append(Connection(transport.Connections.ListeningPort, source, port))
        return fact_output
