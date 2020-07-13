from loxodonta.analyzer.protocol import Protocol
from loxodonta.analyzer.fact import Entity, Connection
from loxodonta.analyzer import transport, network


class UDP(Protocol):
    target_layer = 'udp'

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
        fact_output.append(Connection(transport.Connections.UDPTraffic, source, destination))
        return fact_output
