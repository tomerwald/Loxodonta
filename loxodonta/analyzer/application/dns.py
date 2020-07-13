from loxodonta.analyzer.protocol import Protocol
from loxodonta.analyzer.fact import Entity, Connection
from loxodonta.analyzer import transport, network, application


class DNS(Protocol):
    target_layer = 'dns'

    def analyze(self, packet):
        fact_output = list()
        if hasattr(packet.dns, "a"):
            if hasattr(packet, "ip"):
                server = Entity(network.Entities.IP, packet.ip.src)
            elif hasattr(packet, "ipv6"):
                server = Entity(network.Entities.IPv6, packet.ipv6.src)
            else:
                raise AttributeError("No valid network layer found")
            dns_server = Entity(application.Entities.Service, "DNSServer")
            fact_output.append(Connection(application.Connections.ActiveService, server, dns_server))
            hostname = Entity(application.Entities.hostname, packet.dns.cname)
            answer = Entity(network.Entities.IP, packet.dns.a)
            fact_output.append(Connection(application.Connections.ResolvedHostname, answer, hostname))
        return fact_output
