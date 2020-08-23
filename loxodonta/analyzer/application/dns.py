from loxodonta.analyzer import network, application
from loxodonta.analyzer.fact import Entity, Connection


class DNS(network.IPProtocol):
    target_layer = 'dns'

    def analyze(self, packet):
        fact_output = list()
        if hasattr(packet.dns, "a"):
            server, _ = self._get_ip_entities(packet)
            dns_server = Entity(application.Entities.Service, "DNSServer")
            fact_output.append(Connection(application.Connections.ActiveService, server, dns_server))
            hostname = Entity(application.Entities.Hostname, packet.dns.qry_name)
            answer = Entity(network.Entities.IP, packet.dns.a)
            fact_output.append(Connection(application.Connections.ResolvedHostname, answer, hostname))
        return fact_output
