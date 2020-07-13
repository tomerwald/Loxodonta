from loxodonta.analyzer import transport, network
from loxodonta.analyzer.fact import Connection


class UDP(network.IPProtocol):
    target_layer = 'udp'

    def analyze(self, packet):
        fact_output = list()
        source, destination = self._get_ip_entities(packet)
        fact_output.append(Connection(transport.Connections.UDPTraffic, source, destination))
        return fact_output
