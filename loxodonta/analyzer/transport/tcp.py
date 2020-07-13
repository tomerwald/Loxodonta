from loxodonta.analyzer import transport, network
from loxodonta.analyzer.fact import Entity, Connection


class TCP(network.IPProtocol):
    target_layer = 'tcp'

    @staticmethod
    def _is_syn_ack(packet):
        return int(packet.tcp.flags_syn) and int(packet.tcp.flags_ack)

    def analyze(self, packet):
        fact_output = list()
        source, destination = self._get_ip_entities(packet)
        fact_output.append(Connection(transport.Connections.TCPTraffic, source, destination, port=[packet.tcp.dstport]))
        if self._is_syn_ack(packet):
            port = Entity(transport.Entities.Port, packet.tcp.srcport)
            fact_output.append(Connection(transport.Connections.ListeningPort, source, port))
        return fact_output
