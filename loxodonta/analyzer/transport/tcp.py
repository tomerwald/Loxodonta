from loxodonta.analyzer.protocol import ProtocolAnalyzer
from loxodonta.analyzer.fact import Entity, Connection
from loxodonta.analyzer import transport, network


class TCP(ProtocolAnalyzer):
    target_layer = 'tcp'

    @staticmethod
    def _is_syn_ack(packet):
        return int(packet.tcp.flags_syn) and int(packet.tcp.flags_ack)

    def analyze(self, packet):
        fact_output = list()
        source = Entity(network.Entities.IP, packet.ip.src)
        destination = Entity(network.Entities.IP, packet.ip.dst)
        fact_output.append(Connection(transport.Connections.TCPTraffic, source, destination))
        if self._is_syn_ack(packet):
            port = Entity(transport.Entities.TCP, packet.tcp.srcport)
            fact_output.append(Connection(transport.Connections.ListeningPort, source, port))
        return fact_output
