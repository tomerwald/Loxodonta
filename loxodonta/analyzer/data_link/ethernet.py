from loxodonta.analyzer.protocol import ProtocolAnalyzer
from loxodonta.analyzer.fact import Entity, Connection
from loxodonta.analyzer import data_link


class Ethernet(ProtocolAnalyzer):
    target_layer = 'eth'

    def analyze(self, packet):
        fact_output = list()
        side_a_mac = Entity(entity_type=data_link.Entities.MAC, entity_id=str(packet.eth.src))
        side_b_mac = Entity(entity_type=data_link.Entities.MAC, entity_id=str(packet.eth.dst))
        fact_output.append(Connection(data_link.Connections.EthTraffic, side_a_mac, side_b_mac))
        if hasattr(packet.eth, "src_oui_resolved"):
            side_a_manuf = Entity(entity_type=data_link.Entities.Manufacturer,
                                  entity_id=str(packet.eth.src_oui_resolved))
            fact_output.append(Connection(data_link.Connections.ManufResolve, side_a_mac, side_a_manuf))
        if hasattr(packet.eth, "dst_oui_resolved"):
            side_b_manuf = Entity(entity_type=data_link.Entities.Manufacturer,
                                  entity_id=str(packet.eth.dst_oui_resolved))
            fact_output.append(Connection(data_link.Connections.ManufResolve, side_a_mac, side_b_manuf))
        return fact_output
