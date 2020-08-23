import re

from loxodonta.analyzer import data_link
from loxodonta.analyzer.fact import Entity, Connection
from loxodonta.analyzer.protocol import Protocol

MAC_BLACK_LIST = ["01:00:5e[:\d\w]+", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"]


class Ethernet(Protocol):
    target_layer = 'eth'

    @staticmethod
    def _is_mac_in_blacklist(mac):
        return any([re.match(exp, mac) for exp in MAC_BLACK_LIST])

    def analyze(self, packet):
        fact_output = list()
        if self._is_mac_in_blacklist(str(packet.eth.dst)) or self._is_mac_in_blacklist(str(packet.eth.src)):
            return fact_output
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
            fact_output.append(Connection(data_link.Connections.ManufResolve, side_b_mac, side_b_manuf))
        return fact_output
