from loxodonta.analyzer import data_link, network
from loxodonta.analyzer.fact import Entity, Connection
from loxodonta.analyzer.protocol import Protocol


class VLAN(Protocol):
    target_layer = 'vlan'

    def analyze(self, packet):
        fact_output = list()
        src_mac = Entity(data_link.Entities.MAC, packet.eth.src)
        vlan_id = Entity(data_link.Entities.Vlan, packet.vlan.id)
        fact_output.append(Connection(data_link.Connections.VlanMember, src_mac, vlan_id))
        return fact_output
