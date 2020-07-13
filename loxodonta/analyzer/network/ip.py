from abc import abstractmethod

from pyshark.packet.packet import Packet

from loxodonta.analyzer import network
from loxodonta.analyzer.fact import Entity
from loxodonta.analyzer.protocol import Protocol


class IPProtocol(Protocol):
    target_layer = None

    @staticmethod
    def _get_ip_entities(packet):
        if hasattr(packet, "ip"):
            return Entity(network.Entities.IP, packet.ip.src), Entity(network.Entities.IP, packet.ip.dst)
        elif hasattr(packet, "ipv6"):
            return Entity(network.Entities.IPv6, packet.ipv6.src), Entity(network.Entities.IPv6, packet.ipv6.dst)
        else:
            raise AttributeError("No valid network layer found")

    @abstractmethod
    def analyze(self, packet):
        """
        analyze a packet and return newly learned facts
        :param Packet packet: A packet object
        :return list: a list of new facts
        """
        pass
