from abc import abstractmethod

from pyshark.packet.packet import Packet


class Protocol:
    target_layer = None

    def __init__(self):
        pass

    @abstractmethod
    def analyze(self, packet):
        """
        analyze a packet and return newly learned facts
        :param Packet packet: A packet object
        :return list: a list of new facts
        """
        pass
