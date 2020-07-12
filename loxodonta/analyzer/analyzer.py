import pyshark


class Analyzer:
    def __init__(self, *args):
        self.protocols = args

    @property
    def layer_subscriptions(self):
        subscriptions = {}
        for protocol_analyzer in self.protocols:
            subscriptions[protocol_analyzer.target_layer].setdefault(list())
            subscriptions[protocol_analyzer.target_layer].append(protocol_analyzer)
        return subscriptions

    def analyze_packet(self, packet):
        pass

    def analyze_file_capture(self, capture):
        for packet in capture:
            self.analyze_packet(packet)
