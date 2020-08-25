import functools

import tqdm

from loxodonta.logger import loxo_logger


class Analyzer:
    """
    this object is responsible for the digestion of network packets
    """

    def __init__(self, *args):
        """
        :param Protocol args: protocol analyzer objects of the desired layers to be analyzed
        """
        self.protocols = args

    @property
    def layer_subscriptions(self):
        subscriptions = {}
        for protocol_analyzer in self.protocols:
            subscriptions.setdefault(protocol_analyzer.target_layer, list())
            subscriptions[protocol_analyzer.target_layer].append(protocol_analyzer)
        return subscriptions

    def analyze_packet(self, packet):
        analyzers_to_run = list()
        for layer in packet.layers:
            if layer.layer_name in self.layer_subscriptions:
                analyzers_to_run += self.layer_subscriptions[layer.layer_name]
            else:
                loxo_logger.debug(f"Unselected layer: {layer.layer_name}")
        return functools.reduce(lambda x, y: x + y, [proto().analyze(packet) for proto in analyzers_to_run])

    def analyze_file_capture(self, capture):
        loxo_logger.info(f"Analyzing packets from capture")
        loxo_logger.info(f"Total analyzers count: {len(self.protocols)}")
        for packet in tqdm.tqdm(capture, unit="Packets"):
            yield self.analyze_packet(packet)
        yield []
