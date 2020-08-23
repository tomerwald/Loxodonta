from loxodonta.analyzer import network, application
from loxodonta.analyzer.fact import Entity, Connection


class SSH(network.IPProtocol):
    target_layer = 'ssh'

    def analyze(self, packet):
        fact_output = list()
        source, destination = self._get_ip_entities(packet)
        if int(packet.ssh.direction) and hasattr(packet.ssh, "protocol"):
            client = Entity(application.Entities.SSHServer, packet.ssh.protocol)
            fact_output.append(Connection(application.Connections.ActiveService, source, client))
        elif hasattr(packet.ssh, "protocol"):
            client = Entity(application.Entities.SSHClient, packet.ssh.protocol)
            fact_output.append(Connection(application.Connections.ActiveService, source, client))
        fact_output.append(Connection(application.Connections.SSHConnection, source, destination))
        return fact_output
