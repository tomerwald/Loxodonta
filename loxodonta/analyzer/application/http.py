from loxodonta.analyzer.protocol import Protocol
from loxodonta.analyzer.fact import Entity, Connection
from loxodonta.analyzer import transport, network, application


class HTTP(Protocol):
    target_layer = 'http'

    @staticmethod
    def _analyze_request(packet):
        out_facts = list()
        if hasattr(packet, "ip"):
            client = Entity(network.Entities.IP, packet.ip.src)
            server = Entity(network.Entities.IP, packet.ip.dst)
        elif hasattr(packet, "ipv6"):
            client = Entity(network.Entities.IPv6, packet.ipv6.src)
            server = Entity(network.Entities.IPv6, packet.ipv6.dst)
        else:
            raise AttributeError("No valid network layer found")
        if server.entity_id not in str(packet.http.host):
            server_host = Entity(application.Entities.hostname, packet.http.host)
            out_facts.append(Connection(application.Connections.ResolvedHostname, server, server_host))
        if hasattr(packet.http, "user_agent"):
            user_agent = Entity(application.Entities.UserAgent, packet.http.user_agent)
        else:
            user_agent = Entity(application.Entities.UserAgent, "Unknown user agent")
        out_facts.append(Connection(application.Connections.HTTPUserAgent, client, user_agent))
        out_facts.append(Connection(application.Connections.HTTP, user_agent, server, uri=[packet.http.request_uri]))
        return out_facts

    @staticmethod
    def _analyze_response(packet):
        fact_output = list()
        if hasattr(packet, "ip"):
            server = Entity(network.Entities.IP, packet.ip.src)
        elif hasattr(packet, "ipv6"):
            server = Entity(network.Entities.IPv6, packet.ipv6.src)
        else:
            raise AttributeError("No valid network layer found")
        if hasattr(packet.http, "server"):
            webservice = Entity(application.Entities.WebServer, packet.http.server)
            fact_output.append(Connection(application.Connections.ActiveService, server, webservice))
        return fact_output

    def analyze(self, packet):
        fact_output = list()
        if hasattr(packet.http, "response_code"):
            fact_output += self._analyze_response(packet)
        else:
            fact_output += self._analyze_request(packet)
        return fact_output
