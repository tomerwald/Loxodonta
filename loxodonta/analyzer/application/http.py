from loxodonta.analyzer import network, application
from loxodonta.analyzer.fact import Entity, Connection


class HTTP(network.IPProtocol):
    target_layer = 'http'

    def _analyze_request(self, packet):
        out_facts = list()
        client, server = self._get_ip_entities(packet)
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

    def _analyze_response(self, packet):
        fact_output = list()
        server, _ = self._get_ip_entities(packet)
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
