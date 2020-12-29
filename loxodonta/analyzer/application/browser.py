from loxodonta.analyzer import network, application
from loxodonta.analyzer.fact import Entity, Connection


class Browser(network.IPProtocol):
    target_layer = 'browser'

    def analyze(self, packet):
        fact_output = list()
        source_ip = Entity(network.Entities.IP, packet.ip.addr)
        host = Entity(application.Entities.Hostname, packet.browser.server)
        domain = Entity(application.Entities.Domain, packet.nbdgm.destination_name[:-4])
        fact_output.append(Connection(application.Connections.DomainComputer, host, domain))
        fact_output.append(Connection(application.Connections.ResolvedHostname, host, source_ip))
        if hasattr(packet.browser, 'server_type_server'):
            if packet.browser.server_type_sql:
                service = Entity(application.Entities.Service, "SQLServer")
                fact_output.append(Connection(application.Connections.ActiveService, source_ip, service))
            if packet.browser.server_type_domain_controller:
                fact_output.append(Connection(application.Connections.DomainController, host, domain))
            if packet.browser.server_type_print:
                service = Entity(application.Entities.Service, "PrintServer")
                fact_output.append(Connection(application.Connections.ActiveService, source_ip, service))
        return fact_output
