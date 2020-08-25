from loxodonta.analyzer import network, application
from loxodonta.analyzer.fact import Entity, Connection


class SMB(network.IPProtocol):
    target_layer = 'smb2'

    def _analyze_setup_packet(self, packet):
        if int(packet.smb2.flags_response) == 1:
            return self._analyze_negotiate_response(packet)
        else:
            return self._analyze_negotiate_request(packet)

    def _analyze_negotiate_response(self, packet):
        fact_output = list()
        source, destination = self._get_ip_entities(packet)
        if hasattr(packet.smb2, "ntlmssp_challenge_target_name"):
            build_number = Entity(application.Entities.BuildNumber, str(packet.smb2.ntlmssp_version_build_number))
            hostname = Entity(application.Entities.Hostname, str(packet.smb2.ntlmssp_challenge_target_name))
            domain = Entity(application.Entities.Domain, str(packet.smb2.ntlmssp_challenge_target_info_dns_domain_name))
            fact_output.append(Connection(application.Connections.ResolvedHostname, source, hostname))
            fact_output.append(Connection(application.Connections.ComputerInfo, hostname, build_number))
            if domain.entity_id != hostname.entity_id:
                fact_output.append(Connection(application.Connections.DomainComputer, domain, build_number))
        return fact_output

    def _analyze_negotiate_request(self, packet):
        fact_output = list()
        source, destination = self._get_ip_entities(packet)
        if hasattr(packet.smb2, "ntlmssp_auth_username"):
            build_number = Entity(application.Entities.BuildNumber, str(packet.smb2.ntlmssp_version_build_number))
            hostname = Entity(application.Entities.Hostname, str(packet.smb2.ntlmssp_auth_hostname))
            target_hostname = Entity(application.Entities.Hostname,
                                     str(packet.smb2.ntlmssp_ntlmv2_response_dns_computer_name))
            user = Entity(application.Entities.User, str(packet.smb2.ntlmssp_auth_username))
            domain = Entity(application.Entities.Domain, str(packet.smb2.ntlmssp_auth_domain))
            if domain.entity_id == "MicrosoftAccount":
                fact_output.append(Connection(application.Connections.LocalUser, target_hostname, user))
            else:
                fact_output.append(Connection(application.Connections.DomainUser, domain, user))
            hostname_connection = Connection(application.Connections.ResolvedHostname, source, hostname)
            build_connection = Connection(application.Connections.ComputerInfo, hostname, build_number)
            fact_output.append(hostname_connection)
            fact_output.append(build_connection)
        return fact_output

    def analyze_tree_packet(self, packet):
        if not int(packet.smb2.flags_response):
            source, destination = self._get_ip_entities(packet)
            share = str(packet.smb2.tree).split("\\", 3)[-1]
            return [Connection(application.Connections.SMB, source, destination, shares=[share])]
        return list()

    def analyze(self, packet):
        fact_output = list()
        int(packet.smb2.flags_response)
        if int(packet.smb2.cmd) == 1:
            fact_output += self._analyze_setup_packet(packet)
        elif int(packet.smb2.cmd) == 3:
            fact_output += self.analyze_tree_packet(packet)
        else:
            source, destination = self._get_ip_entities(packet)
            fact_output.append(Connection(application.Connections.SMB, source, destination))

        return fact_output
