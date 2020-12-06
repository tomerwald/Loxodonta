from loxodonta.analyzer import data_link, network
from loxodonta.analyzer.fact import Entity, Connection
from loxodonta.analyzer.protocol import Protocol


class CDP(Protocol):
    target_layer = 'cdp'

    def get_roles(self, packet, device):
        roles = list()
        if int(packet.cdp.capabilities_mac_relay):
            roles.append(Entity(data_link.Entities.Role, "Relay"))
        if int(packet.cdp.capabilities_cvta):
            roles.append(Entity(data_link.Entities.Role, "CVTA"))
        if int(packet.cdp.capabilities_switch):
            roles.append(Entity(data_link.Entities.Role, "Switch"))
        if int(packet.cdp.capabilities_router):
            roles.append(Entity(data_link.Entities.Role, "Router"))
        if int(packet.cdp.capabilities_voip_phone):
            roles.append(Entity(data_link.Entities.Role, "VoipPhone"))
        return [Connection(data_link.Connections.CDPAnnouncement, device, r) for r in roles]

    def analyze(self, packet):
        fact_output = list()
        port = Entity(data_link.Entities.PortID, packet.cdp.portid)
        platform = Entity(data_link.Entities.Platform, packet.cdp.platform)
        software_version = Entity(data_link.Entities.SoftwareVersion, packet.cdp.software_version)
        device_id = Entity(data_link.Entities.DeviceID, packet.cdp.deviceid)
        port_ip = Entity(network.Entities.IP, packet.cdp.nrgyz_ip_address)
        src_mac = Entity(data_link.Entities.MAC, packet.eth.src)
        fact_output.append(Connection(data_link.Connections.CDPAnnouncement, src_mac, port))
        fact_output.append(Connection(data_link.Connections.CDPAnnouncement, src_mac, port_ip))
        fact_output.append(Connection(data_link.Connections.CDPAnnouncement, device_id, port))
        fact_output.append(Connection(data_link.Connections.CDPAnnouncement, device_id, platform))
        fact_output.append(Connection(data_link.Connections.CDPAnnouncement, device_id, software_version))
        fact_output += self.get_roles(packet, device_id)
        return fact_output
