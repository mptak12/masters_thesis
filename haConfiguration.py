from panos import firewall
from panos.network import EthernetInterface
from panos.ha import HighAvailability, HA1, HA2


# this is a step-by-step configuration script, which set up configuration of HA cluster
# used during several tests
# IP addresses shown here are exemplary and should be adjusted to own purposes


# Connect with first device - type in credentials
fw = firewall.Firewall("< firewallManagementIP >", "< firewallLogin >", "< firewallPassword >")

# Configure first device of HA cluster

# Configure interfaces eth7, eth8 to act as HA interfaces
eth7 = EthernetInterface(name="ethernet1/7", mode="ha")
fw.add(eth7)
eth7.create()

eth8 = EthernetInterface(name="ethernet1/8", mode="ha")
fw.add(eth8)
eth8.create()

# Set the HA mode and group ID
ha_config = HighAvailability(enabled="True", group_id="4", mode="active-passive", peer_ip="169.254.1.2", state_sync="True")
fw.add(ha_config)
ha_config.create()

# Configure HA1 and HA2 interfaces' setup
ha_int1 = HA1(ip_address="169.254.1.1", netmask="255.255.255.252", port="ethernet1/7")
ha_config.add(ha_int1)
ha_int1.create()

ha_int2 = HA2(ip_address="169.254.2.1", netmask="255.255.255.252", port="ethernet1/8")
ha_config.add(ha_int2)
ha_int2.create()

# Commit configuration
msg = fw.commit(cmd=True)

# After this step configuration should be applied to second device - firewall peer
# Adjust proper interfaces and IP addresses during peer configuration

# Apply following configuration only after both devices are set up
# Set internal pan-os-python config and synchronize
fw.set_ha_peers(firewall.Firewall("< peerManagementIP >", "< peerLogin >", "< peerPassword >"))
fw.refresh_ha_active()
if not fw.config_synced():
    fw.synchronize_config()
