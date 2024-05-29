from panos import firewall

# this is a step-by-step configuration script, which retrieves configuration used during tests
# it is impossible to create Dhcp Servers and Security Profiles via pan-os-python at the moment,
# so it should be configured manually via gui or console

# connect with device - type in credentials
fw = firewall.Firewall("< firewallManagementIP >", "< firewallLogin >", "< firewallPassword >")

# interfaces
from panos.network import EthernetInterface
eth1 = EthernetInterface(name="ethernet1/1",
                         mode="layer3",
                         enable_dhcp=True,
                         create_dhcp_default_route=True)
fw.add(eth1)

eth3 = EthernetInterface(name="ethernet1/3",
                         mode="layer3",
                         ip=("192.168.4.1/24")
                         )
fw.add(eth3)

eth4 = EthernetInterface(name="ethernet1/4",
                         mode="layer3",
                         ip=("192.168.5.1/24")
                         )
fw.add(eth4)
# create all 3 interfaces with one call
eth4.create_similar()

# there is no possibility to create Dhcp Server via pan-os-python, only DhcpRelay is available
# from panos.network import Dhcp
# dhcp_serv1 = Dhcp("ethernet1/5")
# fw.add(dhcp_serv1)
# dhcp_serv2 = Dhcp("ethernet1/4")
# fw.add(dhcp_serv2)
# dhcp_serv2.create_similar()

# zones
from panos.network import Zone
lan1 = Zone(name="Lan1",
            mode="layer3",
            interface="ethernet1/3")
fw.add(lan1)

lan2 = Zone(name="Lan2",
            mode="layer3",
            interface="ethernet1/4")
fw.add(lan2)

wan = Zone(name="WAN",
           mode="layer3",
           interface="ethernet1/1")
fw.add(wan)

# create all 3 zones with one call
wan.create_similar()

# virtual router
from panos.network import VirtualRouter, StaticRoute
def_static_r = StaticRoute(name="test",
                           destination="0.0.0.0/0",
                           nexthop_type="ip-address",
                           nexthop="<NEXT HOP IP ADDR>",
                           interface="ethernet1/5")

router = VirtualRouter(name="default",
                       interface=["ethernet1/1", "ethernet1/3", "ethernet1/4"],
                       )

# append children object
router.children.append(def_static_r)
fw.add(router)
router.create()

# Security Policies
# it is not possible to create Security PROFILES(spyware, antivirus, ...) via pan-os-python
from panos.policies import Rulebase, SecurityRule
internet_acc = SecurityRule(name="InternetAccess",
                            fromzone=["Lan1", "Lan2"],
                            tozone=["WAN"],
                            action="allow")

l1_to_l2 = SecurityRule(name="Allow LAN1 to LAN2",
                        fromzone="Lan1",
                        tozone="Lan2",
                        action="allow")

l2_to_l1 = SecurityRule(name="Allow LAN2 to LAN1",
                        fromzone="Lan2",
                        tozone="Lan1",
                        action="allow")

# get parent object and update it (firewall -> rulebase -> securityRule)
rb = Rulebase()
fw.add(rb)

for rule in [internet_acc, l1_to_l2, l2_to_l1]:
    rb.add(rule)
internet_acc.create_similar()

# to commit configuration
# msg = fw.commit(cmd=True)