from panos import firewall, objects, policies
from dataclasses import dataclass
from enum import Enum


# additional dataclass to describe policy actions
@dataclass
class Actions(Enum):
    deny = 1
    allow = 2
    drop = 3


# additional dataclass to describe Security Policy
@dataclass
class SecurityPolicy:
    name: str
    description: str
    fromzone: str
    tozone: str
    source: list
    destination: list
    service: list
    action: Actions
    log_end: bool
    uuid: str

    def return_dict(self):
        """
        method which creates dictionary of Security Policy prepared to be inserted as policies.SecurityRule() argument
        :return: dictionary with Security Policy
        """
        return dict(name=self.name, description=self.description, fromzone=self.fromzone, tozone=self.tozone,
                    source=self.source, destination=self.destination, service=self.service, action=self.action.name,
                    log_end=self.log_end)


# security policy which blocks traffic from excluded hosts to WAN
botnet_policy_out = SecurityPolicy(name="BlockUsersOut",
                                   description="[Botnet] Blocking traffic from excluded hosts to WAN",
                                   fromzone="any",
                                   tozone="any",
                                   source=["blocked hosts"],
                                   destination=["any"],
                                   service=["any"],
                                   action=Actions.deny,
                                   log_end=True,
                                   uuid="1")

# security policy which blocks traffic from WAN to excluded hosts
botnet_policy_in = SecurityPolicy(name="BlockUsersIn",
                                  description="[Botnet] Blocking traffic from WAN to excluded hosts",
                                  fromzone="any",
                                  tozone="any",
                                  source=["any"],
                                  destination=["blocked hosts"],
                                  service=["any"],
                                  action=Actions.deny,
                                  log_end=True,
                                  uuid="1")

botnet_policies = [botnet_policy_in, botnet_policy_out]


class FirewallManagement:
    """
    this class encloses pan-os-python methods and is responsible for connecting to firewall, managing policies,
    managing objects and committing configuration
    input should be a set of parameters: < firewallManagementIP >, < firewallLogin >, < firewallPassword >
    """
    def __init__(self, hostname, api_username, api_password):
        self.fw = firewall.Firewall(hostname, api_username, api_password)

    def add_policy(self, input_policy: SecurityPolicy):
        """
        this method allows user to create Security Policy
        input should be a SecurityPolicy dataclass
        :param input_policy:
        :return: void
        """

        # security policies are attached to policies.Rulebase in PANOS
        # create our own Rulebase, attach it to the firewall object
        # then use that to update only the security policies
        base = policies.Rulebase()
        self.fw.add(base)

        print("Creating Security Policy '{}'\n".format(input_policy.name))
        # creating new policies.SecurityRule object based on passed argument 'input_policy'
        new_rule = policies.SecurityRule(**input_policy.return_dict())
        # adding new rule to policies.Rulebase object
        base.add(new_rule)
        new_rule.create()

        # move newly created Security Rule to first place in firewall list
        new_rule.move(location="top", update=True)

    def check_if_policy_exists(self, new_sec_rule: SecurityPolicy):
        """
        this method checks if Security Policy (passed as argument) exists on firewall
        :param new_sec_rule: SecurityPolity dataclass object
        :return: True - policy exists, False otherwise
        """

        base = policies.Rulebase()
        self.fw.add(base)

        # downloading all Security Rules from existing configuration on firewall
        current_policies = policies.SecurityRule.refreshall(base)
        for rule in current_policies:
            if rule.name == new_sec_rule.name:
                print('Security Policy "{}" already exists'.format(new_sec_rule.name))
                return True
        print("Security Policy '{}' doesn't exist".format(new_sec_rule.name))
        return False

    def check_if_object_exists(self, name):
        """
        this method checks if Address Group (with name passed as parameter) exists on firewall
        :param name: name of object to verify
        :return: True - Address Group exists, False - otherwise
        """

        # download addr groups configuration into local device
        curr_addr_groups = objects.AddressGroup.refreshall(self.fw, add=True)
        for obj in curr_addr_groups:
            if obj.name == name:
                print("Address Group '{}' already exists".format(name))
                return True
        print("Address Group '{}' doesn't exist".format(name))
        return False

    def add_group_blocked_hosts(self, addr_tab: list):
        """
        this method creates new Address Objects based on list of IP addresses (passed as argument)
        then objects are added to new Address Group
        :param addr_tab: list of IP addresses
        :return: void
        """

        # create new IPs(objects.AddressObject) to configuration (on local device)
        addr_objects = [objects.AddressObject(f"blocked_{addr}", f"{addr}") for addr in addr_tab]
        self.fw.extend(addr_objects)

        # create new Address Group (on local device)
        grp = objects.AddressGroup("blocked hosts", addr_objects)
        self.fw.add(grp)

        # new method to improve performance: bulk adding (on firewall)
        # we can bulk create all the address objects.  This is accomplished by
        # invoking `create_similar()` on any of the address objects in our tree,
        # turning what would have been all individual API calls with single Address Object
        # and condensing it into a single API call.
        addr_objects[0].create_similar()

        # create new Address Group (on firewall)
        grp.create()

    def edit_addr_group_blocked_hosts(self, ip_list: list):
        """
        this method refreshes Address Group 'blocked hosts' created intentionally in this script with new IP addresses
        :param ip_list: list of ip addresses
        :return: void
        """
        # refresh list of Address Objects from firewall to local device
        objects.AddressObject.refreshall(self.fw, add=True)

        # prepare space for new objects
        new_addr_objects = []

        for ip in ip_list:
            # check if IP figures on list, add it if not
            if self.fw.find(f"blocked_{ip}", objects.AddressObject) is None:
                new_addr = objects.AddressObject(f"blocked_{ip}", f"{ip}")
                new_addr_objects.append(new_addr)
                self.fw.add(new_addr)

        # create new IP addresses on firewall
        new_addr_objects[0].create_similar()

        # extend objects list in Address Group
        objects.AddressGroup.refreshall(self.fw, add=True)
        edited_addr_group = self.fw.find(f"blocked hosts", objects.AddressGroup)

        # add new Address Objects to existing Address Group
        for addr_object in new_addr_objects:
            edited_addr_group.static_value.append(addr_object.name)

        edited_addr_group.create()

    def commit_conf(self):
        """
        # this method is responsible for committing new configuration and receiving log
        :return: firewall response after commit
        """
        print("Performing commit...")
        res = self.fw.commit(sync=True)
        print("Committing Done!")
        return res
