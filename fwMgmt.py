from panos import firewall, objects, policies
from dataclasses import dataclass
from enum import Enum


@dataclass
class Actions(Enum):
    deny = 1
    allow = 2
    drop = 3


@dataclass
class AddressObject:
    name: str
    value: str

    def return_dict(self):
        return dict(name=self.name, value=self.value)


@dataclass
class AddressGroup:
    name: str
    static_value: str
    dynamic_value: str
    description: str
    tag: str

    def return_dict(self):
        return dict(name=self.name, static_value=self.static_value, dynamic_value=self.dynamic_value,
                    description=self.description, tag=self.tag)


@dataclass
class Rule:
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
        return dict(name=self.name, description=self.description, fromzone=self.fromzone, tozone=self.tozone,
                    source=self.source, destination=self.destination, service=self.service, action=self.action.name, log_end=self.log_end)


class FirewallManagement:
    def __init__(self, hostname, api_username, api_password):
        self.fw = firewall.Firewall(hostname, api_username, api_password)

    def add_policy(self, input_policy: Rule):
        # create our unnamed Rulebase object
        base = policies.Rulebase()
        # attach to firewall object
        self.fw.add(base)

        # if not is_present:
        print('Adding policy: {}'.format(input_policy.name))
        new_rule = policies.SecurityRule(**input_policy.return_dict())
        base.add(new_rule)
        new_rule.create()

        new_rule.move(location="top", update=True)
        print("Done!")

    def check_if_policy_exists(self, new_sec_rule: Rule):
        base = policies.Rulebase()
        self.fw.add(base)
        current_policies = policies.SecurityRule.refreshall(base)
        print("Found security rules: {}".format(len(current_policies)))
        for rule in current_policies:
            if rule.name == new_sec_rule.name:
                print('Rule "{}" already exists'.format(new_sec_rule.name))
                return True
        return False

    def add_group_blocked_hosts(self, addr_tab: list):
        # add new IPs
        addr_objects = [objects.AddressObject(f"blocked_{addr}", f"{addr}") for addr in addr_tab]
        self.fw.extend(addr_objects)

        grp = objects.AddressGroup("blocked hosts", addr_objects)
        self.fw.add(grp)

        for obj in self.fw.findall(objects.AddressObject):
            obj.create()

        grp.create()
        print("Created new Address Group")

    def check_if_object_exists(self, name):
        curr_addr_groups = objects.AddressGroup.refreshall(self.fw, add=True)
        for obj in curr_addr_groups:
            if obj.name == name:
                print('Address Group "{}" already exists'.format(name))
                return True
        return False

    def edit_blocked_hosts(self, ip_list: list):
        # add new address objects if not exist
        objects.AddressObject.refreshall(self.fw, add=True)
        new_addr_objects = []

        for ip in ip_list:
            if self.fw.find(f"blocked_{ip}", objects.AddressObject) is None:
                new_addr = objects.AddressObject(f"blocked_{ip}", f"{ip}")
                new_addr_objects.append(new_addr)
                self.fw.add(new_addr)
                new_addr.create()

        # extend objects list in address group
        objects.AddressGroup.refreshall(self.fw, add=True)
        edited_addr_group = self.fw.find(f"blocked hosts", objects.AddressGroup)

        for addr_object in new_addr_objects:
            edited_addr_group.static_value.append(addr_object.name)

        edited_addr_group.apply()

    def commit_conf(self):
        print("Performing commit...")
        res = self.fw.commit(sync=True)
        print("Committing Done! {}".format(res))
