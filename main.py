from fwMgmt import *
from xmlApi import *
from getCredentials import *

if __name__ == '__main__':
    # warnings.filterwarnings('ignore')

    # get user credentials
    userCr = CredentialsInput("input.txt")
    user_credentials = userCr.get_list()

    # collect botnet report
    logger = PythonLogCollector(user_credentials[0], user_credentials[1])
    logger.get_botnet_report()
    logger.parse_logs_xml()
    report = logger.get_botnet_report()

    # TODO: decide if rule change is needed

    ip_list = ["10.10.10.11", "192.168.10.1", "1.1.1.1"]

    fw11 = FirewallManagement(user_credentials[0], user_credentials[2], user_credentials[3])

    # check if Address Group "blocked hosts" exists and edit it
    if fw11.check_if_object_exists("blocked hosts"):
        fw11.edit_blocked_hosts(ip_list)
        print("Editing group blocked hosts")
    else:
        fw11.add_group_blocked_hosts(ip_list)
        print("Added group blocked hosts")

    # change security rules
    botnet_security_rule = Rule(name="BlockUsers",
                                description="Blocking IP addr from botnet log",
                                fromzone="any",
                                tozone="any",
                                source=['blocked hosts'],
                                destination=['blocked hosts'],
                                action=Actions.deny,
                                log_end=True,
                                uuid="1")

    if not fw11.check_if_policy_exists(botnet_security_rule):
        fw11.add_policy(botnet_security_rule)

    fw11.commit_conf()
