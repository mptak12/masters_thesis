import time
import warnings

from fwMgmt import *
from xmlApi import *
from tools import *

if __name__ == '__main__':
    # may be useful to hide information about making HTTPS requests without TLS certificate
    warnings.filterwarnings('ignore')

    print("Starting app...\n")

    # time measurement
    start_time = time.time()

    # get user credentials from external file credentials.txt and import to user_credentials: list
    userCr = CredentialInput("credentials.txt")
    user_credentials = userCr.get_list()
    if user_credentials is None:
        print("Error during retrieving credentials, exiting...")
        exit()

    # collect botnet report by executing a query through the firewall xml API
    logger = PythonLogCollector(user_credentials[0], user_credentials[1])
    logger.get_botnet_report()
    logger.parse_logs_xml()
    report = logger.get_report_df()  # botnet report saved to pandas.dataFrame

    # analyze botnet report
    ipFilter = IpFilter(report)
    ip_list = ipFilter.get_filtered_list()
    if ip_list is None:
        print("Host blocking is not necessary, because Botnet report is empty, exiting...\n")
        exit()

    # open new connection with firewall through pan-os-python
    fw11 = FirewallManagement(user_credentials[0], user_credentials[2], user_credentials[3])

    # check if Address Group "blocked hosts" exists and edit it
    if fw11.check_if_object_exists("blocked hosts"):
        fw11.edit_addr_group_blocked_hosts(ip_list)
        print("Updated Address Group 'blocked hosts'\n")
    else:
        fw11.add_group_blocked_hosts(ip_list)
        print("Created Address Group 'blocked hosts'\n")

    # check if proper security policies exist, otherwise add them
    for p in botnet_policies:
        if not fw11.check_if_policy_exists(p):
            fw11.add_policy(p)

    # calculate execution time
    end_time = time.time()
    time_without_commit = end_time - start_time

    # commit configuration if user presses 'y'
    key = input("Type 'y' to commit configuration ")
    commit_time = 0
    commit_result = ""  # this variable contains firewall output
    if key == "y":
        start_time = time.time()
        commit_result = fw11.commit_conf()
        end_time = time.time()
        commit_time = end_time - start_time

    print(f"\nModification time: {round(time_without_commit, 2)} s")
    print(f"Commit time: {round(commit_time, 2)} s\n")

    # print commit msg on screen
    if len(commit_result):
        print(f"Commit message: {commit_result}")
