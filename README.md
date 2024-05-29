This repository contains application files that enable users to automatically communicate with Palo Alto Networks NGFW, download and analyze botnet activity reports and based on the results, automatically block selected IP addresses classified as part of a botnet.

Application consists of 4 files:  
main.py - main script responsible for the runtime operations of the application,  
xmlApi.py - contains the declaration of a class that utilizes the XML API of a firewall device to download botnet reports,  
fwMgmt.py - declares a class based on the 'pan-os-python' module created by Palo Alto Networks Inc. (https://github.com/PaloAltoNetworks/pan-os-python), which is designed for modifying firewall configuration,  
tools.py - declarations of class responsible for retrieving user passwords and class that sorts IP addresses according to specified rules for subsequent blocking.  

Additionally, there are two supplementary files:  
initialConfig.py - allows user to retrieve firewall configuration same as in the study,  
haConfiguration.py - allows user to configure HA cluster same as in the study.

This code is part of a Master's Thesis titled: Remote Monitoring and Configuration of Palo Alto Networks PA-440 Firewalls Using Python.  
Author: inż. Michał Ptak
