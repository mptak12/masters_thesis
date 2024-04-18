import xml.etree.ElementTree as ET
import requests as requests
import pandas as pd


class PythonLogCollector:
    """
    this class is responsible for connecting with firewall via xmlApi, downloading existing Botnet log as XML
    and parse it into pandas dataframe object
    input should be a set of parameters: < firewallManagementIP >, < xmlApiKey >
    """

    addr: str
    key: str
    xml_response = None
    botnetDf: pd.DataFrame()

    def __init__(self, fw_addr, key):
        self.addr = fw_addr
        self.key = key

    def get_botnet_report(self):
        """
        this method establishes connection with firewall via requests library and downloads Botnet report
        then if response is proper, xml object is saved
        :return: void
        """
        request_url = "https://{}/api/?key={}&type=report&reporttype=predefined&reportname=botnet".format(self.addr, self.key)
        try:
            raw_response = requests.get(request_url, verify=False)
        except Exception as err:
            print(f"{type(err).__name__} was raised, exiting...")
            exit()

        if raw_response.ok is False:
            print(raw_response.reason)
            exit()
        self.xml_response = ET.fromstring(raw_response.content)

    def parse_logs_xml(self, test_xml=None):
        """
        this method parses xml logs to pandas library dataFrame object
        :param test_xml:
        :return: pd.DataFrame
        """
        # allows inserting prepared xml for testing purpose
        if test_xml:
            self.xml_response = test_xml

        # create new structure to hold entries
        data = []
        # iterate through xml structure
        for result_element in self.xml_response.findall('.//result'):
            for entry_element in result_element.findall('.//entry'):
                # extract data from each entry
                confidence = int(entry_element.find('confidence').text)
                src = entry_element.find('src').text
                srcuser = entry_element.find('srcuser').text
                vsys = entry_element.find('vsys').text
                description = entry_element.find('description').text

                # save extracted data to dictionary and append it to new list
                row_data = {'confidence': confidence,
                            'src': src,
                            'srcuser': srcuser,
                            'vsys': vsys,
                            'description': description}
                data.append(row_data.copy())

        # export existing list into DataFrame
        self.botnetDf = pd.DataFrame(data)

    def get_report_df(self):
        """
        this method returns prepared earlier dataFrame, based on Botnet report
        :return: pandas.DataFrame
        """
        return self.botnetDf
