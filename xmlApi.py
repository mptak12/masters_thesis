import xml.etree.ElementTree as ET
import requests as requests
import pandas as pd


class PythonLogCollector:
    addr: str
    key: str
    xml_response = None
    botnetDf: pd.DataFrame()

    def __init__(self, fw_addr, key):
        self.addr = fw_addr
        self.key = key

    def get_botnet_report(self):
        request_url = "https://{}/api/?key={}&type=report&reporttype=predefined&reportname=botnet".format(self.addr, self.key)
        raw_response = requests.get(request_url, verify=False)
        self.xml_response = ET.fromstring(raw_response.content)

    def parse_logs_xml(self, test_xml=None):
        if test_xml:
            self.xml_response = test_xml
        data = []
        for result_element in self.xml_response.findall('.//result'):
            result_attributes = result_element.attrib

            # info kiedy wygenerowany i tp
            header = {'result_name': result_attributes.get('name'),
                        'start': result_attributes.get('start'),
                        'end': result_attributes.get('end'),
                        'generated_at': result_attributes.get('generated-at'),
                        'range': result_attributes.get('range')}

            for entry_element in result_element.findall('.//entry'):
                confidence = entry_element.find('confidence').text
                src = entry_element.find('src').text
                srcuser = entry_element.find('srcuser').text
                vsys = entry_element.find('vsys').text
                description = entry_element.find('description').text

                row_data = {'confidence': confidence,
                            'src': src,
                            'srcuser': srcuser,
                            'vsys': vsys,
                            'description': description}
                data.append(row_data.copy())

        df = pd.DataFrame(data)
        print(df)
        self.botnetDf = df

    def get_report_dataframe(self):
        return self.botnetDf
