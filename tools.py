import pandas as pd


class CredentialInput:
    """
    this class allows user to read credentials from .txt file
    input should be a file with 4 lines of text divided by enter
    file should contain elements in following order:
    < firewallManagementIP >
    < xmlApiKey >
    < firewallLogin >
    < firewallPassword >
    """
    filename: str

    def __init__(self, filename: str):
        self.filename = filename

    def get_list(self):
        """
        this method reads provided .txt file and extracts credentials to list of 4 elements
        :return: list with 4 elements
        """

        try:
            f = open(self.filename, "r")
        except FileNotFoundError:
            print(f"Not found file {self.filename}, exiting...")
            return

        credentials = f.read().splitlines()
        f.close()
        if len(credentials) != 4:
            print("Invalid credential file format")
            return

        return credentials


class IpFilter:
    """
    this class contains algorithm of filtering IP addresses from botnet report
    input: pandas.DataFrame with botnet report
    IP addresses with 'confidence' level > 3 will be added to block list
    IP addresses with 'confidence' level == 3 will be added to block list if matched to specific keywords
    IP addresses with 'confidence' level < 3 will trigger a warning message on the screen
    """
    input_df: pd.DataFrame
    # IP addresses with 'confidence' level == 3 will be added to block list if description matched following keywords:
    keywords = ["malicious URL", "executable", "registered", "unknown", "TCP", "UDP", "malware"]

    def __init__(self, data: pd.DataFrame):
        self.input_df = data

    def get_filtered_list(self):
        """
        this method verifies received botnet report, classifies IP addresses to block and prints log message
        :return: list of IP addresses, which are perceived as botnet and their connection should be blocked
        """

        if self.input_df.empty:
            return None

        # extract IPs from botnet report with confidence > 3 to be blocked
        block_list = self.input_df.query('confidence > 3').get('src').unique().tolist()
        if len(block_list) > 0:
            print("Following IPs will be blocked immediately, because they exceeded confidence level 3:")
            print(block_list, "\n")

        # extract IPs prepare IPs with confidence == 3 and make decision based on keywords
        warn_str = self.input_df.query('confidence == 3')
        warn_str = warn_str[['src', 'description']]

        # prepare string with keywords to match
        regex_str = '|'.join(self.keywords)

        # verify report description matching with prepared string
        warn_str = warn_str[warn_str["description"].str.contains(regex_str)]

        # extract filtered IPs to list
        keyword_ips = warn_str.get('src').unique().tolist()
        if len(keyword_ips) > 0:
            print(f"Following IPs will be blocked because they matched keywords:\n({self.keywords}):")
            print(keyword_ips, "\n")
            block_list.extend(keyword_ips)

        # prepare IPs with confidence < 3 to show warning message on the screen
        to_log = self.input_df.query('confidence < 3')
        if not to_log.empty:
            # extract only source IP and description to string, format
            to_log = to_log[['src', 'description']]
            log_str = to_log.to_string(header=False,
                                       index=False,
                                       index_names=False)
            log_str = log_str.replace("\n ", "\n")
            print("Please note the activity of the following hosts listed on confidence levels 1 or 2:")
            print(log_str, "\n")

        return block_list
