import pandas as pd


class CredentialsInput:
    credentials: list

    def __init__(self, filename: str):
        f = open(filename, "r")

        self.credentials = f.read().splitlines()
        f.close()

    def get_list(self):
        return self.credentials


class IpFilter:
    input_df: pd.DataFrame
    keywords = ["malicious URL", "executable", "registered", "unknown", "TCP", "UDP"]

    def __init__(self, data: pd.DataFrame):
        self.input_df = data

    def get_filtered_list(self):
        if self.input_df is None:
            return None
        block_list = self.input_df.query('confidence > 3').get('src').unique().tolist()

        warning_s = self.input_df.query('confidence == 3')
        warning_s = warning_s[['src', 'description']]
        regex_str = '|'.join(self.keywords)
        warning_s = warning_s[warning_s["description"].str.contains(regex_str)]
        block_list.extend(warning_s.get('src').unique().tolist())

        # print(f"Hosts selected to block {block_list}")

        to_log = self.input_df.query('confidence == 2')
        if not to_log.empty:
            to_log = to_log[['src', 'description']]
            log_str = to_log.to_string(header=False,
                                       index=False,
                                       index_names=False).split('\n')
            if log_str is not None:
                print("Please note the activity of the following hosts. They are listed on confidence level 2")
                print(log_str)

        return block_list