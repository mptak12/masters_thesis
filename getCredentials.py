
class CredentialsInput:
    credentials: list

    def __init__(self, filename: str):
        f = open(filename, "r")

        self.credentials = f.read().splitlines()
        f.close()

    def get_list(self):
        return self.credentials
