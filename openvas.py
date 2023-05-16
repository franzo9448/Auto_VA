import os


class Openvas:
    def __init__(self, username, password):
        self.path = "report_openvas"
        self.username = username
        self.password = password


    def create(self):
        parent_dir = str(os.getcwd())
        is_exist = os.path.exists(self.path)
        if is_exist is False:
            res = os.path.join(parent_dir, self.path)
            os.makedirs(res)

    def authenticate(self, gmp):
        gmp.authenticate(self.username, self.password)

    def get_path(self):
        return self.path
