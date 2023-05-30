import os


class Openvas:
    def __init__(self, username, password):
        self.path_pdf = "report_openvas_pdf"
        self.path_xml = "report_openvas_xml"
        self.username = username
        self.password = password

    def create(self):
        parent_dir = str(os.getcwd())
        is_exist = os.path.exists(self.path_pdf)
        if is_exist is False:
            res = os.path.join(parent_dir, self.path_pdf)
            os.makedirs(res)
        parent_dir = str(os.getcwd())
        is_exist = os.path.exists(self.path_xml)
        if is_exist is False:
            res = os.path.join(parent_dir, self.path_xml)
            os.makedirs(res)

    def authenticate(self, gmp):
        gmp.authenticate(self.username, self.password)

    def get_path_xml(self):
        return self.path_xml

    def get_path_pdf(self):
        return self.path_pdf
