import os
import nmap3
from json2html import json2html


class Scanner:
    def __init__(self):
        self.nm = nmap3.Nmap()
        self._open_ports = []
        self._http_ports = []
        self._output = {}
        self.nm_type = ""
        self._hostname = ""
        self.path = "report_nmap"

    def create(self):
        parent_dir = str(os.getcwd())
        is_exist = os.path.exists(self.path)
        if is_exist is False:
            res = os.path.join(parent_dir, self.path)
            os.makedirs(res)

    def nmap_scan_file(self, hostname, ip):
        output_file = f"{hostname}.html"
        output = self.nm.nmap_version_detection(ip, args="-Pn")
        self._output = output
        html = json2html.convert(json=output)
        try:
            with open('report_nmap/' + str(output_file), 'w') as o:
                o.write(html)
                print("Ho stampato il report")
        except FileNotFoundError:
            print("The 'report' directory does not exist")
        self._hostname = hostname

    def parse_info(self, ip):
        # recupero i dati di nmap
        data = self._output
        # dato l'indirizzo ip recupero la lista delle porte aperte
        spec_data = data[ip]["ports"]
        ports = []
        http_ports = []
        # nel range della lista itero
        for i in range(0, len(spec_data)):
            spec = spec_data[i]
            # recupero il numero della porta aperta
            ports.append(spec["portid"])
            # controllo i lservizio presente
            if spec["service"]["name"] == ("http" or "https"):
                http_ports.append(spec["portid"])
        # salvo nelle liste
        self._open_ports = ports
        self._http_ports = http_ports

    def get_open_ports(self):
        return self._open_ports

    def get_hostname(self):
        return self._hostname

    def get_http_ports(self):
        return self._open_ports
