import os
import time
from zapv2 import ZAPv2
from scan import Scanner
import pandas as pd
import xml.etree.ElementTree as Et


# ancora da testare

class HttpScanner:
    def __init__(self):
        scan = Scanner()
        self._hostname = scan.get_hostname()

        self.path_zap = "report_zap"

    def create(self):
        parent_dir = str(os.getcwd())
        is_exist = os.path.exists(self.path_zap)
        if is_exist is False:
            res = os.path.join(parent_dir, self.path_zap)
            os.makedirs(res)

    def run_zap_scan(self, apikey, ip, port, host_name):
        target = f'http://{ip}:{port}'
        zap = ZAPv2(apikey=apikey, proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
        print('Accessing target {}'.format(target))
        zap.urlopen(target)
        # Give the sites tree a chance to get updated
        time.sleep(2)

        print('Spidering target {}'.format(target))
        # The scan returns a scan id to support concurrent scanning
        scan_id = zap.spider.scan(target)
        while int(zap.spider.status(scan_id)) < 100:
            # Poll the status until it completes
            print('Spider progress %: {}'.format(zap.spider.status(scan_id)))
            time.sleep(1)

        print('Spider has completed!')

        while int(zap.pscan.records_to_scan) > 0:
            # Loop until the passive scan has finished
            print('Records to passive scan : ' + zap.pscan.records_to_scan)
            time.sleep(2)

        print('Passive Scan completed')

        print('Active Scanning target {}'.format(target))
        scan_id = zap.ascan.scan(target)
        while int(zap.ascan.status(scan_id)) < 100:
            # Loop until the scanner has finished
            print('Scan progress %: {}'.format(zap.ascan.status(scan_id)))
            time.sleep(5)

        print('Active Scan completed')

        # Report the results
        print('Hosts: {}'.format(', '.join(zap.core.hosts)))
        print('Alerts: ')

        # Report the results
        report_name = host_name + ".xml"
        report_path = os.path.join(self.path_zap, report_name)
        with open(report_path, 'w') as fHTML:
            fHTML.write(zap.core.xmlreport())

        print(f"ZAP report saved at {report_path}")

    def process_xml_folder(self):
        # create empty lists to store the extracted data
        sites = []
        alerts = []

        # process each XML file in the folder
        for filename in os.listdir(self.path_zap):
            if filename.endswith('.xml'):
                # parse the XML
                tree = Et.parse(os.path.join(self.path_zap, filename))
                root = tree.getroot()

                # extract site information
                for site in root.findall('.//site'):
                    site_name = site.get('name')
                    site_host = site.get('host')
                    site_port = site.get('port')
                    site_ssl = site.get('ssl')
                    sites.append([site_name, site_host, site_port, site_ssl])

                    # extract alert information
                    for alert in site.findall('.//alertitem'):
                        plugin_id = alert.find('pluginid').text
                        alert_ref = alert.find('alertRef').text
                        alert_name = alert.find('alert').text
                        alert_risk_code = alert.find('riskcode').text
                        alert_confidence = alert.find('confidence').text
                        alert_risk_desc = alert.find('riskdesc').text
                        alert_confidence_desc = alert.find('confidencedesc').text
                        alert_desc = alert.find('desc').text
                        alert_instances = alert.find('instances').text
                        alerts.append(
                            [plugin_id, alert_ref, alert_name, alert_risk_code, alert_confidence, alert_risk_desc,
                             alert_confidence_desc, alert_desc, alert_instances])

        # create a pandas DataFrame from the extracted data
        with pd.ExcelWriter('ReportOwasp.xlsx') as writer:
            df = pd.DataFrame(sites, columns=['name', 'host', 'port', 'ssl'])
            df.to_excel(writer, sheet_name='IP')
            df2 = pd.DataFrame(alerts,
                               columns=['pluginid', 'alertRef', 'alert', 'riskcode', 'confidence', 'riskdesc',
                                        'confidencedesc', 'desc', 'instances'])
            df2.to_excel(writer, sheet_name='Alerts')
