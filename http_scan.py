import os
import time
from zapv2 import ZAPv2
from scan import Scanner
import requests
import xml.etree.ElementTree as Et
import xlsxwriter
from bs4 import BeautifulSoup


class HttpScanner:
    def __init__(self):
        scan = Scanner()
        self._hostname = scan.get_hostname()
        self.path_zap = "report_zap"
        self.solution = []
        self.summary = []
        self.reference = []
        self.link = []
        self.values = {}
        self.alert_ref = []
        self.sites = []
        self.alerts = []

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

        # The scan returns a scan id to support concurrent scanning
        scan_id = zap.spider.scan(target)
        while int(zap.spider.status(scan_id)) < 100:
            # Poll the status until it completes
            time.sleep(1)

        print('Spider has completed!')

        while int(zap.pscan.records_to_scan) > 0:
            # Loop until the passive scan has finished
            time.sleep(2)

        print('Passive Scan completed')

        print('Active Scanning target {}'.format(target))
        scan_id = zap.ascan.scan(target)
        while int(zap.ascan.status(scan_id)) < 100:
            # Loop until the scanner has finished
            time.sleep(5)

        print('Active Scan completed')

        # Report the results
        report_name = host_name + "_" + port + ".xml"
        report_path = os.path.join(self.path_zap, report_name)
        with open(report_path, 'w') as fHTML:
            fHTML.write(zap.core.xmlreport())

        print(f"ZAP report saved at {report_path}")

    def extract_values_from_html(self, html):
        soup = BeautifulSoup(html.text, 'html.parser')
        main_section = soup.select_one('div.wrapper.py-20 main.post-content')

        if main_section:
            values = {}

            summary_tag = main_section.select_one('div[data-attr="summary"]')
            values['summary'] = summary_tag.get_text(strip=True) if summary_tag else ""

            solution_tag = main_section.select_one('div[data-attr="solution"]')
            values['solution'] = solution_tag.get_text(strip=True) if solution_tag else ""

            references_tags = main_section.select('ul[data-attr="references"] a')
            values['references'] = [ref.get('href') for ref in references_tags] if references_tags else []

            code_link_tag = main_section.select_one('a[href]')
            values['code_link'] = code_link_tag.get('href') if code_link_tag else ""

            self.values = values

        return None

    def process_xml_folder(self):
        # create empty lists to store the extracted data
        sites = []
        alert_ref = []
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
                        alert_ref.append(alert.find('alertRef').text)
                        self.alert_ref = alert_ref
                        alert_name = alert.find('alert').text
                        alert_risk_code = alert.find('riskcode').text
                        alert_confidence = alert.find('confidence').text
                        alert_risk_desc = alert.find('riskdesc').text
                        alert_confidence_desc = alert.find('confidencedesc').text
                        alert_desc = alert.find('desc').text
                        alert_instances = alert.find('instances').text
                        alerts.append(
                            [site_host, alert_name, alert_risk_code, alert_confidence, alert_risk_desc,
                             alert_confidence_desc, alert_desc, alert_instances])
        self.alerts = alerts
        self.sites = sites

    def process_xml(self):
        workbook = xlsxwriter.Workbook("ReportOwasp.xlsx")
        workbook.set_properties({
            'title': "Report Owasp",
            'subject': 'Report Owasp',
            'category': 'report',
            'keywords': 'Owasp, report'})
        # ====================
        # FORMATTING
        # ====================

        # Define formatting styles
        format_table_titles = workbook.add_format({'font_name': 'Arial', 'font_size': 11,
                                                   'font_color': '#679695', 'bold': True,
                                                   'align': 'center', 'valign': 'vcenter',
                                                   'bg_color': '#679695'})
        format_table_cells = workbook.add_format({'font_name': 'Arial', 'font_size': 10,
                                                  'align': 'left', 'valign': 'top',
                                                  'text_wrap': 1})
        format_align_border = workbook.add_format({'font_name': 'Arial', 'font_size': 10,
                                                   'align': 'center', 'valign': 'top',
                                                   'text_wrap': 1})
        """
        Write the extracted information to an Excel file.
        """
        url = "https://www.zaproxy.org/docs/alerts/"
        worksheet_ip = workbook.add_worksheet("IP")
        headers_ip = ['Host', 'Nome', 'Port', 'SSL']
        for row, site in enumerate(self.sites):
            for col, value in enumerate(site):
                worksheet_ip.write(row + 1, col, value, format_table_cells)
        # Create table for 'IP' sheet
        num_rows = len(self.sites) + 1
        num_cols = len(headers_ip)
        ip_table_range = f'A1:{chr(ord("A") + num_cols - 1)}{num_rows + 1}'
        worksheet_ip.add_table(ip_table_range, {'columns': [{'header': header} for header in headers_ip],
                                                'header_row': True, 'autofilter': False,
                                                'style': 'Table Style Light 9'})

        # Set column widths for 'IP' sheet
        worksheet_ip.set_column(0, 0, 60)
        worksheet_ip.set_column(1, 1, 60)
        worksheet_ip.set_column(2, 2, 80)
        worksheet_ip.set_column(3, 3, 60)
        worksheet_ip.set_column(4, 4, 20)

        # Apply formatting to 'IP' sheet
        worksheet_ip.set_row(0, None, format_table_cells)
        worksheet_ip.set_column(0, num_cols - 1, None, format_table_cells)
        worksheet_ip.set_column(0, 0, None, format_align_border)
        worksheet_ip.set_column(num_cols - 1, num_cols - 1, None, format_align_border)

        # Write data to 'Alerts' sheet
        worksheet_alerts = workbook.add_worksheet("Alerts")
        headers_alerts = ['Host', 'Alert', 'Risk Code', 'Confidence', 'Risk Description', 'Confidence Description',
                          'Description', 'Instances', 'Alert Ref']

        for row, alert in enumerate(self.alerts):
            alert.append(self.alert_ref[row])  # Append corresponding alert_ref value
            for col, value in enumerate(alert):
                worksheet_alerts.write(row + 1, col, value, format_table_cells)
        # Create table for 'Alerts' sheet
        num_rows = len(self.alerts) + 1
        num_cols = len(headers_alerts)
        alerts_table_range = f'A1:{chr(ord("A") + num_cols - 1)}{num_rows + 1}'
        worksheet_alerts.add_table(alerts_table_range, {'columns': [{'header': header} for header in headers_alerts],
                                                        'header_row': True, 'autofilter': False,
                                                        'style': 'Table Style Light 9'})

        # Set column widths for 'Alerts' sheet
        worksheet_alerts.set_column(0, 0, 60)
        worksheet_alerts.set_column(1, 1, 60)
        worksheet_alerts.set_column(2, 2, 80)
        worksheet_alerts.set_column(3, 3, 60)
        worksheet_alerts.set_column(4, 4, 20)

        # Apply formatting to 'Alerts' sheet
        worksheet_alerts.set_row(0, None, format_table_cells)
        worksheet_alerts.set_column(0, num_cols - 1, None, format_table_cells)
        worksheet_alerts.set_column(0, 0, None, format_align_border)
        worksheet_alerts.set_column(num_cols - 1, num_cols - 1, None, format_align_border)

        # Write data to 'Desc' sheet
        worksheet_desc = workbook.add_worksheet("Desc")
        headers_desc = ['Summary', 'Solution', 'References', 'Code Link', 'Alert Ref']
        for col, header in enumerate(headers_desc):
            worksheet_desc.write(0, col, header, format_table_titles)

        for index, alert in enumerate(self.alert_ref):
            r = requests.get(url + alert + '/')
            self.extract_values_from_html(r)
            values = self.values

            summary = values['summary']
            solution = values['solution']
            references = values['references']
            code_link = values['code_link']

            worksheet_desc.write_string(index + 1, 0, summary, format_table_cells)
            worksheet_desc.write_string(index + 1, 1, solution, format_table_cells)
            worksheet_desc.write_string(index + 1, 2, ' '.join(references), format_table_cells)
            worksheet_desc.write_string(index + 1, 3, code_link, format_table_cells)
            worksheet_desc.write_string(index + 1, 4, alert, format_table_cells)  # Write alert_ref value

        # Create table for 'Desc' sheet
        num_rows = len(self.alert_ref) + 1
        num_cols = len(headers_desc)
        desc_table_range = f'A1:{chr(ord("A") + num_cols - 1)}{num_rows + 1}'
        worksheet_desc.add_table(desc_table_range, {'columns': [{'header': header} for header in headers_desc],
                                                    'header_row': True, 'autofilter': False,
                                                    'style': 'Table Style Light 9'})

        # Set column widths for 'Desc' sheet
        worksheet_desc.set_column(0, 0, 60)
        worksheet_desc.set_column(1, 1, 60)
        worksheet_desc.set_column(2, 2, 80)
        worksheet_desc.set_column(3, 3, 60)
        worksheet_desc.set_column(4, 4, 20)

        # Apply formatting to 'Desc' sheet
        worksheet_desc.set_row(0, None, format_table_cells)
        worksheet_desc.set_column(0, num_cols - 1, None, format_table_cells)
        worksheet_desc.set_column(0, 0, None, format_align_border)
        worksheet_desc.set_column(num_cols - 1, num_cols - 1, None, format_align_border)

        workbook.close()

    def get_path(self):
        return self.path_zap
