import os

import argparse
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmpv224 import Gmp, AliveTest, FilterType
from gvm.transforms import EtreeTransform
from scan import Scanner
from openvas import Openvas
from http_scan import HttpScanner
from gvm.xml import pretty_print
import sys
from argparse import Namespace
from base64 import b64decode
from pathlib import Path

connection = UnixSocketConnection()
transform = EtreeTransform()


def validate_input_file(filepath):
    if not os.path.exists(filepath):
        raise ValueError("Input file does not exist")
    with open(filepath) as f:
        for line in f:
            if not line.strip():
                continue
            if len(line.split()) != 2:
                raise ValueError(f"Invalid input format: {line}")
            hostname, ip = line.strip().split()
            if not hostname or not ip:
                raise ValueError(f"Invalid input format: {line}")


def get_filter_id(gmp):
    response = gmp.get_filters()
    filters = response.findall('filter')
    for o_filter in filters:
        name = o_filter.find('name').text
        if name == "see_all":
            return o_filter.get('id')


def get_scanner_id(gmp):
    response = gmp.get_scanners()
    scanner_lists = response.findall('scanner')
    for o_scanner in scanner_lists:
        name = o_scanner.find('name').text
        if name == "Full and fast":
            return o_scanner.get('id')


def get_config_id(gmp):
    response = gmp.get_scan_configs()
    config_lists = response.findall('config')
    for config in config_lists:
        name = config.find('name').text
        if name == "Consider Alive":
            return config.get('id')


def get_report_format_id_xml(gmp):
    response = gmp.get_report_formats()
    format_lists = response.findall('report_format')
    for forma in format_lists:
        name = forma.find('name').text
        if name == "Anonymous XML":
            return forma.get('id')


def get_report_format_id_pdf(gmp):
    response = gmp.get_report_formats()
    format_lists = response.findall('report_format')
    for forma in format_lists:
        name = forma.find('name').text
        if name == "PDF":
            return forma.get('id')


def get_port_list_id(gmp, host):
    response = gmp.get_port_lists()
    port_lists = response.findall('port_list')
    for port in port_lists:
        name = port.find('name').text
        if name == host:
            return port.get('id')


def get_target_id(gmp, host):
    response = gmp.get_targets()
    target_list = response.findall('target')
    for target in target_list:
        name = target.find('name').text
        if name == host:
            return target.get('id')


def get_report_id(gmp, host):
    response = gmp.get_tasks()
    for task in response.findall('task'):
         if task.find('name').text == host:
            last_report = task.find('last_report/report')
            if last_report is not None:
                return last_report.attrib['id']


def create_filter(gmp):
    name = "see_all"
    filter_type = FilterType.SCAN_CONFIG
    term = "apply_overrides=0 levels=hmlg min_qod=0"
    gmp.create_filter(name=name, filter_type=filter_type, term=term)


def create_port_list(gmp, host_name, open_ports):
    port_range = "T:" + ','.join(open_ports)
    gmp.create_port_list(name=host_name, port_range=port_range)
    print("Port list created")


def create_openvas_target(gmp, host, ip):
    port_id = get_port_list_id(gmp, host)
    gmp.create_target(name=host, hosts=[ip], alive_test=AliveTest.CONSIDER_ALIVE, port_list_id=port_id)
    print("target created")


def create_openvas_task(gmp, host):
    config_id = get_config_id(gmp)
    target_id = get_target_id(gmp, host)
    scanner_id = get_scanner_id(gmp)
    gmp.create_task(name=host, config_id=config_id, target_id=target_id, scanner_id=scanner_id)
    print("task created")


def save_xml(gmp, host_name, directory):
    report_id = get_report_id(gmp, host_name)
    filter_id = get_filter_id(gmp)
    xml_id = get_report_format_id_xml(gmp)  # Funzione per ottenere l'ID del formato XML
    response = gmp.get_report(
        report_id=report_id, filter_string=filter_id, report_format_id=xml_id
    )
    report_element = response.find("report")
    # get the full content of the report element
    content = report_element.find("report_format").tail
    if not content:
        print(
            "Requested report is empty. Either the report does not contain any "
            " results or the necessary tools for creating the report are "
            "not installed.",
            file=sys.stderr,
        )
        sys.exit(1)
    # convert content to 8-bit ASCII bytes
    binary_base64_encoded_xml = content.encode("ascii")
    # decode base64
    binary_xml = b64decode(binary_base64_encoded_xml)
    # write to file and support ~ in filename path
    xml_path = Path(directory) / f"{host_name}.xml"
    xml_path.expanduser().write_bytes(binary_xml)

def save_pdf(gmp, host_name, pdf_directory):
    report_id = get_report_id(gmp, host_name)
    filter_id = get_filter_id(gmp)
    pdf_id = get_report_format_id_pdf(gmp)
    response = gmp.get_report(
        report_id=report_id, filter_string=filter_id, report_format_id=pdf_id
    )
    report_element = response.find("report")
    # get the full content of the report element
    content = report_element.find("report_format").tail
    if not content:
        print(
            "Requested report is empty. Either the report does not contain any "
            " results or the necessary tools for creating the report are "
            "not installed.",
            file=sys.stderr,
        )
        sys.exit(1)
    # convert content to 8-bit ASCII bytes
    binary_base64_encoded_pdf = content.encode("ascii")
    # decode base64
    binary_pdf = b64decode(binary_base64_encoded_pdf)
    # write to file and support ~ in filename path
    pdf_path = Path(pdf_directory) / host_name
    pdf_path.write_bytes(binary_pdf)


def scanner(filepath, username, password):
    my_scanner = Scanner()
    my_openvas = Openvas(username, password)
    my_zap = HttpScanner()
    my_scanner.create()
    my_openvas.create()
    my_zap.create()
    apikey = "9203935709"
    with Gmp(connection, transform=transform) as gmp:
        my_openvas.authenticate(gmp)
        create_filter(gmp)
        with open(filepath) as f:
            for line in f:
                hostname, ip = line.strip().split()
                my_scanner.nmap_scan_file(hostname, ip)
                my_scanner.parse_info(ip)
                open_port = my_scanner.get_open_ports()
                http_ports = my_scanner.get_http_ports()
                if len(open_port) != 0:
                    create_port_list(gmp, hostname, open_port)
                    create_openvas_target(gmp, hostname, ip)
                    create_openvas_task(gmp, hostname)
                if len(http_ports) != 0:
                    for port in http_ports:
                        my_zap.run_zap_scan(apikey, ip, port, hostname)


def report(filepath, username, password):
    my_openvas = Openvas(username, password)
    openvas_dir_xml = my_openvas.get_path_xml()
    openvas_dir_pdf = my_openvas.get_path_pdf()
    my_zap = HttpScanner()
    with Gmp(connection, transform=transform) as gmp:
        my_openvas.authenticate(gmp)
        with open(filepath) as f:
            validate_input_file(filepath)
            for line in f:
                hostname, ip = line.strip().split()
                save_pdf(gmp, hostname, openvas_dir_pdf)
                save_xml(gmp,hostname,openvas_dir_xml)
                my_zap.process_xml_folder()


def main():
    parser = argparse.ArgumentParser(description='Tool per lo scanning e la creazione di report')
    subparsers = parser.add_subparsers(dest='command', required=True, help='Comandi disponibili')

    parser_scanner = subparsers.add_parser('scanner', help='Scansione dei server e invio delle informazioni ad OpenVAS')
    parser_scanner.add_argument('filepath', type=str, help='Path del file contenente gli indirizzi IP e gli hostname')
    parser_scanner.add_argument('username', type=str, help='Username per l\'autenticazione su OpenVAS')
    parser_scanner.add_argument('password', type=str, help='Password per l\'autenticazione su OpenVAS')

    parser_report = subparsers.add_parser('report', help='Creazione di report degli host scansionati')
    parser_report.add_argument('filepath', type=str, help='Path del file contenente gli indirizzi IP e gli hostname')
    parser_report.add_argument('username', type=str, help='Username per l\'autenticazione su OpenVAS')
    parser_report.add_argument('password', type=str, help='Password per l\'autenticazione su OpenVAS')

    args = parser.parse_args()

    if args.command == 'scanner':
        scanner(args.filepath, args.username, args.password)
    elif args.command == 'report':
        report(args.filepath, args.username, args.password)


if __name__ == '__main__':
    main()
