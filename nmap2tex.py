#! /usr/bin/python3

__version__ = '0.1'
__author__ = 'Daylam Tayari'

# Imports:

import re
import argparse
import json
import requests
from os.path import exists
from xml.dom import minidom
from collections import OrderedDict

# Global Variables and Constants:

SERVICES_URL = "https://git.tayari.gg/tayari/nmap2tex/-/raw/master/services.json"
TEMPLATE_URL = "https://git.tayari.gg/tayari/nmap2tex/-/raw/master/template.tex"
nmap_file = ''
latex_file = ''
users_file = ''
template_file = ''
services_file = ''
vuln_file = ''
hosts = []
users = []
user_seperator = ''
services = OrderedDict([])

# Object Classes:


class Host:
    # Host object class which contains all of the values and child objects of a particular network host.
    def __init__(self, ip, os):
        self.ip = ip
        self.os = os
        self.hostname = 'Unknown'
        self.domainname = 'Unknown'
        self.ports = []
        self._port_id = 0
        self.vulns = []
        self._vuln_id = 0
        self.vuln_host = False
        return

    def get_service(self, port_id):
        # Gets the service of a particular port.
        return self.ports[port_id].get_service()

    def get_port_service(self, _port):
        # Gets the services for all of the ports.
        for p in self.ports:
            if p.port == _port:
                return p.get_service()
        return

    def get_port_output(self, port_id):
        return self.ports[port_id].port + '/' + self.ports[
            port_id].protocol.upper()

    def ports_open(self):
        # Checks if the host has any open ports.
        if len(self.ports) > 0:
            return True
        else:
            return False

    def has_vulns(self):
        # Checks if the host has any vulnerabilities.
        if len(self.vulns) > 0:
            return True
        else:
            return False

    def add_port(self, port, protocol):
        new_port = Port(port, protocol)
        self.ports.append(new_port)
        self._port_id += 1
        return (self._port_id - 1)

    def add_service(self, port_id, service_name):
        self.ports[port_id].service = Service(service_name)
        return

    def add_serviceProduct(self, port_id, product):
        self.ports[port_id].service.product = product
        return

    def add_serviceVersion(self, port_id, version):
        self.ports[port_id].service.version = version
        return

    def add_vuln(self, cve, cvss, port):
        new_vuln = Vuln(cve, cvss, port)
        if self._vuln_id == 0 or float(cvss) > float(
                self.vulns[self._vuln_id - 1].cvss):
            self.vulns.append(new_vuln)
            self._vuln_id += 1
            return (self._vuln_id - 1)
        else:
            for i in range(len(self.vulns)):
                if float(cvss) <= float(self.vulns[i].cvss):
                    self.vulns.insert(i, new_vuln)
                    self._vuln_id += 1
                    return i

    def vuln_status(self):
        # Overall vulnerability status of the host with any high or critical CVEs causing a red rating.
        if len(self.vulns) == 0:
            return 'Green'
        for v in self.vulns:
            if float(v.cvss) >= 7.0:
                return 'Red'
            elif float(v.cvss) > 0.0:
                return 'Yellow'
            else:
                return 'Green'


class Port:
    # Port object which contains the information and children classes of a port.
    def __init__(self, port, protocol):
        self.port = port
        self.protocol = protocol
        self.service = None
        return

    def get_service(self):
        # Get the service running on the particular port.
        _output = ''
        if self.service is None:
            return 'Unknown'
        elif self.service.product == '':
            _output += self.service.name
        else:
            _output += self.service.product
        if self.service.version != '':
            _output += ' v' + self.service.version
        return _output


class Service:
    # Service object which contains the information about the service that corresponds to a particular port.
    def __init__(self, name):
        self.name = name
        self.product = ''
        self.version = ''
        return


class Vuln:
    # Vulnerability object which contains information about the vulnerability.
    def __init__(self, cve, cvss, port):
        self.cve = cve
        self.cvss = cvss
        self.port = port
        return


class User:
    # User object containing nformation about a particular user.
    def __init__(self, name, super):
        self.super = super
        self.name = name
        return


# Services Handling:


def parse_services():
    # Retrieve all the services from the file and place them into an ordered dictionary allowing the order of the JSON file to be retained.
    json_services = read_file(services_file)
    global services
    services = json.JSONDecoder(
        object_pairs_hook=OrderedDict).decode(json_services)
    return


def update_services():
    print('Updating services...')
    new_services = requests.get(SERVICES_URL).content
    open('services.json', 'wb').write(new_services)
    print('Updated services!')
    return


def handle_services():
    parse_services()
    return


# XML Handling:


def xml_handling(file):
    return minidom.parse(file)


def parse_names(host, script):
    if script.getElementsByTagName("elem") != []:
        elem = script.getElementsByTagName("elem")
        for e in elem:
            if e.getAttribute("key") == 'NetBIOS_Computer_Name':
                host.hostname = e.firstChild.data
            if e.getAttribute("key") == 'NetBIOS_Domain_Name':
                host.domainname = e.firstChild.data
    return


def parse_vulns(host, tables, port):
    for t in range(1, len(tables)):
        elems = tables[t].getElementsByTagName("elem")
        cve = False
        cveid = ''
        cvss = ''
        for e in elems:
            if e.getAttribute("key") == "type" and e.firstChild.data == "cve":
                cve = True
            elif e.getAttribute("key") == "cvss":
                cvss = e.firstChild.data
            elif e.getAttribute("key") == "id":
                cveid = e.firstChild.data
            if cve:
                host.add_vuln(cveid, cvss, port.getAttribute("portid"))
    return


def rename_services(serv):
    # Rename services if the corresponding human readable name is provided in the services file.
    for s in services:
        if s in serv:
            return services.get(s)
    return serv


def parse_service(host, port_id, serv):
    host.add_service(port_id, rename_services(serv.getAttribute("name")))
    if serv.getAttribute("product") != '':
        host.add_serviceProduct(port_id,
                                rename_services(serv.getAttribute("product")))
    if serv.getAttribute("version") != '':
        vers = re.search(r'^([0-9][\.0-9a-z]*)|[\ _]([0-9][\.0-9]*)',
                         serv.getAttribute("version"))
        if vers is not None and vers.group(1) is not None:
            vers = vers.group(1)
        elif vers is not None and vers.group(2) is not None:
            vers = vers.group(2)
        else:
            vers = ''
        host.add_serviceVersion(port_id, vers)
    return


def parse_host(host):
    # Parses a host retrieving information about it and storing it into the corresponding host object.
    ip = host.getElementsByTagName("address")[0].getAttribute("addr")
    if host.getElementsByTagName("os") == []:
        opSys = {}
    else:
        opSys = host.getElementsByTagName("os")[0].getElementsByTagName(
            "osmatch")
    if len(opSys) == 0:
        opSys = 'Unknown'
    else:
        opSys = opSys[0].getAttribute("name")
        if "Microsoft" in opSys:
            opSys = opSys[10:]
    hst = Host(ip, opSys)
    # Parse ports:
    if host.getElementsByTagName("ports") == []:
        portInfo = []
    else:
        portInfo = host.getElementsByTagName("ports")[0].getElementsByTagName(
            "port")
    for port in portInfo:
        port_id = hst.add_port(port.getAttribute("portid"),
                               port.getAttribute("protocol"))
        if port.getElementsByTagName("service") == []:
            hst.add_service(port_id, 'Unknown')
        else:
            parse_service(hst, port_id,
                          port.getElementsByTagName("service")[0])
        # Check for PC name if available:
        if port.getElementsByTagName("script") != []:
            parse_names(hst, port.getElementsByTagName("script")[0])
        # Check for and add vulnerabilities:
        if not port.getElementsByTagName("script") == []:
            tables = port.getElementsByTagName(
                "script")[0].getElementsByTagName("table")
            if tables != []:
                parse_vulns(hst, tables, port)
    global hosts
    hosts.append(hst)
    return hst


# Nmap File Handling:


def nmap_output():
    hosts_title()
    start_hosts()
    for h in hosts:
        if not h.vuln_host:
            add_host(h)
    end_hosts()
    return


def nmap_handling():
    # Does the handling of the main Nmap scan file.
    nmap_scan = xml_handling(nmap_file)
    host_xml = nmap_scan.getElementsByTagName("host")
    for h in host_xml:
        parse_host(h)
    nmap_output()
    return


# Vulnerability File Handling:


def vuln_handling():
    # Handles vulnerabilities.
    vulns_title()
    start_vulns()
    vuln_hosts = hosts
    if args.vuln:
        vuln_xml = xml_handling(vuln_file)
        vuln_hosts = vuln_xml.getElementsByTagName("host")
        for h in vuln_hosts:
            hst = parse_host(h)
            for host in hosts:
                if host.ip == hst.ip:
                    # Remove duplicate hosts.
                    hosts.pop()
                    host.vuln_host = True
                else:
                    hst.vuln_host = True
    else:
        for h in hosts:
            h.vuln_host = True
    for h in hosts:
        if h.vuln_host:
            add_vulns(h)
    return


# Users File Handling:


def user_is_super(username):
    # Checks if a user is delmited as a superuser.
    if re.match(r"[(\[{*\'\"]+[A-Za-z0-9]*[)\]}*\'\"]+", username) != None:
        return True
    return False


def get_users():
    # Retrieves all the users from the given users file.
    users_separators = ['\n', '\t', ',', '.', ':', ';', '/', '\\', '-', '`']
    usernames = []
    global user_seperator
    with open(users_file) as file:
        data = file.read()
        if user_seperator == '':
            for s in users_separators:
                if data.find(s) != -1:
                    user_seperator = s
        usernames = data.split(user_seperator)
    file.close()
    if usernames[-1] == '':
        usernames.pop()
    for u in usernames:
        if user_is_super(u):
            users.append(
                User(
                    re.search(r'[(\[{*\'\"]+([A-Za-z0-9_-]*)[)\]}*\'\"]+',
                              u).group(1), True))
        else:
            users.append(User(u, False))
    return


def admin_handling(user):
    # If a user is an admin, bold their name in the user list.
    if user.super:
        return "\\bfseries{" + user.name + "}"
    else:
        return user.name


def users_output():
    # This handles the output of users ensuring that they appear in a 6 row grid.
    if len(users) % 6 == 0:
        for i in range(0, len(users), 6):
            add_users(admin_handling(users[i]), admin_handling(users[i + 1]),
                      admin_handling(users[i + 2]),
                      admin_handling(users[i + 3]),
                      admin_handling(users[i + 4]),
                      admin_handling(users[i + 5]))
    else:
        diff = len(users) % 6
        for i in range(0, len(users) + diff, 6):
            if i + 5 > (len(users) - 1):
                lim = len(users) - i - 1
                lastUsers = []
                for j in range(1, 7):
                    if j > lim:
                        lastUsers.append(User('', False))
                    else:
                        lastUsers.append(users[i + j])
                add_users(admin_handling(lastUsers[0]),
                          admin_handling(lastUsers[1]),
                          admin_handling(lastUsers[2]),
                          admin_handling(lastUsers[3]),
                          admin_handling(lastUsers[4]),
                          admin_handling(lastUsers[5]))
            else:
                add_users(admin_handling(users[i]),
                          admin_handling(users[i + 1]),
                          admin_handling(users[i + 2]),
                          admin_handling(users[i + 3]),
                          admin_handling(users[i + 4]),
                          admin_handling(users[i + 5]))
    return


def user_handling():
    users_title()
    start_users()
    get_users()
    users_output()
    end_users()
    return


# File Handling:


def create_file():
    file = open(latex_file, "w")
    # Allows us to also wipe the file if it already contains something.
    file.write("")
    file.close()
    return


def append_file(content):
    file = open(latex_file, "a")
    file.write(content)
    file.close()
    return


def read_file(file):
    f = open(file, "r")
    content = f.read()
    f.close()
    return content


# LaTeX Handling:


def update_template():
    print('Updating template...')
    new_template = requests.get(TEMPLATE_URL).content
    open('template.tex', 'wb').write(new_template)
    print('Updated template!')
    return


def create_tex():
    content = read_file("template.tex")
    create_file()
    append_file(content)
    return


def hosts_title():
    append_file('\n' + r"\section*{Network Inventory:}" + '\n')
    return


def start_hosts():
    append_file('\n' + r"\hosttable{")
    return


def add_host(host):
    append_file('\n\t' + r"\host{%s}{%s}{%s}{" %
                (host.hostname, host.ip, host.os))
    if not host.ports_open():
        append_file('\n\t\t' + r"\portserv{None}{None}")
    else:
        for i in range(len(host.ports)):
            append_file('\n\t\t' + r"\portserv{%s}{%s}" %
                        (host.get_port_output(i), host.ports[i].get_service()))
    append_file("\n\t}")
    return


def end_hosts():
    append_file("\n}")
    return


def users_title():
    append_file('\n' + r"\section*{Users:}" + '\n')
    return


def start_users():
    append_file('\n' + r"\usertble{")
    return


def add_users(user1, user2, user3, user4, user5, user6):
    append_file('\n\t' + r"\user{%s}{%s}{%s}{%s}{%s}{%s}" %
                (user1, user2, user3, user4, user5, user6))
    return


def end_users():
    append_file("\n}")
    return


def vulns_title():
    append_file('\n' + r"\section*{Vulnerability Report}" + '\n')
    return


def start_vulns():
    append_file('\n')
    return


def add_vulns(host):
    append_file('\n' + r"\systemvuln{%s}{%s}{%s}{" %
                (host.hostname, host.ip, host.vuln_status()))
    if not host.has_vulns():
        append_file('\n\t' + r"\vuln{None}{0.0}")
    else:
        for v in range(len(host.vulns)):
            append_file('\n\t' + r"\vuln{%s: %s}{%s}" %
                        (host.get_port_service(host.vulns[v].port),
                         host.vulns[v].cve, host.vulns[v].cvss))
    append_file('\n}')
    return


def end_file():
    append_file('\n\n' + r"\end{document}")
    return


# Core Program Handling:


def vulns_pres():
    for h in hosts:
        if h.has_vulns():
            return True
    else:
        return False


def main():
    # Create and initiate LaTeX file:
    create_tex()
    # Handle services:
    handle_services()
    # Handle Nmap scan:
    nmap_handling()
    # Handle vulnerabilities:
    if args.vuln_report or args.vuln:
        vuln_handling()
    # Handle users:
    if args.users:
        user_handling()
    end_file()
    return


# Input Handling:


def exist_verifier(file, name):
    if not exists(file):
        update = input('\nThe ' + name + ' file at ' + eval(name + '_file') +
                       ' cannot be found.' +
                       '\nDo you wish to download the latest version of the ' +
                       name + ' file? [Y/n] ')
        if update.lower() == 'y':
            eval('update_' + name + '()')
            return
        else:
            quit('\nNot updating ' + name + ' file.\nExiting...')


# Initalise Parser:
parser = argparse.ArgumentParser(prog='Nmap2Tex',
                                 description='''
        Nmap2Tex allows you to automatically create a LaTeX document
         presenting all of the information from the provided Nmap scans.
        ''',
                                 add_help=False)
parser._positionals.title = 'Mandatory Arguments:'
parser._optionals.title = 'Optional Arguments:'
# Arguments:
parser.add_argument("Nmap", help="Nmap XML file")
parser.add_argument("Output", help="Output LaTeX file")
parser.add_argument("-u", "--users", help="File containing a list of users")
parser.add_argument(
    "-us",
    "--user-seperator",
    help="Custom input for character that seperates users in the users file")
parser.add_argument("-t",
                    "--template",
                    default="template.tex",
                    help="LaTeX template file")
parser.add_argument(
    "-tu",
    "--template-update",
    action='store_true',
    help="Retrieve latest LaTeX template file - Will OVERWRITE template.tex")
parser.add_argument(
    "-s",
    "--services",
    default="services.json",
    help="JSON file containing human readable names for specific services")
parser.add_argument(
    "-su",
    "--services-update",
    action='store_true',
    help="Retrieve latest services file - Will OVERWRITE services.json")
parser.add_argument("-v",
                    "--vuln",
                    help="External Nmap vulentability scan XML file")
parser.add_argument(
    "-vr",
    "--vuln-report",
    action='store_true',
    help=
    "Create a vulnerability report even if no external vulnerability scan file has been provided"
)
parser.add_argument("-h",
                    "--help",
                    action="help",
                    default=argparse.SUPPRESS,
                    help="Show this help message")
parser.add_argument("--version",
                    action='version',
                    version='%(prog)s ' + __version__,
                    help="Show program's version number")
# Argument Parsing:
args = parser.parse_args()
nmap_file = args.Nmap
latex_file = args.Output
template_file = args.template
services_file = args.services
if not exists(nmap_file):
    quit('\nNmap XML scan file not found\nExiting...')
if args.users:
    users_file = args.users
if args.vuln:
    vuln_file = args.vuln
if args.services_update:
    update_services()
if args.template_update:
    update_template()
exist_verifier(template_file, 'template')
exist_verifier(services_file, 'services')

main()
