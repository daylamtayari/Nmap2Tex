#! /usr/bin/python3

__version__ = '0.1'
__author__ = 'Daylam Tayari'

import sys
import re
from xml.dom import minidom
from collections import OrderedDict

# Global Variables:

nmap_file = ''
latex_file = ''
users_file = ''
template_file = ''
nmap_scan = ''
host_xml = ''
hosts = []
users = []

# Services Dictionary:

services = OrderedDict([
            ('Microsoft Terminal Services', 'Windows RDP'),
            ('Apache httpd', 'Apache HTTP Server'),
            ('Dropbear sshd', 'Dropbear SSH'),
            ('Active Directory LDAP', 'Active Directory LDAP'),
            ('Windows RPC over HTTP', 'Windows RPC over HTTP'),
            ('Microsoft Windows RPC', 'Windows RPC'),
            ('microsoft-ds', 'Windows SMB'),
            ('netbios-ssn', 'NetBIOS'),
            ('Kerberos', 'Windows Kerberos'),
            ('HTTPAPI', 'HTTPAPI'),
            ('ms-wbt-server', 'Windows RDP (WBT)'),
            ('Cockpit web service', 'Cockpit Web Administration')
        ])


# Object Classes:

class Host:
    def __init__(self, ip, os):
        self.ip = ip
        self.os = os
        self.hostname = 'Unknown'
        self.ports = []
        self._port_id = 0
        self.vulns = []
        self._vuln_id = 0

    def get_service(self, port_id):
        return self.ports[port_id].get_service()

    def get_port_service(self, _port):
        for p in self.ports:
            if p.port == _port:
                return p.get_service()

    def get_port_output(self, port_id):
        return self.ports[port_id].port + '/' + self.ports[port_id].protocol.upper()

    def ports_open(self):
        if len(self.ports) > 0:
            return True
        else:
            return False

    def has_vulns(self):
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

    def add_serviceProduct(self, port_id, product):
        self.ports[port_id].service.product = product

    def add_serviceVersion(self, port_id, version):
        self.ports[port_id].service.version = version

    def add_vuln(self, cve, cvss, port):
        new_vuln = Vuln(cve, cvss, port)
        if self._vuln_id == 0 or float(cvss) > float(self.vulns[self._vuln_id - 1].cvss):
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
    def __init__(self, port, protocol):
        self.port = port
        self.protocol = protocol
        self.service = None

    def get_service(self):
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
    def __init__(self, name):
        self.name = name
        self.product = ''
        self.version = ''


class Vuln:
    def __init__(self, cve, cvss, port):
        self.cve = cve
        self.cvss = cvss
        self.port = port


class User:
    def __init__(self, name):
        self.admin = False
        self.name = name


# Input Handling:

def invalid_input(num):
    print('Nmap2Tex ' + __version__)
    if num == 0:
        print('Invalid Input: No inputs provided.')
    elif num == 1:
        print('Invalid Input: Only one input provided.')
    elif num == 2:
        print('Invalid Input: Only 6 inputs at most can be provided including files.')
    elif num == 3:
        print('Invalid input combination.')
    print(
        'Usage: nmap2tex <Nmap XML file> <Output LaTeX file> [-u/--users <User\'s file>] [-t/--template <Template file>]')
    print('The Nmap file provided must be an Nmap scan output file \nformatted in Nmap\'s XML format.')
    print(
        'A users file can also be provided which provides a list of users \nseparated by either `,` `;`, a new line character or a tab character.')
    print(
        'A LaTeX template file can also be provided in an XML format. \nPlease see project documentation for more details.')


def input_handling():
    if len(sys.argv) == 1:
        return invalid_input(0)
    elif len(sys.argv) == 2:
        if sys.argv[1] == '-h' or sys.argv[1] == '--help':
            return invalid_input(-1)
        else:
            return invalid_input(1)
    elif len(sys.argv) > 7:
        return invalid_input(2)
    else:
        global nmap_file, latex_file
        nmap_file = sys.argv[1]
        latex_file = sys.argv[2]
        if len(sys.argv) == 5 or len(sys.argv) == 7:
            global users_file, template_file
            for i in range(5, 7, 2):
                if sys.argv[i-2] == '-u' or sys.argv[i-2] == '--users':
                    users_file = sys.argv[i - 1]
                elif sys.argv[i-2] == '-t' or sys.argv[i-2] == '--template':
                    template_file = sys.argv[i - 1]
                else:
                    return invalid_input(3)
        elif not len(sys.argv) == 3:
            return invalid_input(3)


# XML File Handling:


def xml_handling():
    global nmap_scan, host_xml
    nmap_scan = minidom.parse(nmap_file)
    host_xml = nmap_scan.getElementsByTagName("host")


def rename_services(serv):
    for s in services:
        if s in serv:
            return services.get(s)
    return serv


def parse_host(host):
    ip = host.getElementsByTagName("address")[0].getAttribute("addr")
    if host.getElementsByTagName("os") == []:
        opSys = {}
    else:
        opSys = host.getElementsByTagName("os")[0].getElementsByTagName("osmatch")
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
        portInfo = host.getElementsByTagName("ports")[0].getElementsByTagName("port")
    for port in portInfo:
        port_id = hst.add_port(port.getAttribute("portid"), port.getAttribute("protocol"))
        if port.getElementsByTagName("service") == []:
            hst.add_service(port_id, 'Unknown')
        else:
            serv = port.getElementsByTagName("service")[0]
            hst.add_service(port_id, rename_services(serv.getAttribute("name")))
            if serv.getAttribute("product") != '':
                hst.add_serviceProduct(port_id, rename_services(serv.getAttribute("product")))
            if serv.getAttribute("version") != '':
                vers = re.search(r'^([0-9][\.0-9a-z]*)|[\ _]([0-9][\.0-9]*)', serv.getAttribute("version"))
                if vers is not None and vers.group(1) is not None:
                    vers = vers.group(1)
                elif vers is not None and vers.group(2) is not None:
                    vers = vers.group(2)
                else:
                    vers = ''
                hst.add_serviceVersion(port_id, vers)
        # Check for PC name if available:
        if port.getElementsByTagName("script") != []:
            script = port.getElementsByTagName("script")[0]
            if script.getElementsByTagName("elem") != []:
                elem = script.getElementsByTagName("elem")
                if len(elem) > 2:
                    if elem[2].getAttribute("key") == 'NetBIOS_Computer_Name':
                        hst.hostname = elem[2].firstChild.data
        # Check for and add vulnerabilities:
        if not port.getElementsByTagName("script") == []:
            tables = port.getElementsByTagName("script")[0].getElementsByTagName("table")
            if tables != []:
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
                        hst.add_vuln(cveid, cvss, port.getAttribute("portid"))
    global hosts
    hosts.append(hst)


# Users File Handling:

def get_users():
    with open(users_file) as file:
        for line in file:
            users.append(User(line.rstrip()))
    file.close()


def admin_handling(user):
    if user.admin:
        return "\\textbf{" + user.name + "}"
    else:
        return user.name


def handle_users():
    if len(users) % 6 == 0:
        for i in range(0, len(users), 6):
            add_users(admin_handling(users[i]), admin_handling(users[i+1]), admin_handling(users[i+2]), admin_handling(users[i+3]), admin_handling(users[i+4]), admin_handling(users[i+5]))
    else:
        diff = len(users) % 6
        for i in range(0, len(users) + diff, 6):
            if i + 5 > (len(users) - 1):
                lim = len(users) - i - 1
                lastUsers = []
                for j in range(1, 7):
                    if j > lim:
                        lastUsers.append("")
                    else:
                        lastUsers.append(users[i+j])
                add_users(admin_handling(lastUsers[0]), admin_handling(lastUsers[1]), admin_handling(lastUsers[2]), admin_handling(lastUsers[3]), admin_handling(lastUsers[4]), admin_handling(lastUsers[5]))
            else:
                add_users(admin_handling(users[i]), admin_handling(users[i + 1]), admin_handling(users[i + 2]), admin_handling(users[i + 3]), admin_handling(users[i + 4]), admin_handling(users[i + 5]))


# File Handling:

def create_file():
    file = open(latex_file, "w")
    # Allows us to also wipe the file if it already contains something.
    file.write("")
    file.close()


def append_file(content):
    file = open(latex_file, "a")
    file.write(content)
    file.close()


def read_file(file):
    f = open(file, "r")
    content = f.read()
    f.close()
    return content


# LaTeX Handling:

def create_tex():
    content = read_file("template.tex")
    create_file()
    append_file(content)


def start_hosts():
    append_file('\n' + r"\hosttable{")


def add_host(host):
    append_file('\n\t' + r"\host{%s}{%s}{%s}{" % (host.hostname, host.ip, host.os))
    if not host.ports_open():
        append_file('\n\t\t' + r"\portserv{None}{None}")
    else:
        for i in range(len(host.ports)):
            append_file('\n\t\t' + r"\portserv{%s}{%s}" % (host.get_port_output(i), host.ports[i].get_service()))
    append_file("\n\t}")


def end_hosts():
    append_file("\n}")


def start_users():
    append_file('\n' + r"\vspace{0.9cm}" + '\n' + r"\usertble{")


def add_users(user1, user2, user3, user4, user5, user6):
    append_file('\n\t' + r"\user{%s}{%s}{%s}{%s}{%s}{%s}" % (user1, user2, user3, user4, user5, user6))


def end_users():
    append_file("\n}")


def start_vuln():
    append_file('\n' + r"\vspace{0.9cm}" + '\n')


def add_vulns(host):
    append_file('\n' + r"\systemvuln{%s}{%s}{%s}{" % (host.hostname, host.ip, host.vuln_status()))
    if not host.has_vulns():
        append_file('\n\t' + r"\vuln{None}{0.0}")
    else:
        for v in range(len(host.vulns)):
            append_file('\n\t' + r"\vuln{%s: %s}{%s}" % (host.get_port_service(host.vulns[v].port), host.vulns[v].cve, host.vulns[v].cvss))
    append_file('\n}')


def end_file():
    append_file('\n' + r"\end{document}")


# Core Program Handling:

def vulns_pres():
    for h in hosts:
        if h.has_vulns():
            return True
    else:
        return False


def main():
    input_handling()
    xml_handling()
    # Create and initiate LaTeX file:
    create_tex()
    # Handle hosts:
    start_hosts()
    for hx in host_xml:
        parse_host(hx)
    for h in hosts:
        add_host(h)
    end_hosts()
    # Handle vulnerabilities:
    if vulns_pres():
        start_vuln()
        for hv in hosts:
            add_vulns(hv)
    # Handle users:
    if not users_file == '':
        get_users()
        start_users()
        handle_users()
        end_users()
    end_file()


main()
