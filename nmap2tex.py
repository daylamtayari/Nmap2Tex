#! /usr/bin/python3

__version__ = '0.1'
__author__ = 'Daylam Tayari'

from os import rename
import sys
import re
from xml.dom import minidom
from collections import OrderedDict

# Global Variables:

nmapFile = ''
latexFile = ''
usersFile = ''
templateFile = ''
nmapScan = ''
hostXML = ''
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

    def getService(self, port_id):
        return self.ports[port_id].getService()

    def getPortOutput(self, port_id):
        return self.ports[port_id].port + '/' + self.ports[port_id].protocol.upper()

    def portsOpen(self):
        if len(self.ports) > 0:
            return True
        else:
            return False

    def addPort(self, port, protocol):
        new_port = Port(port, protocol)
        self.ports.append(new_port)
        self._port_id += 1
        return (self._port_id - 1)

    def addService(self, port_id, service_name):
        self.ports[port_id].service = Service(service_name)

    def addServiceProduct(self, port_id, product):
        self.ports[port_id].service.product = product

    def addServiceVersion(self, port_id, version):
        self.ports[port_id].service.version = version

    def addVuln(self, cve, cvss, port):
        new_vuln = Vuln(cve, cvss, port)
        self.vulns.append(new_vuln)
        self._vuln_id += 1
        return (self._vuln_id - 1)


class Port:
    def __init__(self, port, protocol):
        self.port = port
        self.protocol = protocol
        self.service = None

    def getService(self):
        output = ''
        if self.service is None:
            return 'Unknown'
        elif self.service.product == '':
            output += self.service.name
        else:
            output += self.service.product
        if self.service.version != '':
            output += ' v' + self.service.version
        return output


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
    admin = False

    def __init__(self, name):
        self.name = name


# Input Handling:

def invalidInput(num):
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


def inputHandling():
    if len(sys.argv) == 1:
        return invalidInput(0)
    elif len(sys.argv) == 2:
        if sys.argv[1] == '-h' or sys.argv[1] == '--help':
            return invalidInput(-1)
        else:
            return invalidInput(1)
    elif len(sys.argv) > 7:
        return invalidInput(2)
    else:
        global nmapFile, latexFile
        nmapFile = sys.argv[1]
        latexFile = sys.argv[2]
        if len(sys.argv) == 5 or len(sys.argv) == 7:
            global usersFile, templateFile
            for i in range(5, 7, 2):
                if sys.argv[i-2] == '-u' or sys.argv[i-2] == '--users':
                    usersFile = sys.argv[i - 1]
                elif sys.argv[i-2] == '-t' or sys.argv[i-2] == '--template':
                    templateFile = sys.argv[i - 1]
                else:
                    return invalidInput(3)
        elif not len(sys.argv) == 3:
            return invalidInput(3)


# XML File Handling:


def xmlHandling():
    global nmapScan, hostXML
    nmapScan = minidom.parse(nmapFile)
    hostXML = nmapScan.getElementsByTagName("host")


def renameServices(serv):
    for s in services:
        if s in serv:
            return services.get(s)
    return serv


def parseHost(host):
    ip = host.getElementsByTagName("address")[0].getAttribute("addr")
    opSys = host.getElementsByTagName("os")[0].getElementsByTagName("osmatch")
    if len(opSys) == 0:
        opSys = 'Unknown'
    else:
        opSys = opSys[0].getAttribute("name")
        if "Microsoft" in opSys:
            opSys = opSys[10:]
    hst = Host(ip, opSys)
    # Parse ports:
    portInfo = host.getElementsByTagName("ports")[0].getElementsByTagName("port")
    for port in portInfo:
        port_id = hst.addPort(port.getAttribute("portid"), port.getAttribute("protocol"))
        if port.getElementsByTagName("service") == []:
            hst.addService(port_id, 'Unknown')
        else:
            serv = port.getElementsByTagName("service")[0]
            hst.addService(port_id, renameServices(serv.getAttribute("name")))
            if serv.getAttribute("product") != '':
                hst.addServiceProduct(port_id, renameServices(serv.getAttribute("product")))
            if serv.getAttribute("version") != '':
                vers = re.search(r'^([0-9][\.0-9a-z]*)|[\ _]([0-9][\.0-9]*)', serv.getAttribute("version"))
                if vers is not None and vers.group(1) is not None:
                    vers = vers.group(1)
                elif vers is not None and vers.group(2) is not None:
                    vers = vers.group(2)
                else:
                    vers = ''
                hst.addServiceVersion(port_id, vers)
        # Check for PC name if available:
        if not port.getElementsByTagName("script") == []:
            script = port.getElementsByTagName("script")[0]
            if not script.getElementsByTagName("elem") == []:
                elem = script.getElementsByTagName("elem")
                if len(elem) > 2:
                    if elem[2].getAttribute("key") == 'NetBIOS_Computer_Name':
                        hst.hostname = elem[2].firstChild.data
    global hosts
    hosts.append(hst)


# Users File Handling:

def getUsers():
    with open(usersFile) as file:
        for line in file:
            users.append(User(line.rstrip()))
    file.close()


def adminHandling(user):
    if user.admin:
        return "\\textbf{" + user.name + "}"
    else:
        return user.name


def handleUsers():
    if len(users) % 6 == 0:
        for i in range(0, len(users), 6):
            addUsers(adminHandling(users[i]), adminHandling(users[i+1]), adminHandling(users[i+2]), adminHandling(users[i+3]), adminHandling(users[i+4]), adminHandling(users[i+5]))
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
                addUsers(adminHandling(lastUsers[0]), adminHandling(lastUsers[1]), adminHandling(lastUsers[2]), adminHandling(lastUsers[3]), adminHandling(lastUsers[4]), adminHandling(lastUsers[5]))
            else:
                addUsers(adminHandling(users[i]), adminHandling(users[i + 1]), adminHandling(users[i + 2]), adminHandling(users[i + 3]), adminHandling(users[i + 4]), adminHandling(users[i + 5]))


# File Handling:

def createFile():
    file = open(latexFile, "w")
    # Allows us to also wipe the file if it already contains something.
    file.write("")
    file.close()


def appendFile(content):
    file = open(latexFile, "a")
    file.write(content)
    file.close()


def readFile(file):
    f = open(file, "r")
    content = f.read()
    f.close()
    return content


# LaTeX Handling:

def createTex():
    content = readFile("template.tex")
    createFile()
    appendFile(content)


def startHosts():
    appendFile('\n' + r"\hosttable{")


def addHost(host):
    appendFile('\n\t' + r"\host{%s}{%s}{%s}{" % (host.hostname, host.ip, host.os))
    if not host.portsOpen():
        appendFile('\n\t\t' + r"\portserv{None}{None}")
    else:
        for i in range(len(host.ports)):
            appendFile('\n\t\t' + r"\portserv{%s}{%s}" % (host.getPortOutput(i), host.ports[i].getService()))
    appendFile("\n\t}")


def endHosts():
    appendFile("\n}")


def startUsers():
    appendFile('\n' + r"\vspace{0.9cm}" + '\n' + r"\usertble{")


def addUsers(user1, user2, user3, user4, user5, user6):
    appendFile('\n\t' + r"\user{%s}{%s}{%s}{%s}{%s}{%s}" % (user1, user2, user3, user4, user5, user6))


def endUsers():
    appendFile("\n}")


def endFile():
    appendFile('\n' + r"\end{document}")


# Core Program Handling:

def main():
    inputHandling()
    xmlHandling()
    # Create and initiate LaTeX file:
    createTex()
    # Handle hosts:
    startHosts()
    for hx in hostXML:
        parseHost(hx)
    for h in hosts:
        addHost(h)
    endHosts()
    # Handle users:
    if not usersFile == '':
        getUsers()
        startUsers()
        handleUsers()
        endUsers()
    endFile()


main()
