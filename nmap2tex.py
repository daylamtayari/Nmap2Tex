#! /usr/bin/python3

__version__ = 0.1
__author__ = 'Daylam Tayari'

import sys
from xml.dom import minidom

# Global Variables:

nmapFile = ''
latexFile = ''
usersFile = ''
templateFile = ''
nmapScan = ''
hosts = ''
users = []


# Input Handling:

def invalidInput(num):
    print('Nmap2Tex ' + str(__version__))
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
    global nmapScan, hosts
    nmapScan = minidom.parse(nmapFile)
    hosts = nmapScan.getElementsByTagName("host")


def parseHost(host):
    hostInfo = []
    ports = []
    services = []
    hostInfo.append(host.getElementsByTagName("address")[0].getAttribute("addr"))
    opSys = host.getElementsByTagName("os")[0].getElementsByTagName("osmatch")
    if len(opSys) == 0:
        hostInfo.append('Unknown')
    else:
        hostInfo.append(opSys[0].getAttribute("name"))
        if "Microsoft" in hostInfo[1]:
            operSys = hostInfo[1][10:]
            hostInfo.pop(1)
            hostInfo.append(operSys)
    # Parse ports:
    portInfo = host.getElementsByTagName("ports")[0].getElementsByTagName("port")
    for port in portInfo:
        ports.append(port.getAttribute("portid") + '/' + port.getAttribute("protocol"))
        if port.getElementsByTagName("service") == []:
            services.append('Unknown')
        else:
            serv = port.getElementsByTagName("service")[0]
            if serv.getAttribute("product") == '':
                services.append(serv.getAttribute("name"))
            else:
                services.append(serv.getAttribute("product"))
            if "Microsoft" in services[len(services)-1]:
                service = services[len(services)-1][10:]
                services.pop(len(services)-1)
                services.append(service)
        # Check for PC name if available:
        if not port.getElementsByTagName("script") == []:
            script = port.getElementsByTagName("script")[0]
            if not script.getElementsByTagName("elem") == []:
                elem = script.getElementsByTagName("elem")
                if len(elem) > 2:
                    if elem[2].getAttribute("key") == 'NetBIOS_Computer_Name':
                        hostInfo.append(elem[2].firstChild.data)
    addHost(hostInfo, ports, services)


# Users File Handling:

def getUsers():
    with open(usersFile) as file:
        for line in file:
            users.append(line.rstrip())
    file.close()


def handleUsers():
    if len(users) % 6 == 0:
        for i in range(0, len(users), 6):
            addUsers(users[i], users[i+1], users[i+2], users[i+3], users[i+4], users[i+5])
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
                addUsers(lastUsers[0], lastUsers[1], lastUsers[2], lastUsers[3], lastUsers[4], lastUsers[5])
            else:
                addUsers(users[i], users[i + 1], users[i + 2], users[i + 3], users[i + 4], users[i + 5])


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


def addHost(hostInfo, ports, services):
    if len(hostInfo) > 2:
        appendFile('\n\t' + r"\host{%s}{%s}{%s}{" % (hostInfo[2], hostInfo[0], hostInfo[1]))
    else:
        appendFile('\n\t' + r"\host{Unknown}{%s}{%s}{" % (hostInfo[0], hostInfo[1]))
    if len(ports) == 0:
        appendFile('\n\t\t' + r"\portserv{None}{None}")
    else:
        for i in range(len(ports)):
            appendFile('\n\t\t' + r"\portserv{%s}{%s}" % (ports[i].upper(), services[i]))
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
    for h in hosts:
        parseHost(h)
    endHosts()
    # Handle users:
    if not usersFile == '':
        getUsers()
        startUsers()
        handleUsers()
        endUsers()
    endFile()


main()