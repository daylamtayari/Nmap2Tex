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
                if sys.argv[i] == '-u' or sys.argv[i] == '--users':
                    usersFile = sys.argv[i - 1]
                elif sys.argv[i] == '-t' or sys.argv[i] == '--template':
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
                for j in range(1, (lim + 1)):
                    if (i + j) > (len(users) - 1):
                        lastUsers.append("")
                    else:
                        lastUsers.append(users[i+j])
                addUsers(lastUsers[0], lastUsers[1], lastUsers[2], lastUsers[3], lastUsers[4], lastUsers[5])


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
    appendFile(r"\hosttable{")


def addHost(hostInfo, ports, services):
    if len(hostInfo) > 2:
        appendFile(r"\host{%s}{%s}{%s}{" % (hostInfo[2], hostInfo[0], hostInfo[1]))
    else:
        appendFile(r"\host{Unknown}{%s}{%s}{" % (hostInfo[0], hostInfo[1]))
    for i in range(len(ports)):
        appendFile(r"\portserve{%s}{%s}" % (ports[i].upper(), services[i]))
    appendFile("}")


def endHosts():
    appendFile("}")


def startUsers():
    appendFile(r"\nvspace{0.9cm}\n\usertble{")


def addUsers(user1, user2, user3, user4, user5, user6):
    appendFile(r"\user{%s}{%s}{%s}{%s}{%s}{%s}" % (user1, user2, user3, user4, user5, user6))


def endUsers():
    appendFile("}")


def endFile():
    appendFile(r"\end{document}")


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
        startUsers()
        handleUsers()
        endUsers()
    endFile()


if __name__ == "__main":
    main()