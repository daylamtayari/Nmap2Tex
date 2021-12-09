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


# Input Handling:

def invalidInput(num):
    print('Nmap2Tex '+str(__version__))
    if num == 0:
        print('Invalid Input: No inputs provided.')
    elif num == 1:
        print('Invalid Input: Only one input provided.')
    elif num == 2:
        print('Invalid Input: Only 6 inputs at most can be provided including files.')
    elif num == 3:
        print('Invalid input combination.')
    print('Usage: nmap2tex <Nmap XML file> <Output LaTeX file> [-u/--users <User\'s file>] [-t/--template <Template file>]')
    print('The Nmap file provided must be an Nmap scan output file \nformatted in Nmap\'s XML format.')
    print('A users file can also be provided which provides a list of users \nseparated by either `,` `;`, a new line character or a tab character.')
    print('A LaTeX template file can also be provided in an XML format. \nPlease see project documentation for more details.')


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
                    usersFile = sys.argv[i-1]
                elif sys.argv[i] == '-t' or sys.argv[i] == '--template':
                    templateFile = sys.argv[i-1]
                else:
                    return invalidInput(3)
        elif not len(sys.argv) == 3:
            return invalidInput(3)


# XML File Handling:


def xmlHandling():
    global nmapScan, hosts
    nmapScan = minidom.parse(nmapFile)
    hosts = nmapScan.getElementsByTagName("host")
    for h in hosts:
        parseHost(h)


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
        ports.append(port.getAttribute("portid")+'/'+port.getAttribute("protocol"))
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
    # Return all 3 arrays to LaTeX file.


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
