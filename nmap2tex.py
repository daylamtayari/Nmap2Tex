#! /usr/bin/python3

__version__ = 0.1
__author__ = 'Daylam Tayari'

import sys
from xml.dom import minidom


# Global Variables:

nmapFile = ''
latexFile = ''
usersFile = ''
nmapScan = ''
hosts = ''


# Handle Inputs:

def invalidInput(num):
    print('Nmap2Tex '+str(__version__))
    if num == 0:
        print('Invalid Input: No inputs provided.')
    if num == 1:
        print('Invalid Input: Only one input provided.')
    if num == 2:
        print('Invalid Input: Only two inputs must be provided.')
    print('Usage: nmap2tex <Nmap XML file> <Output LaTeX file> [-u/--users <User\'s file>]')
    print('The Nmap file provided must be an Nmap scan output file \nformatted in Nmap\'s XML format.')
    print('A users file can also be provided which provides a list of users \nseparated by either `,` `;`, a new line character or a tab character.')


def inputHandling():
    if len(sys.argv) == 1 or len(sys.argv) == 2:
        if len(sys.argv) == 1:
            return invalidInput(0)
    if len(sys.argv) == 2:
        if sys.argv[1] == '-h' or sys.argv[1] == '--help':
            return invalidInput(-1)
        else:
            return invalidInput(1)
    if len(sys.argv) > 4:
        return invalidInput(2)
    else:
        if len(sys.argv) == 4:
            global usersFile
            usersFile = sys.argv[3]
        global nmapFile, latexFile
        nmapFile = sys.argv[1]
        latexFile = sys.argv[2]


# Retrieving and parsing the Nmap XML file:

def xmlHandling():
    global nmapScan, hosts
    nmapScan = minidom.parse(nmapFile)
    hosts = nmapScan.getElementsByTagName("host")


def parseHost(host):
    hostInfo = []
    ports = []
    services = []
    hostInfo.append(host.getElementsByTagName("address").getAttribute("addr"))
    opSys = host.getElementsByTagName("os").getElementsByTagName("osmatch")
    if opSys is None:
        hostInfo.append('Unknown')
    else:
        hostInfo.append(opSys)
    # Parse ports:
    portInfo = host.getElementsByTagName("posts")
    for port in portInfo:
        ports.append(port.getAttribute("portid")+'/'+port.getAttribute("tcp"))
        serv = port.getElementsByTagName("service")
        if serv.getAttribute("product") is None:
            services.append(serv.getAttribute("name"))
        else:
            services.append(serv.getAttribute("product"))
        name = port.getElementsByTagName("script").getElementsByTagName("elem")[1]
        if name is not None:
            hostInfo.append(name)
    # Return all 3 arrays to LaTeX file.
