#! /usr/bin/python3

__version__ = 0.1
__author__ = 'Daylam Tayari'

import sys


# Global Variables:

xmlFile = ''
latexFile = ''
usersFile = ''


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
    print('The Nmap file provided must be an Nmap scan output file formatted in Nmap\'s XML format.')


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
        global xmlFile
        xmlFile = sys.argv[1]
        global latexFile
        latexFile = sys.argv[2]


inputHandling()
