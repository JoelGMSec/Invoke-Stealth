#!/usr/bin/env python3

'''
 
 	PyFuscation.py
    This python3 script obfuscates powershell function, variable and parameters in an attempt to bypass AV blacklists 

'''

import re
import os
import sys
import ast
import time
import shutil
import random
import subprocess
import shlex
import string
from argparse import ArgumentParser
import configparser
import fileinput

def printR(out): print("\033[91m{}\033[00m" .format("[!] " + out)) 
def printG(out): print("\033[92m{}\033[00m" .format("[*] " + out)) 
def printY(out): print("\033[93m{}\033[00m" .format("[+] " + out)) 
def printP(out): print("\033[95m{}\033[00m" .format("[-] " + out)) 

def realTimeMuxER(command):
    p = subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE)
    while True:
        output = p.stdout.readline().decode()
        if output == '' and p.poll() is not None:
            break
        if output:
            print(output.strip())
    rc = p.poll()

def removeJunk(oF):
    # general cleanup 
    cmd = "sed -i -e \'/<#/,/#>/c\\\\\' " + oF
    realTimeMuxER(cmd)
    cmd = "sed -i -e \'s/^[[:space:]]*#.*$//g\' " + oF
    realTimeMuxER(cmd)
    cmd = "sed -i \'/^$/d\' " + oF
    realTimeMuxER(cmd)

def useSED(DICT, oF):
    for var in DICT:
        new = str(DICT.get(var))
        cmd = "sed -i -e \'s/" + var +'\\b' + "/" + new + "/g\' " + oF
        realTimeMuxER(cmd)

def THEreplacER(DICT, iF, oF):
    iFHandle = open(iF, 'r')
    ofHandle = open(oF, 'w')
    regex = r'(\$\w{3,})'
    lower_DICT = list(map(lambda x:x.lower(),DICT))
    # For var replace with Dictionary value
    for line in iFHandle:
        v = re.findall(regex,line)
        if not v:
            #print("Not: " + line)
            ofHandle.write(line + "\n")
            ofHandle.flush()
        else:
            for var in v:
                if var.lower() in lower_DICT:
                    new = str(DICT.get(var))
                    #print("Replacing " + var + " with " + new)
                    ofHandle.write(line.replace(var, new) + "\n")
                    ofHandle.flush()
                else:
                    #print(var)
                    ofHandle.write(line + "\n")
                    ofHandle.flush()

    iFHandle.close()
    ofHandle.close()

def findCustomParams(iFile,oFile,VARs):
    PARAMs = {}
    READ = False
    start = 0
    end = 0
    regex = r'([\$-]\w{4,})'
    ofHandle = open(oFile, 'w')

    with open(iFile, "r") as f:
        for line in f:
            line = line.strip()

            if re.search(r'\bparam\b', line, re.I):
                # Ok we are at the begining of a custum parameter
                READ = True

                # The open paren is on another line so move until we find it
                start = start + line.count('(')
                if start == 0:
                    continue

                end   = end + line.count(')')

                v = re.findall(regex,line)
                for i in v:
                    if i.lower() not in lower_Reserverd and i not in PARAMs:
                        # Lets check to see if this has been replaced already
                        new = VARs.get(i)
                        if not new:
                            continue
                        new = " -" + new[1:]
                        old = " -" + i[1:]
                        PARAMs[old] = new
                        ofHandle.write("Replacing: " + old + " with: " + new + "\n")

                # If the params are all on one line were done here
                if start != 0 and start == end:
                    start = 0
                    end = 0
                    READ = False
                    continue
                
            # These are the custom parameters
            elif READ:
                v = re.findall(regex,line)
                for i in v:
                    if i.lower() not in lower_Reserverd and i not in PARAMs:
                        new = VARs.get(i)
                        if not new:
                            continue
                        new = " -" + new[1:]
                        old = " -" + i[1:]
                        PARAMs[old] = new
                        ofHandle.write("Replacing: " + old + " with: " + new + "\n")

                start = start + line.count('(')
                end   = end + line.count(')')
                if start != 0 and start == end:
                    start = 0
                    end = 0
                    READ = False

            # Keep moving until we have work
            else:
                continue

    printY("Parameters Replaced : " + str(len(PARAMs)))

    return PARAMs

def findVARs(iFile,lFile):
    VARs = {}
    vNum = 9999
    regex = r'(\$\w{6,})'
    ofHandle = open(lFile, 'w')

    with open(iFile, "r") as f:
        for line in f:
            v = re.findall(regex,line)
            for i in v:
                if i in VARs:
                    continue
                elif i.lower() not in lower_Reserverd:
                    # Powershell vars are case insensitive
                    lowerVARS = {k.lower(): v for k, v in VARs.items()}
                    if i.lower() in lowerVARS:
                        new = lowerVARS.get(i.lower())
                        ofHandle.write("Replacing: " + i + " with: " + new + "\n")
                        VARs[i] = new
                    else:
                        vNum = 99
                        new = "$" + ''.join([random.choice(string.ascii_letters) for n in range(8)])
                        VARs[i] = new + str(vNum)
                        ofHandle.write("Replacing: " + i + " with: " + new + "\n")
                        vNum += 1

    # return dict of variable and their replacements
    printY("Variables Replaced  : " + str(len(VARs)))
    return VARs

def findFUNCs(iFile,lFile):

    FUNCs = {}
    ofHandle = open(lFile, 'w')
    with open(iFile, "r") as f:
        for line in f:
            funcMatch = re.search(r'^\s*Function ([a-zA-Z0-9_-]{6,})[\s\{]+$',line, re.IGNORECASE)
            if funcMatch and funcMatch.group(1) not in FUNCs: 
                if funcMatch.group(1) == "main":
                    continue
                vNum = 9999
                new = randomString(wordList)
                FUNCs[funcMatch.group(1)] = new
                ofHandle.write("Replacing: " + funcMatch.group(1) + " with: " + str(new) + "\n")
                vNum += 1
    # return dict of variable and their replacements
    printY("Functions Replaced  : " + str(len(FUNCs)))
    return FUNCs

def randomString(iFile):
    with open(iFile, "r") as f:
        line = next(f)
        for num, aline in enumerate(f, 2):
          if random.randrange(num): continue
          line = aline
        string = ''.join(e for e in line if e.isalnum())
        return string

def main():
    iFile = args.script

    printR("Obfuscating: " + iFile)
    ts = "tmp"
    oDir = os.path.dirname(args.script) + "/Resources/PyFuscation/tmp"
    os.mkdir( oDir );
    oFile = oDir + "/" + "script.ps1"
    vFile = oDir + "/" + "vFile.ps1"
    fFile = oDir + "/" + "fFile.ps1"
    pFile = oDir + "/" + "pFile.ps1"
    shutil.copy(args.script, oFile)

    obfuVAR     = dict()
    obfuPARMS   = dict()
    obfuFUNCs   = dict()

    # Remove White space and comments
    removeJunk(oFile)

    # Obfuscate Variables
    if (args.var):
        obfuVAR = findVARs(iFile,vFile) 
        useSED(obfuVAR, oFile)

    # Obfuscate custom parameters
    if (args.par):
        obfuPARMS = findCustomParams(iFile, pFile, obfuVAR)
        useSED(obfuPARMS, oFile)

    # Obfuscate Functions
    if (args.func):
        obfuFUNCs = findFUNCs(iFile, fFile)
        useSED(obfuFUNCs, oFile)

        # Print the Functions
        print("")
        printP("Obfuscated script located at  : " + oFile)

if __name__ == "__main__":
    
    if sys.version_info <= (3, 0):
        sys.stdout.write("This script requires Python 3.x\n")
        sys.exit(1)

    config = configparser.ConfigParser()
    parser = ArgumentParser()
    parser.add_argument("-f",   dest="func",    help="Obfuscate functions",     action="store_true")
    parser.add_argument("-v",   dest="var",     help="Obfuscate variables",     action="store_true")
    parser.add_argument("-p",   dest="par",     help="Obfuscate parameters",    action="store_true")
    parser.add_argument("--ps", dest="script",  help="Obfuscate powershell")

    args = parser.parse_args()

    # Powershell script
    if (args.script is None):
        parser.print_help()
        exit()
    else:
        # Check if the input file is valid:
        if not os.path.isfile(args.script):
            printR("Check File: " + args.script)
            exit()  
        else:
            PSconfigFile = os.path.abspath(os.path.dirname(__file__)) + "/PSconfig.ini"
            config.read(PSconfigFile)
            Reseverd = ast.literal_eval(config.get("PS_Reserverd", "f"))
            lower_Reserverd = list(map(lambda x:x.lower(),Reseverd))

    wordList = os.path.abspath(os.path.dirname(__file__)) + "/Wordlist.txt"
    if not os.path.isfile(wordList):
        printR("Check wordList: " + wordList)
        exit()

    main()
