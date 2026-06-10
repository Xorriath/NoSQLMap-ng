#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# NoSQLMap Copyright 2012-2017 NoSQLMap Development team
# See the file 'doc/COPYING' for copying permission

from .exception import NoSQLMapException
import sys
from . import nsmcouch
from . import nsmmongo
from . import nsmscan
from . import nsmweb
import os
import signal
import json

import argparse


def main(args):
    signal.signal(signal.SIGINT, signal_handler)
    global optionSet
    # Set a list so we can track whether options are set or not to avoid resetting them in subsequent calls to the options menu.
    optionSet = [False]*9
    global yes_tag
    global no_tag
    yes_tag = ['y', 'Y']
    no_tag = ['n', 'N']
    global victim
    global webPort
    global uri
    global httpMethod
    global platform
    global https
    global myIP
    global myPort
    global verb
    global scanNeedCreds
    global dbPort
    # Use MongoDB as the default, since it's the least secure ( :-p at you 10Gen )
    platform = "MongoDB"
    dbPort = 27017
    myIP = "Not Set"
    myPort = "Not Set"
    if args.attack:
        attack(args)
    else:
        mainMenu()

def mainMenu():
    global platform
    global victim
    global dbPort
    global myIP
    global webPort
    global uri
    global httpMethod
    global https
    global verb
    global requestHeaders
    global postData

    mmSelect = True
    while mmSelect:
        os.system('clear')
        print(" _  _     ___  ___  _    __  __           ")
        print("| \\| |___/ __|/ _ \\| |  |  \\/  |__ _ _ __ ")
        print("| .` / _ \\__ \\ (_) | |__| |\\/| / _` | '_ \\")
        print("|_|\\_\\___/___/\\__\\_\\____|_|  |_\\__,_| .__/")
        print(" v0.7 codingo@protonmail.com        |_|   ")
        print("\n")
        print("1-Set options")
        print("2-NoSQL DB Access Attacks")
        print("3-NoSQL Web App attacks")
        print("4-Scan for Anonymous " + platform + " Access")
        print("5-Change Platform (Current: " + platform + ")")
        print("x-Exit")

        select = input("Select an option: ")

        if select == "1":
            options()

        elif select == "2":
            if optionSet[0] == True and optionSet[4] == True:
                if platform == "MongoDB":
                    nsmmongo.netAttacks(victim, dbPort, myIP, myPort)

                elif platform == "CouchDB":
                    nsmcouch.netAttacks(victim, dbPort, myIP)

            # Check minimum required options
            else:
                input("Target not set! Check options.  Press enter to continue...")


        elif select == "3":
            # Check minimum required options
            if (optionSet[0] == True) and (optionSet[2] == True):
                if httpMethod == "GET":
                    nsmweb.getApps(webPort,victim,uri,https,verb,requestHeaders)

                elif httpMethod == "POST":
                    nsmweb.postApps(victim,webPort,uri,https,verb,postData,requestHeaders)

            else:
                input("Options not set! Check host and URI path.  Press enter to continue...")


        elif select == "4":
            scanResult = nsmscan.massScan(platform)

            if scanResult != None:
                optionSet[0] = True
                victim = scanResult[1]

        elif select == "5":
            platSel()

        elif select == "x":
            sys.exit()

        else:
            input("Invalid selection.  Press enter to continue.")

def build_request_headers(reqHeadersIn):
    reqHeadersArray = reqHeadersIn.split(",")
    if len(reqHeadersArray) % 2 != 0 and any(reqHeadersArray):
        print("Warning: odd number of header fields; the last value will be dropped.")
    headerNames = reqHeadersArray[0::2]
    headerValues = reqHeadersArray[1::2]
    return dict(zip(headerNames, headerValues))

def build_post_data(postDataIn):
    pdArray = postDataIn.split(",")
    if len(pdArray) % 2 != 0 and any(pdArray):
        print("Warning: odd number of POST fields; the last value will be dropped.")
    paramNames = pdArray[0::2]
    paramValues = pdArray[1::2]
    return dict(zip(paramNames,paramValues))

def attack(args):
    platform = args.platform
    victim = args.victim
    webPort = args.webPort
    dbPort = args.dbPort
    myIP = args.myIP
    myPort = args.myPort
    uri = args.uri
    https = args.https
    verb = args.verb
    httpMethod = args.httpMethod
    requestHeaders = build_request_headers(args.requestHeaders)
    postData = build_post_data(args.postData)

    if args.attack == 1:
        if platform == "MongoDB":
            nsmmongo.netAttacks(victim, dbPort, myIP, myPort, args)
        elif platform == "CouchDB":
            nsmcouch.netAttacks(victim, dbPort, myIP, args)
    elif args.attack == 2:
        if httpMethod == "GET":
            nsmweb.getApps(webPort,victim,uri,https,verb,requestHeaders, args)
        elif httpMethod == "POST":
            nsmweb.postApps(victim,webPort,uri,https,verb,postData,requestHeaders, args)
    elif args.attack == 3:
        scanResult = nsmscan.massScan(platform)
        if scanResult != None:
            optionSet[0] = True
            victim = scanResult[1]

def platSel():
    global platform
    global dbPort
    select = True
    print("\n")

    while select:
        print("1-MongoDB")
        print("2-CouchDB")
        pSel = input("Select a platform: ")

        if pSel == "1":
            platform = "MongoDB"
            dbPort = 27017
            return

        elif pSel == "2":
            platform = "CouchDB"
            dbPort = 5984
            return
        else:
            input("Invalid selection.  Press enter to continue.")


def options():
    global victim
    global webPort
    global uri
    global https
    global platform
    global httpMethod
    global postData
    global myIP
    global myPort
    global verb
    global mmSelect
    global dbPort
    global requestHeaders
    requestHeaders = {}
    optSelect = True

    # Set default value if needed
    if optionSet[0] == False:
        victim = "Not Set"
    if optionSet[1] == False:
        webPort = 80
        optionSet[1] = True
    if optionSet[2] == False:
        uri = "Not Set"
    if optionSet[3] == False:
        httpMethod = "GET"
    if optionSet[4] == False:
        myIP = "Not Set"
    if optionSet[5] == False:
        myPort = "Not Set"
    if optionSet[6] == False:
        verb = "OFF"
        optSelect = True
    if optionSet[8] == False:
        https = "OFF"
        optSelect = True

    while optSelect:
        print("\n\n")
        print("Options")
        print("1-Set target host/IP (Current: " + str(victim) + ")")
        print("2-Set web app port (Current: " + str(webPort) + ")")
        print("3-Set App Path (Current: " + str(uri) + ")")
        print("4-Toggle HTTPS (Current: " + str(https) + ")")
        print("5-Set " + platform + " Port (Current : " + str(dbPort) + ")")
        print("6-Set HTTP Request Method (GET/POST) (Current: " + httpMethod + ")")
        print("7-Set my local " +  platform + "/Shell IP (Current: " + str(myIP) + ")")
        print("8-Set shell listener port (Current: " + str(myPort) + ")")
        print("9-Toggle Verbose Mode: (Current: " + str(verb) + ")")
        print("0-Load options file")
        print("a-Load options from saved Burp request")
        print("b-Save options file")
        print("h-Set headers")
        print("x-Back to main menu")

        select = input("Select an option: ")

        if select == "1":
            # Unset the boolean if it's set since we're setting it again.
            optionSet[0] = False

            while optionSet[0] == False:
                victim = input("Enter the host IP/DNS name: ")

                if not victim.strip():
                    print("Host cannot be empty.")
                    continue

                octets = victim.split(".")

                # Four numeric octets -> validate ranges.  Anything else
                # (including a 4-label FQDN like app.staging.corp.com) is treated
                # as a DNS name.  The old code caught an exception INSTANCE here,
                # which raised TypeError and crashed on any non-numeric host.
                if len(octets) == 4 and all(o.isdigit() for o in octets):
                    if all(0 <= int(o) <= 255 for o in octets):
                        print("\nTarget set to " + victim + "\n")
                        optionSet[0] = True
                    else:
                        print("Bad octet in IP address.")
                else:
                    print("\nTarget set to " + victim + "\n")
                    optionSet[0] = True

        elif select == "2":
            p = input("Enter the HTTP port for web apps: ").strip()
            if p.isdigit() and 1 <= int(p) <= 65535:
                webPort = int(p)
                print("\nHTTP port set to " + str(webPort) + "\n")
                optionSet[1] = True
            else:
                print("Invalid port.  Must be 1-65535.")

        elif select == "3":
            uri = input("Enter URI Path (Press enter for no URI): ")
            #Ensuring the URI path always starts with / and accepts null values
            if len(uri) == 0:
                uri = "Not Set"
                print("\nURI Not Set.\n")
                optionSet[2] = False

            elif uri[0] != "/":
                uri = "/" + uri
                print("\nURI Path set to " + uri + "\n")
            optionSet[2] = True

        elif select == "4":
            if https == "OFF":
                print("HTTPS enabled.")
                https = "ON"
                optionSet[8] = True

            elif https == "ON":
                print("HTTPS disabled.")
                https = "OFF"
                optionSet[8] = True


        elif select == "5":
            p = input("Enter target " + platform + " port: ").strip()
            if p.isdigit() and 1 <= int(p) <= 65535:
                dbPort = int(p)
                print("\nTarget " + platform + " Port set to " + str(dbPort) + "\n")
                optionSet[7] = True
            else:
                print("Invalid port.  Must be 1-65535.")

        elif select == "6":
            httpMethod = True
            while httpMethod == True:

                print("1-Send request as a GET")
                print("2-Send request as a POST")
                httpMethod = input("Select an option: ")

                if httpMethod == "1":
                    httpMethod = "GET"
                    print("GET request set")
                    requestHeaders = {}
                    optionSet[3] = True

                elif httpMethod == "2":
                    print("POST request set")
                    optionSet[3] = True
                    postDataIn = input("Enter POST data in a comma separated list (i.e. param name 1,value1,param name 2,value2)\n")
                    postData = build_post_data(postDataIn)
                    httpMethod = "POST"

                else:
                    print("Invalid selection")

        elif select == "7":
            # Unset the setting boolean since we're setting it again.
            optionSet[4] = False

            while optionSet[4] == False:
                myIP = input("Enter the host IP for my " + platform + "/Shells: ")
                octets = myIP.split(".")

                # The listener IP must be a real dotted IPv4; int() on a
                # non-numeric octet used to raise an uncaught ValueError.
                if (len(octets) == 4 and all(o.isdigit() for o in octets)
                        and all(0 <= int(o) <= 255 for o in octets)):
                    print("\nShell/DB listener set to " + myIP + "\n")
                    optionSet[4] = True
                else:
                    print("Invalid IP address.")

        elif select == "8":
            myPort = input("Enter TCP listener for shells: ")
            print("Shell TCP listener set to " + myPort + "\n")
            optionSet[5] = True

        elif select == "9":
            if verb == "OFF":
                print("Verbose output enabled.")
                verb = "ON"
                optionSet[6] = True

            elif verb == "ON":
                print("Verbose output disabled.")
                verb = "OFF"
                optionSet[6] = True

        elif select == "0":
            loadPath = input("Enter file name to load: ")
            try:
                with open(loadPath, "r") as fo:
                    opts = json.load(fo)
            except OSError as e:
                print("I/O error: " + str(e))
                input("error reading file.  Press enter to continue...")
                return
            except (ValueError, json.JSONDecodeError):
                input("Invalid or corrupt options file.  Press enter to continue...")
                return

            victim = opts.get("victim", "Not Set")
            webPort = opts.get("webPort", 80)
            uri = opts.get("uri", "Not Set")
            httpMethod = opts.get("httpMethod", "GET")
            myIP = opts.get("myIP", "Not Set")
            myPort = opts.get("myPort", "Not Set")
            verb = opts.get("verb", "OFF")
            https = opts.get("https", "OFF")
            dbPort = opts.get("dbPort", dbPort)
            postData = opts.get("postData", {}) or {}
            requestHeaders = opts.get("requestHeaders", {}) or {}

            # Set the option-checking flags explicitly (the old positional loop
            # was mis-aligned with the optionSet indices).
            optionSet[0] = victim != "Not Set"
            optionSet[1] = True
            optionSet[2] = uri != "Not Set"
            optionSet[3] = True
            optionSet[4] = myIP != "Not Set"
            optionSet[5] = myPort != "Not Set"
            optionSet[6] = True
            optionSet[7] = True
            optionSet[8] = True

        elif select == "a":
            loadPath = input("Enter path to Burp request file: ")
            reqData = []
            try:
                with open(loadPath,"r") as fo:
                    for line in fo:
                        reqData.append(line.rstrip("\r\n"))
            except OSError as e:
                print("I/O error: " + str(e))
                input("error reading file.  Press enter to continue...")
                return

            if not reqData:
                input("Empty request file.  Press enter to continue...")
                return

            methodPath = reqData[0].split(" ")
            if len(methodPath) < 2 or methodPath[0] not in ("GET", "POST"):
                input("Unsupported or malformed request line.  Press enter to continue...")
                return

            httpMethod = methodPath[0]
            uri = methodPath[1]
            optionSet[2] = True
            optionSet[3] = True

            # Parse headers up to the blank line that separates them from the body.
            requestHeaders = {}
            bodyStart = len(reqData)
            for i in range(1, len(reqData)):
                if not reqData[i].strip():
                    bodyStart = i + 1
                    break
                parts = reqData[i].split(": ", 1)
                if len(parts) == 2:
                    requestHeaders[parts[0]] = parts[1].strip()

            # Target host comes from the Host header (strip any :port), not from a
            # fixed line number.
            victim = requestHeaders.get("Host", "").split(":")[0]
            if victim:
                optionSet[0] = True

            if httpMethod == "POST":
                bodyLines = [l for l in reqData[bodyStart:] if l.strip()]
                body = bodyLines[-1] if bodyLines else ""
                postData = {}
                for item in body.split("&"):
                    if not item:
                        continue
                    kv = item.split("=", 1)
                    postData[kv[0]] = kv[1] if len(kv) > 1 else ""

        elif select == "b":
            savePath = input("Enter file name to save: ")
            opts = {
                "victim": victim,
                "webPort": webPort,
                "uri": uri,
                "httpMethod": httpMethod,
                "myIP": myIP,
                "myPort": myPort,
                "verb": verb,
                "https": https,
                "dbPort": dbPort,
                "postData": globals().get("postData", {}) if httpMethod == "POST" else {},
                "requestHeaders": requestHeaders,
            }
            try:
                with open(savePath, "w") as fo:
                    json.dump(opts, fo, indent=2)
                print("Options file saved!")
            except OSError:
                print("Couldn't save options file.")

        elif select == "h":
            reqHeadersIn = input("Enter HTTP Request Header data in a comma separated list (i.e. header name 1,value1,header name 2,value2)\n")
            requestHeaders = build_request_headers(reqHeadersIn)

        elif select == "x":
            return

def build_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("--attack", help="1 = NoSQL DB Access Attacks, 2 = NoSQL Web App attacks, 3 - Scan for Anonymous platform Access", type=int, choices=[1,2,3])
    parser.add_argument("--platform", help="Platform to attack", choices=["MongoDB", "CouchDB"], default="MongoDB")
    parser.add_argument("--victim", help="Set target host/IP (ex: localhost or 127.0.0.1)")
    parser.add_argument("--dbPort", help="Set shell listener port", type=int)
    parser.add_argument("--myIP",help="Set my local platform/Shell IP")
    parser.add_argument("--myPort",help="Set my local platform/Shell port", type=int)
    parser.add_argument("--webPort", help="Set web app port ([1 - 65535])", type=int)
    parser.add_argument("--uri", help="Set App Path. For example '/a-path/'. Final URI will be [https option]://[victim option]:[webPort option]/[uri option]")
    parser.add_argument("--httpMethod", help="Set HTTP Request Method", choices=["GET","POST"], default="GET")
    parser.add_argument("--https", help="Toggle HTTPS", choices=["ON", "OFF"], default="OFF")
    parser.add_argument("--verb", help="Toggle Verbose Mode", choices=["ON", "OFF"], default="OFF")
    parser.add_argument("--postData", help="Enter POST data in a comma separated list (i.e. param name 1,value1,param name 2,value2)", default="")
    parser.add_argument("--requestHeaders", help="Request headers in a comma separated list (i.e. param name 1,value1,param name 2,value2)", default="")

    modules = [nsmcouch, nsmmongo, nsmscan, nsmweb]
    for module in modules:
        group = parser.add_argument_group(module.__name__)
        for arg in module.args():
            group.add_argument(arg[0], help=arg[1])

    return parser

def signal_handler(signal, frame):
    print("\n")
    print("CTRL+C detected.  Exiting.")
    sys.exit()

