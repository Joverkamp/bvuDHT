from subprocess import check_output
import shutil
from socket import *
import hashlib
from sys import argv, exit
from pathlib import Path
import threading
import os


# Global variables we want to keep track of
MY_ADDR = ''
SUCC_ADDR = ''
PRED_ADDR = ''
# How many fingers we want people in the system to have
NUM_FINGERS = 4
# The finger table is a list of all the people we know.
# It contains our own address, our predacessor's address, 
# our successor's address, and NUM_FINGERS addresses of people 
# closeset to offests of the circle's size divided NUM_FINGERS.
FINGER_TABLE = []
# A list of commands that the user is allowed to use
COMMANDS = ['contains', 'insert', 'remove', 'disconnect', 'help']
# Port we are listening on
listeningPort = 1111

def recvAll(sock, numBytes):
    data = b''
    while (len(data) < numBytes):
        data += sock.recv(numBytes - len(data))
    return data

def listen(listener):
    #Create a listening socket to receive requests from peers
    listener.listen(4)
    running = True
    while running:
        threading.Thread(target=handleRequests, args=(listener.accept(),),daemon=True).start()


def handleRequests(conn):
    


# Returns us a hashed value of the string 
def getHashKey(value):
    key = hashlib.sha1(value.encode()).hexdigest()
    return key


# Finds the offsets of where your fingers should be
def getFingerOffsets(MY_ADDR):
    # maxHash is the highest value that the circle can store
    maxHash = "ffffffffffffffffffffffffffffffffffffffff"
    maxHash = int(maxHash, 16)
    offset = int(maxHash / (NUM_FINGERS + 1))
    # Get the key and turn it into a regular base 10 int
    key = hashlib.sha1(MY_ADDR.encode()).hexdigest()
    key = int(key, 16)
    # Add NUM_FINGERS hash values to a list and return it
    offsetList = []
    for i in range(NUM_FINGERS):
        if key + (offset * (i+1)) > maxHash:
            # For the wrap around here, I just subtracted the max
            # from the larger than max number
            offsetList.append( hex((key + (offset * (i+1))) - maxHash)[2:] )
        else:
            offsetList.append( hex(key + (offset * (i+1)))[2:] )
    return offsetList


# Finds out who we know that is closest to the key
def closestToKey(key):
    FINGER_TABLE.sort()
    for i in range(len(FINGER_TABLE) - 1):
        if key > FINGER_TABLE[i][0] and key < FINGER_TABLE[i+1][0]:
            return FINGER_TABLE[i][1]
    return FINGER_TABLE[-1][1]


# Helper function that tells us if we are the owner of the file
def containedLocal(searchString):
    fileKey = getHashKey(searchString)
    if MY_ADDR == SUCC_ADDR:
        if fileKey in getMyFileKeys():
            return True
        return False


# Finds who is the closest peer to the string we want to search by
def closestPeer(searchString):
    key = getHashKey(searchString)
    closest = closestToKey(key)
    if closest == MY_ADDR:
        return closest
    else:
        #network protocol
        #send clop and key to closest
        #get back node address
        #if closets == node address return nodeaddress
        #else repeat
        pass


# Stores a file in the DHT
def insert(searchString):
    key = getHashKey(searchString)
    storeAddr = closestPeer(searchString)
    if storeAddr == MY_ADDR:
        #store locally
        print("Storing {} locally.".format(searchString))
        shutil.copy(searchString, 'repository/{}'.format(key))
    else:
        #network protocol
        pass


# Removes a file from teh DHT if it's there
def remove(searchString):
    key = getHashKey(searchString)
    if containedLocal(searchString) == True:
        os.remove("repository/"+ key)
        print("Removing {} locally.".format(searchString))
    else:
        pass
        #TODO Add network protocal here


# Prints if the file is found or not
def contains(searchString):
    if containedLocal(searchString) == True:
        print("File {} exists.".format(searchString))
    elif True == False:
        # TODO Network stuff
        pass
    else:
        print("File {} NOT found.".format(searchString))


def disconnect():
    if MY_ADDR == SUCC_ADDR:
        print("Goodbye")
        exit(0)
    else:
        pass
    #TODO network stuff

# Function to call when the user wants to create their own system
def startNewSystem():
    global SUCC_ADDR
    global PRED_ADDR
    SUCC_ADDR = MY_ADDR
    PRED_ADDR = MY_ADDR
    fingers = getFingerOffsets(MY_ADDR)
    for i in range(NUM_FINGERS):
        FINGER_TABLE.append((fingers[i], MY_ADDR))
    for i in range(3):
        FINGER_TABLE.append((getHashKey(MY_ADDR), MY_ADDR))


# Function to call when the user is joining by another user
def joinSystem(IP, port):
    # Send CONN and myAddr to who you know
    print(IP + " " + str(port))
    joinSock = socket(AF_INET, SOCK_STREAM)
    joinSock.connect( (IP, port))
    conn = "CONN"
    joinSock.send(conn.encode())
    joinSock.send(MY_ADDR.encode())
    TF = joinSock.recv(1)
    if TF == "T":
        
    else:


# Returns a list of all the keys we own
def getMyFileKeys():
    fileKeys = os.listdir('./repository')    
    return fileKeys


# Function that prints out all available ways to use the system
def help():
    print('Here is a list of possible commands...')
    print('contains <file-name>')
    print('insert <file-name>')
    print('remove <file-name>')
    print('disconnect')
    print('help')


# Execution of main code begins here
if __name__ == '__main__':
    progname = argv[0]
    if len(argv) not in [1, 3]:
        print('Usage: {}')
        print('Usage: {} <IP> <PORT>')

    # Set up listener 
    listener = socket(AF_INET, SOCK_STREAM)
    listener.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    listener.bind(('', 0))
    listeningPort = listener.getsockname()[1]

    print(listeningPort)

    # Set my address
    ip = check_output(['hostname', '-I']).decode().rstrip()
    MY_ADDR = '{}:{}'.format(ip,listeningPort)

    # Check for repository to store files
    folder = Path('./repository')
    if not folder.exists():
        folder.mkdir(parents=True, exist_ok=True)

    if len(argv) == 1:
        startNewSystem()
    else:
        # Have to get values from person we know in system
        IP = argv[1]
        port = int(argv[2])
        joinSystem(IP, port)

    listenThread = threading.Thread(target=listen, args=(listener,),            daemon=False).start()


    # Main run loop
    running = True
    help()
    while running:
        line = input('> ')
        command = line.split()[0]
        command = command.lower()
        if command not in COMMANDS:
            continue
        if command == 'disconnect':
            disconnect()
        elif command == 'help':
            help()
        else:
            try:
                fileName = line.split()[1]
            except:
                print('Must specify a file name')
                continue
            if command == 'insert':
                insert(fileName)
            elif command == "remove":
                remove(fileName)
            elif command == "contains":
                contains(fileName)
