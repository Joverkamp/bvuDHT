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

def sendAddr(addr, conn):
    sz = len(addr)
    conn.send(sz.to_bytes(4, byteorder="little", signed=False))
    conn.send(addr.encode())

def readFile(fileHash):
    fileBytes = []
    f = open("repository/{}".format(fileHash), "rb")
    byte = f.read(1)
    while byte:
        fileBytes.append(byte)
        byte = f.read(1)
    return fileBytes

def sendFile(fileHash, fileBytes, conn):
    sz = len(fileBytes)
    conn.send(fileHash.encode())
    conn.send(sz.to_bytes(4, byteorder="little", signed=False))
    for byte in fileBytes:
        conn.send(byte)

def filesTransfer(sock, connectorHash):    
    # Retreive files available for sending
    folder = Path("./repository")
    if not folder.exists():
        folder.mkdir(parents=True, exist_ok=True)
    # Retrieve our file hashes
    fileHashes = []
    for entry in folder.iterdir():
        if not entry.is_dir():
            fileHashes.append(entry.name)
    # Get number of files to send
    filesToSend = []
    succHash = getHashKey(SUCC_ADDR)

    # Find which files to transfer considering wrap around
    if succHash < connectorHash:
        for fileHash in fileHashes:
            if fileHash < succHash or fileHash > connectorHash:
                filesToSend.append(fileHash)
    else:
        for fileHash in fileHashes:
            if fileHash > connectorHash:
                filesToSend.append(fileHash)

    # Send number of files followed by each file following protocol
    sz = len(filesToSend)
    sock.send(sz.to_bytes(4, byteorder="little", signed=False))
    for fileHash in filesToSend:
        fileBytes = readFile(fileHash)
        sendFile(fileHash, fileBytes, sock)



def recvAll(sock, numBytes):
    data = b''
    while (len(data) < numBytes):
        data += sock.recv(numBytes - len(data))
    return data

def recvAddr(sock):
    data = recvAll(sock, 4)
    addrSize = int.from_bytes(data, byteorder="little", signed=False)
    data = recvAll(sock, addrSize)
    addr = data.decode()
    return addr

def listen(listener):
    #Create a listening socket to receive requests from peers
    listener.listen(4)
    running = True
    while running:
        threading.Thread(target=handleRequests, args=(listener.accept(),),daemon=True).start()


def handleRequests(connInfo):
    sock, connAddr = connInfo
    code  = recvAll(sock, 4).decode()
    #Protocol for incoming CONN
    if code == "CONN":
        connectorAddr = recvAddr(sock)
        connectorHash = getHashKey(connectorAddr)
        if closestToKey(connectorHash) == MY_ADDR:
            sock.send("T".encode())
            sendAddr(SUCC_ADDR, sock)
            filesTransfer(sock, connectorHash)
            confirm = recvAll(sock, 1).decode()
            if confirm == "T":
                #TODO
                print("Delete files")
        else:
            sock.send("F".encode())
            closest = getClosest(connectorHash)
            #TODO what do we send along with F
    elif code == "PRUP":
        print("Got prup req")
        global PRED_ADDR
        newPred = recvAddr(sock)
        PRED_ADDR = newPred
        sock.send("T".encode())
    else: 
        print("Got something else")


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
    joinSock = socket(AF_INET, SOCK_STREAM)
    joinSock.connect( (IP, port))
    conn = "CONN"
    joinSock.send(conn.encode())
    sendAddr(MY_ADDR, joinSock)
    
    TF = joinSock.recv(1)
    if TF == "T":
        pass   
    else:
        pass


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


    print("My key: {}".format(getHashKey(MY_ADDR)))


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

    listenThread = threading.Thread(target=listen, args=(listener,),daemon=False).start()


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
