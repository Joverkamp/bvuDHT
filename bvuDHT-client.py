from subprocess import check_output
import shutil
from socket import *
import hashlib
from sys import argv, exit
from pathlib import Path
import threading
import os

###
'''                             #####
MAKE SURE TO DO THREAD LOCKING  #####
                                #####
'''
###


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
# Port we are listening on this will get overwritten
listeningPort = 1111

def printFingers():
    myKey = getHashKey(MY_ADDR)
    predKey = getHashKey(PRED_ADDR)
    succKey = getHashKey(SUCC_ADDR)
    print("My Address")
    print("   {}".format(MY_ADDR))
    print("   {}".format(myKey))
    print("Pred Address")
    print("   {}".format(PRED_ADDR))
    print("   {}".format(predKey))
    print("Succ Address")
    print("   {}".format(SUCC_ADDR))
    print("   {}".format(succKey))
    for finger in FINGER_TABLE:
        if finger[0] != myKey and finger[0] != predKey and finger[0] != succKey:
            print("Finger Address")
            print("   {}".format(finger[1]))
            print("   {}".format(finger[0]))           

def sendAddr(addr, sock):
    sz = len(addr)
    sock.send(sz.to_bytes(4, byteorder="little", signed=False))
    sock.send(addr.encode())

def readFile(fileHash):
    fileBytes = []
    f = open("repository/{}".format(fileHash), "rb")
    byte = f.read(1)
    while byte:
        fileBytes.append(byte)
        byte = f.read(1)
    return fileBytes

def sendFile(fileHash, fileBytes, sock):
    sz = len(fileBytes)
    sock.send(fileHash.encode())
    sock.send(sz.to_bytes(4, byteorder="little", signed=False))
    for byte in fileBytes:
        sock.send(byte)

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
        print("Got something else in handleRequests")


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


# Stores a file in the DHT
def insert(searchString):
    key = getHashKey(searchString)
    storeAddr = closestToKey(key)
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
    key = getHashKey(searchString)
    if containedLocal(key) == True:
        print("File {} exists.".format(searchString))
    else:
        askAddr = closestToKey(key)
        recvAddr = "1"
        while askAddr != recvAddr:
            askAddrSplit = askAddr.split(":")
            clopSock = socket(AF_INET, SOCK_STREAM)
            clopSock.connect( (askAddrSplit[0], int(askAddrSplit[1])))
            clopSock.send("CLOP".encode())
            clopSock.send(key.encode())
            recvAddr = recvAddr(clopSock)
        if askAddr == recvAddr:
            askAddrSplit = askAddr.split(":")
            contSock = socket(AF_INET, SOCK_STREAM)
            contSock.connect( (askAddrSplit[0], int(askAddrSplit[1])))
            contSock.send("CONT".encode())
            contSock.send(key.encode())
            TF = recvAll(contSock, 1).decode()
            if TF == "F":
                contains(searchString)
            TF = recvAll(contSock, 1).decode()
            if TF == "F":
                print("File {} NOT found.".format(searchString))
            else:
                print("File {} found.").format(searchString)

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
    global SUCC_ADDR
    joinSock = socket(AF_INET, SOCK_STREAM)
    joinSock.connect( (IP, port))
    # Basic start of connect where we send conn and addr
    conn = "CONN"
    joinSock.send(conn.encode())
    sendAddr(MY_ADDR, joinSock)
    # If true or false
    TF = joinSock.recv(1)
    if TF.decode() == "T":
        SUCC_ADDR = recvAddr(joinSock)
        print("SUCC_ADDR: " + SUCC_ADDR)
        # Get all the files we need to take over and put in repository
        numFiles = recvAll(joinSock, 4)
        numFiles = int.from_bytes(numFiles, byteorder="little", signed=False)
        for i in range(numFiles):
            key = recvAll(joinSock, 40)
            key = key.decode()
            sz = recvAll(joinSock, 4)
            sz = int.from_bytes(sz, byteorder="little", signed=False)
            data = recvAll(joinSock, sz)
            path = Path('./repository/' + key)
            with open(path, 'wb') as outf:
                outf.write(data)
        # Do Predecessor update stuff
        succ_list = SUCC_ADDR.split(":")
        newSuccSock = socket(AF_INET, SOCK_STREAM)
        newSuccSock.connect( (succ_list[0], int(succ_list[1])))
        prup = "PRUP"
        newSuccSock.send(prup.encode())
        sendAddr(MY_ADDR, newSuccSock)
        TF = newSuccSock.recv(1)
        TF = TF.decode()
        if TF == "T":
            # Send Final True to person you connected to in the beginning
            joinSock.send("T".encode())
            # Close both the sockets
            newSuccSock.close()
            joinSock.close()
    else:
        print("That was not the correct person to connect to.")
        print("They do not own the spcae you need to be inserted into.")
        # Close the join socket becesue the other side will too
        joinSock.close()
        # Do CLOP call to this person to see who it has changed to
        clopSock = socket(AF_INET, SOCK_STREAM)
        clopSock.connect( (IP, port) )
        clop = "CLOP"
        clopSock.send(clop.encode())
        myAddr = getHashKey(MY_ADDR)
        clopSock.send(myAddr.encode())
        newConn = recvAddr(clopSock)
        # Make sure to close the clop socket after this
        clopSock.close()
        # Call joinSystem again on a differnt peer now
        newConn = newConn.split(":")
        joinSystem(newConn[0], int(newConn[1]))


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

    print("listeningPort: " + str(listeningPort))

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

    listenThread = threading.Thread(target=listen, args=(listener,),daemon=False).start()

    print("My address as a hash:  " + getHashKey(MY_ADDR))
    print("My key: {}".format(getHashKey(MY_ADDR)))
    printFingers()

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
