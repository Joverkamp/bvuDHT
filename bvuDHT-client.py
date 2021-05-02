from subprocess import check_output
import shutil
from socket import *
import hashlib
from sys import argv, exit
from pathlib import Path
import threading
import os


connLock = threading.Lock()
prupLock = threading.Lock()
discLock = threading.Lock()
getvLock = threading.Lock()
clopLock = threading.Lock()
instLock = threading.Lock()
rmveLock = threading.Lock()
contLock = threading.Lock()
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
FINGERS = []
# A list of commands that the user is allowed to use
COMMANDS = ['contains', 'insert', 'remove', 'disconnect', 'help', 'get']
# Port we are listening on this will get overwritten
listeningPort = 1111


def printFingers():
    myKey = getHashKey(MY_ADDR)
    predKey = getHashKey(PRED_ADDR)
    succKey = getHashKey(SUCC_ADDR)
    print("--------------------------")
    print("-      FINGER TABLE      -")
    print("--------------------------")
    print("My Address")
    print("   {}".format(MY_ADDR))
    print("   {}".format(myKey))
    print("Pred Address")
    print("   {}".format(PRED_ADDR))
    print("   {}".format(predKey))
    print("Succ Address")
    print("   {}".format(SUCC_ADDR))
    print("   {}".format(succKey))
    i = 0
    for finger in FINGER_TABLE:
        if finger[0] != myKey and finger[0] != predKey and finger[0] != succKey:
            print("Finger {}".format(i))
            print("   {}".format(finger[1]))
            print("   {}".format(finger[0]))
            i = i+1

# Protocol for sending addresses
# Send size and then address
def sendAddr(addr, sock):
    sz = len(addr)
    sock.send(sz.to_bytes(4, byteorder="little", signed=False))
    sock.send(addr.encode())

# read a file given its hash(file name) and produce an array of bytes
# readFrom specifies whether to read from your local files not in the DHT
# if passed "local" or else read from the "repository dir
def readFile(fileHash, readFrom):
    if readFrom == "local":
        f = open("{}".format(fileHash), "rb")
    else:
        f = open("repository/{}".format(fileHash), "rb")
    fileBytes = []
    byte = f.read(1)
    while byte:
        fileBytes.append(byte)
        byte = f.read(1)
    return fileBytes

# protocol for sending a file. Send number of bytes then then the key
# and then each byte
def sendFile(fileHash, fileBytes, sock):
    sz = len(fileBytes)
    sock.send(fileHash.encode())
    sock.send(sz.to_bytes(4, byteorder="little", signed=False))
    for byte in fileBytes:
        sock.send(byte)

# receive a given number of files following our protocol. WriteTo specifies 
#  whether to write locally or to our DHT repository
def recvFiles(numFiles, sock, writeTo):
    for i in range(numFiles):
        key = recvAll(sock, 40)
        key = key.decode()
        sz = recvAll(sock, 4)
        sz = int.from_bytes(sz, byteorder="little", signed=False)
        data = recvAll(sock, sz)
        if writeTo == "local":
            path = Path('./' + key)
        else:
            path = Path('./repository/' + key)
        with open(path, 'wb') as outf:
            outf.write(data)

# delete files from DHT repository given an array of file keys
def deleteFiles(toDelete):
    for f in toDelete:
        try:
            os.remove("repository/{}".format(f))
            print("Deleted {}".format(f))
            return True
        except: 
            print("File not deleted {}".format(f))
            return False


def filesTransfer(sock, connectorHash, Type):
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

    if Type == "conn":
        # Find which files to transfer considering wrap around
        if succHash < connectorHash:
            for fileHash in fileHashes:
                if fileHash < succHash or fileHash > connectorHash:
                    filesToSend.append(fileHash)
        # Find files when no wrap around
        else:
            for fileHash in fileHashes:
                if fileHash > connectorHash:
                    filesToSend.append(fileHash)
    else:
        # Add all files we own
        filesToSend = getMyFileKeys() 

    # Send number of files followed by each file following protocol
    sz = len(filesToSend)
    sock.send(sz.to_bytes(4, byteorder="little", signed=False))
    for fileHash in filesToSend:
        fileBytes = readFile(fileHash, "")
        sendFile(fileHash, fileBytes, sock)

    return filesToSend

# Receiving bytes until bytes = numBytes
def recvAll(sock, numBytes):
    data = b''
    while (len(data) < numBytes):
        data += sock.recv(numBytes - len(data))
        if len(data) == 0:
            break
    return data

# receive size of addr followed by the addr
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
    global PRED_ADDR
    global SUCC_ADDR
    #Protocol for incoming CONN refer to protocol file for details
    if code == "CONN":
        connLock.acquire()
        connectorAddr = recvAddr(sock)
        connectorHash = getHashKey(connectorAddr)
        if closestToKey(connectorHash) == MY_ADDR:
            sock.send("T".encode())
            sendAddr(SUCC_ADDR, sock)
            toDelete = filesTransfer(sock, connectorHash, "conn")
            confirm = recvAll(sock, 1).decode()
            if confirm == "T":
                updateFingers(connectorAddr)
                updateFingerTable()
                deleteFiles(toDelete)
        else:
            sock.send("F".encode())
            sock.close()
        connLock.release()
    #Protocol for incoming PRUP refer to protocol file for details
    elif code == "PRUP":
        prupLock.acquire()
        newPred = recvAddr(sock)
        PRED_ADDR = newPred
        if SUCC_ADDR == MY_ADDR:
            SUCC_ADDR = PRED_ADDR         
        updateFingers(PRED_ADDR)
        updateFingerTable()
        sock.send("T".encode())
        prupLock.release()
    #Protocol for incoming CLOP refer to protocol file for details
    elif code == "CLOP":
        clopLock.acquire()
        print("CLOP REQUEST...")
        key = recvAll(sock, 40).decode()
        closest = closestToKey(key)
        sendAddr(closest, sock)
        clopLock.release()
    elif code == "CONT":
        contLock.acquire()
        key = recvAll(sock, 40).decode()
        closest = closestToKey(key)
        if closest == MY_ADDR:
            sock.send("T".encode())
            if containedLocal(key) == True:
                sock.send("T".encode())
            else: 
                sock.send("F".encode())
        else: 
            sock.send("F".encode())
        contLock.release()
    #Protocol for incoming INST refer to protocol file for details
    elif code == "INST":
        instLock.acquire()
        key = recvAll(sock, 40).decode()
        closest = closestToKey(key)
        if closest == MY_ADDR:
            sock.send("T".encode())
            recvFiles(1, sock, "") 
            sock.send("T".encode())
        else:
            sock.send("F".encode())
        instLock.release()
    #Protocol for incoming RMVE refer to protocol file for details
    elif code == "RMVE":
        rmveLock.acquire()
        key = recvAll(sock, 40).decode()
        closest = closestToKey(key)
        if closest == MY_ADDR:
            sock.send("T".encode())
            if deleteFiles([key]) == True:
                sock.send("T".encode())
            else: 
                sock.send("F".encode())
        else:
            sock.send("F".encode())
        rmveLock.release()
    #Protocol for incoming GETV refer to protocol file for details
    elif code == "GETV":
        getvLock.acquire()
        key = recvAll(sock, 40).decode()
        closest = closestToKey(key)
        if closest == MY_ADDR:
            sock.send("T".encode())
            if containedLocal(key) == True:
                sock.send("T".encode())
                fileBytes = readFile(key,"")
                sendFile(key, fileBytes, sock)
            else:
                sock.send("F".encode())
        else:
            sock.send("F".encode())
        getvLock.release()
    #Protocol for incoming DISC refer to protocol file for details
    elif code == "DISC":
        discLock.acquire()
        newSucc = recvAddr(sock)
        sz = recvAll(sock, 4)
        sz = int.from_bytes(sz, byteorder="little", signed=False)
        recvFiles(sz, sock, "")
        if PRED_ADDR == SUCC_ADDR:
            sock.send("T".encode())
            resetFingerTable()
        elif prup(newSucc, sock) == True:
            sock.send("T".encode())
            removeFromFingerTable(SUCC_ADDR)
            SUCC_ADDR = newSucc
        discLock.release()
    else:
        pass

def prup(targetAddr, confirmSock):
    print("In prup func")
    succ_list = targetAddr.split(":")
    newSuccSock = socket(AF_INET, SOCK_STREAM)
    newSuccSock.connect( (succ_list[0], int(succ_list[1])))
    code = "PRUP"
    print("Sending prup to {}".format(targetAddr))
    newSuccSock.send(code.encode())
    sendAddr(MY_ADDR, newSuccSock)
    TF = newSuccSock.recv(1)
    TF = TF.decode()
    if TF == "T":
        # Send Final True to person you connected to in the beginning
        confirmSock.send("T".encode())
        print("sent t")
        # Close both the sockets
        newSuccSock.close()
        confirmSock.close()
        return True
    return False


def resetFingerTable():
    global FINGERS
    global PRED_ADDR
    global SUCC_ADDR
    FINGERS = []
    offsets = getFingerOffsets(MY_ADDR)
    for i in range(len(offsets)):
        FINGERS.append((offsets[i], MY_ADDR))
    PRED_ADDR = MY_ADDR
    SUCC_ADDR = MY_ADDR
    updateFingerTable()


def removeFromFingerTable(addr):
    global FINGERS
    for i in range(len(FINGERS)):
        if FINGERS[i][1] == addr:
            FINGERS[i] = (FINGERS[i][0], MY_ADDR)
    updateFingerTable()
    


def updateFingerTable():
    global FINGER_TABLE
    FINGER_TABLE = FINGERS
    FINGER_TABLE.append((getHashKey(MY_ADDR), MY_ADDR))
    FINGER_TABLE.append((getHashKey(SUCC_ADDR), SUCC_ADDR))
    FINGER_TABLE.append((getHashKey(PRED_ADDR), PRED_ADDR))
    FINGER_TABLE.sort()
    printFingers()

# Algorithm for replacing items in your fingers
# Walks through fingers and if the new peerAddr key is closer to 
# the offset, replace the finger value. Accounts for values outside
# the finger keyspace and wrap around.
def updateFingers(peerAddr):
    global FINGERS
    peerKey = getHashKey(peerAddr)
    for i in range(len(FINGERS)):
        currFingKey = getHashKey(FINGERS[i][1])
        # i = 1 and wrap around
        if i == 0 and FINGERS[-1][0] > FINGERS[i][0]:
            # is current finger value in keyspace
            if currFingKey > FINGERS[-1][0] or currFingKey < FINGERS[i][0]:
                if currFingKey > FINGERS[-1][0]:
                    if peerKey < FINGERS[i][0] or peerKey > currFingKey:
                        FINGERS[i] = (FINGERS[i][0], peerAddr)
                elif peerKey > currFingKey and peerKey < FINGERS[i][0]:
                    FINGERS[i] = (FINGERS[i][0], peerAddr)
            elif peerKey > currFingKey or peerKey < FINGERS[i][0]:
                FINGERS[i] = (FINGERS[i][0], peerAddr)
        # i != 1 and wrap around        
        elif i > 0 and FINGERS[i-1][0] > FINGERS[i][0]:
            # is current finger value in keyspace
            if currFingKey > FINGERS[i-1][0] or currFingKey < FINGERS[i][0]:
                if currFingKey > FINGERS[i-1][0]:
                    if peerKey < FINGERS[i][0] or peerKey > currFingKey:
                        FINGERS[i] = (FINGERS[i][0], peerAddr)
                elif peerKey > currFingKey and peerKey < FINGERS[i][0]:
                    FINGERS[i] = (FINGERS[i][0], peerAddr)
            elif peerKey > currFingKey or peerKey < FINGERS[i][0]:
                FINGERS[i] = (FINGERS[i][0], peerAddr)
        # any i no wrap around
        else:
            # is current finger value in keyspace
            if currFingKey < FINGERS[i][0] and currFingKey > FINGERS[i-1][0]:
                if peerKey < FINGERS[i][0] and peerKey > currFingKey:
                    FINGERS[i] = (FINGERS[i][0], peerAddr)
            else:
                if currFingKey > FINGERS[i][0]:
                    if peerKey > currFingKey or peerKey < FINGERS[i][0]:
                        FINGERS[i] = (FINGERS[i][0], peerAddr)
                else:
                    if peerKey > currFingKey and peerKey < FINGERS[i][0]:
                        FINGERS[i] = (FINGERS[i][0], peerAddr)


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
            off = hex((key + (offset * (i+1))) - maxHash)[2:]
            if len(off) < 40:
                off = off + "0"
            offsetList.append(off)
        else:
            off = hex(key + (offset * (i+1)))[2:]
            if len(off) < 40:
                off = off + "0"
            offsetList.append(off)
    return offsetList


def closestNow(Addr, key):
    if Addr == MY_ADDR:
        return Addr
    askAddr = Addr
    recvAddress = "1"
    while askAddr != recvAddress:
        askAddrSplit = askAddr.split(":")
        clopSock = socket(AF_INET, SOCK_STREAM)
        clopSock.connect( (askAddrSplit[0], int(askAddrSplit[1])))
        clopSock.send("CLOP".encode())
        clopSock.send(key.encode())
        recvAddress = recvAddr(clopSock)
        clopSock.close()
        if recvAddress == askAddr:
            return recvAddress   
        askAddr = recvAddress
    return recvAddress            
                                  
                                  
def setFingers(Addr):             
    global FINGERS         
    FINGERS = []
    offsets = getFingerOffsets(MY_ADDR)
    for finger in offsets:
        recvAddress = closestNow(Addr, finger)
        FINGERS.append((finger, recvAddress))
    updateFingerTable()


# Finds out who we know that is closest to the key
def closestToKey(key):
    for i in range(len(FINGER_TABLE) - 1):
        if key > FINGER_TABLE[i][0] and key < FINGER_TABLE[i+1][0]:
            return FINGER_TABLE[i][1]
    return FINGER_TABLE[-1][1]


# Helper function that tells us if we are the owner of the file
def containedLocal(key):
    if key in getMyFileKeys():
        return True
    return False


# Stores a file in the DHT
def insert(searchString):
    fileKeys = os.listdir('.')    
    if searchString not in fileKeys:
        print("You do not own that file.")
        return 
    key = getHashKey(searchString)
    storeAddr = closestToKey(key)
    if storeAddr == MY_ADDR:
        # Store locally
        print("Storing {} locally.".format(searchString))
        shutil.copy(searchString, 'repository/{}'.format(key))
    else:
        closest = closestNow(storeAddr,key)
        closest = closest.split(":")
        instSock = socket(AF_INET, SOCK_STREAM)
        instSock.connect( (closest[0], int(closest[1])))
        instSock.send("INST".encode())
        instSock.send(key.encode())
        TF = recvAll(instSock, 1).decode()
        if TF == "F":
            insert(searchString)
        else:
            fileBytes = readFile(searchString, "local")
            sendFile(key, fileBytes, instSock)
            TF = recvAll(instSock, 1).decode()
            if TF == "T":
                instSock.close()
                print("File {} successfully inserted.".format(searchString))
            else:
                insert(searchString)


# Grabs the file and stores it in your local repository 
def getv(searchString):
    print("entered function")
    key = getHashKey(searchString)
    if containedLocal(key) == True:
        print("Copied file {} from repository to your local directory.".format(searchString))
        shutil.copy('repository/{}'.format(key), key)
    else:
        if contains(searchString):
            print("it is a file")
            storeAddr = closestToKey(key)
            closest = closestNow(storeAddr,key)
            closest = closest.split(":")
            getSock = socket(AF_INET, SOCK_STREAM)
            getSock.connect( (closest[0], int(closest[1])))
            getSock.send("GETV".encode())
            getSock.send(key.encode())
            TF = recvAll(getSock, 1).decode()
            if TF == "F":
                get(searchString)
            else:
                TF = recvAll(getSock, 1).decode()
                if TF == "F":
                    print("That file, {} does not exist anymore.".format(searchString))
                else:
                    recvFiles(1, getSock, "local")
                    print("Received {}.".format(searchString))
        else:
            print("That file does not exist.")


# Removes a file from teh DHT if it's there
def remove(searchString):
    key = getHashKey(searchString)
    if containedLocal(key) == True:
        os.remove("repository/"+ key)
        print("Removing {} locally.".format(searchString))
    else:
        if contains(searchString):
            storeAddr = closestToKey(key)
            closest = closestNow(storeAddr,key)
            closest = closest.split(":")
            rmveSock = socket(AF_INET, SOCK_STREAM)
            rmveSock.connect( (closest[0], int(closest[1])))
            rmveSock.send("RMVE".encode())
            rmveSock.send(key.encode())
            TF = recvAll(rmveSock, 1).decode()
            if TF == "F":
                remove(searchString)
            else:
                TF = recvAll(rmveSock, 1).decode()
                if TF == "F":
                    print("File {} is already gone.".format(searchString))
                else:
                    print("File {} deleted.".format(searchString))
        else:
            print("That file does not exist within the system.")


# Prints if the file is found or not
def contains(searchString):
    key = getHashKey(searchString)
    if containedLocal(key) == True:
        print("File {} exists.".format(searchString))
        return True
    else:
        askAddr = closestToKey(key)
        recvAddress = "1"
        while askAddr != recvAddress:
            askAddrSplit = askAddr.split(":")
            clopSock = socket(AF_INET, SOCK_STREAM)
            clopSock.connect( (askAddrSplit[0], int(askAddrSplit[1])))
            clopSock.send("CLOP".encode())
            clopSock.send(key.encode())
            recvAddress = recvAddr(clopSock)
        if askAddr == recvAddress:
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
                return False
            else:
                print("File {} found.".format(searchString))
                return True


def disconnect():
    # Disconnect fro it it's a one man system
    if MY_ADDR == SUCC_ADDR:
        print("Goodbye")
        exit(0)
#    if SUCC_ADDR == PRED_ADDR:

    # Disconnect over the network
    else:
        # Get our hash key to be used as a dummy variable
        myHash = getHashKey(MY_ADDR)
        # Get predecessors address connect to them and start sending stuff
        predAddr = PRED_ADDR.split(":")
        predSock = socket(AF_INET, SOCK_STREAM)
        predSock.connect( (predAddr[0], int(predAddr[1])))
        predSock.send("DISC".encode())
        sendAddr(SUCC_ADDR, predSock)
        # Send all the files we own to the predecessor
        toSend = filesTransfer(predSock, myHash, "disc")
        # Receive the T from the Predecessor so that you know to quit
        TF = recvAll(predSock, 1).decode()
        if TF == "T":
            predSock.close()
            print("Goodbye")


# Function to call when the user wants to create their own system
def startNewSystem():
    global SUCC_ADDR
    global PRED_ADDR
    global FINGER_TABLE
    global FINGERS
    SUCC_ADDR = MY_ADDR
    PRED_ADDR = MY_ADDR
    fingers = getFingerOffsets(MY_ADDR)
    for i in range(NUM_FINGERS):
        FINGER_TABLE.append((fingers[i], MY_ADDR))
        FINGERS.append((fingers[i], MY_ADDR))
    for i in range(3):
        FINGER_TABLE.append((getHashKey(MY_ADDR), MY_ADDR))
    FINGER_TABLE.sort()
    FINGERS.sort()


# Function to call when the user is joining by another user
def joinSystem(IP, port):
    global SUCC_ADDR
    global PRED_ADDR
    global FINGERS
    joinSock = socket(AF_INET, SOCK_STREAM)
    joinSock.connect( (IP, port))
    # Basic start of connect where we send conn and addr
    conn = "CONN"
    joinSock.send(conn.encode())
    sendAddr(MY_ADDR, joinSock)
    # If true or false
    TF = joinSock.recv(1)
    if TF.decode() == "T":
        # Set pred and succ addr and fingers
        PRED_ADDR = "{}:{}".format(IP, port)
        SUCC_ADDR = recvAddr(joinSock)
        
        FINGER_TABLE = []
        offsets = getFingerOffsets(MY_ADDR)
        for finger in offsets:
            FINGERS.append((finger, MY_ADDR))

        updateFingers(PRED_ADDR)
        updateFingers(SUCC_ADDR)
        updateFingerTable()
        
        if PRED_ADDR != SUCC_ADDR:
            setFingers(PRED_ADDR)

        # Get all the files we need to take over and put in repository
        numFiles = recvAll(joinSock, 4)
        numFiles = int.from_bytes(numFiles, byteorder="little", signed=False)
        recvFiles(numFiles, joinSock, "")
        # Do Predecessor update stuff
        prup(SUCC_ADDR, joinSock)
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
    print('get <file-name>')
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
    else:
        shutil.rmtree(folder)
        folder.mkdir(parents=True, exist_ok=True)
        
    
    if len(argv) == 1:
        startNewSystem()
    else:
        # Have to get values from person we know in system
        IP = argv[1]
        port = int(argv[2])
        joinSystem(IP, port)

    listenThread = threading.Thread(target=listen, args=(listener,),daemon=True).start()

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
            print("That is not a valid command.")
            help()
            continue
        if command == 'disconnect':
            disconnect()
            running = False
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
            elif command == "get":
                getv(fileName)
