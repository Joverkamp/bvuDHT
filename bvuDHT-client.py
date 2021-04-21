from subprocess import check_output
import shutil
from socket import *
import hashlib
from sys import argv
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


# Returns us a hashed value of the string 
def getHashKey(value):
    key = hashlib.sha1(value.encode()).hexdigest()
    return key


# Finds out who we know that is closest to the key
def closestToKey(key):
    #TODO account for wrap around
    #Put in for loop
    if key > getHashKey(MY_ADDR) and key < getHashKey(SUCC_ADDR):
        print('1 {}'.format(MY_ADDR))
        return MY_ADDR
    elif key > getHashKey(SUCC_ADDR) and key < getHashKey(FINGER_TABLE[0]):
        print('2 {}'.format(SUCC_ADDR))
        return SUCC_ADDR
    elif key > getHashKey(FINGER_TABLE[0]) and key < getHashKey(FINGER_TABLE[1]):
        print('3 {}'.format(FINGER_TABLE[0]))
        return FINGER_TABLE[0]
    elif key > getHashKey(FINGER_TABLE[1]) and key < getHashKey(FINGER_TABLE[2]):
        print('4 {}'.format(FINGER_TABLE[1]))
        return FINGER_TABLE[1]
    elif key > getHashKey(FINGER_TABLE[2]) and key < getHashKey(FINGER_TABLE[3]):
        print('5 {}'.format(FINGER_TABLE[2]))
        return FINGER_TABLE[2]
    elif key > getHashKey(FINGER_TABLE[3]) and key < getHashKey(PRED_ADDR):
        print('6 {}'.format(FINGER_TABLE[3]))
        return FINGER_TABLE[3]
    else:
        print('7 {}'.format(PRED_ADDR))
        return PRED_ADDR;


# Helper function that tells us if we are the owner of the file
def containedLocal(searchString):
    fileKey = getHashKey(searchString)
    
    # TODO May need to change this to reflect how we do the new finger table
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
        print("storing {} locally".format(searchString))
        shutil.copy(searchString, 'repository/{}'.format(key))
    else:
        #network protocol
        pass


# Function to call when the user wants to create their own system
def startNewSystem():
    SUCC_ADDR = MY_ADDR
    PRED_ADDR = MY_ADDR
    for i in range(NUM_FINGERS):
        FINGER_TABLE.append(MY_ADDR)


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
        pass

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
            pass
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
#            if not containedLocal(fileName):


