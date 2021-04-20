from subprocess import check_output
import shutil
from socket import *
import hashlib
from sys import argv
from pathlib import Path
import threading
import os

MY_ADDR = ''
SUCC_ADDR = ''
PRED_ADDR = ''
NUM_FINGERS = 4
FINGER_TABLE = []
COMMANDS = ['contains', 'insert', 'remove', 'disconnect', 'help']


def getHashKey(value):
    key = hashlib.sha1(value.encode()).hexdigest()
    return key


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


def containedLocal(searchString):
    fileKey = getHashKey(searchString)
    
    if MY_ADDR == SUCC_ADDR:
        if fileKey in getMyFileKeys():
            return True
        return False


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

def startNewSystem():
    SUCC_ADDR = MY_ADDR
    PRED_ADDR = MY_ADDR
    for i in range(NUM_FINGERS):
        FINGER_TABLE.append(MY_ADDR)

def getMyFileKeys():
    fileKeys = os.listdir('./repository')    
    return fileKeys


def help():
    print('Here is a list of possible commands...')
    print('contains <file-name>')
    print('insert <file-name>')
    print('remove <file-name>')
    print('disconnect')
    print('help')



if __name__ == '__main__':
    progname = argv[0]
    if len(argv) not in [1, 3]:
        print('Usage: {}')
        print('Usage: {} <IP> <PORT>')

    #set up listener 
    listener = socket(AF_INET, SOCK_STREAM)
    listener.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    listener.bind(('', 0))
    listeningPort = listener.getsockname()[1]

    #set my address
    ip = check_output(['hostname', '-I']).decode().rstrip()
    MY_ADDR = '{}:{}'.format(ip,listeningPort)

    folder = Path('./repository')
    if not folder.exists():
        folder.mkdir(parents=True, exist_ok=True)

    if len(argv) == 1:
        startNewSystem()
    else:
        # have to get values from person we know in system
        pass


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


