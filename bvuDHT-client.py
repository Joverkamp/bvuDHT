from subprocess import check_output
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
    if key > MY_ADDER.getHashKey() and key < SUCC_ADDR.getHashKey:
        return MY_ADDR
    elif key > SUCC_ADDER.getHashKey() and key < FINGER_TABLE[0].getHashKey():
        return SUCC_ADDR
    elif key > FINGER_TABLE[0].getHashKey() and key < FINGER_TABLE[1].getHashKey():
        return FINGER_TABLE[0]
    elif key > FINGER_TABLE[1].getHashKey() and key < FINGER_TABLE[2].getHashKey():
        return FINGER_TABLE[1]
    elif key > FINGER_TABLE[2].getHashKey() and key < FINGER_TABLE[3].getHashKey():
        return FINGER_TABLE[2]
    elif key > FINGER_TABLE[3].getHashKey() and key < PRED_ADDR.getHashKey():
        return FINGER_TABLE[3] 
    else:
        return PRED_ADDR;


def contains(fileName):
    fileKey = getHashKey(fileName)
    
    if MY_ADDR == SUCC_ADDR:
        if fileKey in getMyFileKeys():
            return True
        return False



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
        if command[0] not in COMMANDS:
            continue
        if command.lower() == 'disconnect':
            pass
        elif command.lower() == 'help':
            help()
        else:
            try:
                fileName = line.split()[1]
            except:
                print('Must specify a file name')
                continue
            if not contains(fileName):


