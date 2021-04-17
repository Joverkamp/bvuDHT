from socket import *
from sys import argv
from pathlib import Path
import threading
import os


if __name__ == "__main__":
    progname = argv[0]
    if len(argv) not in [1, 3]:
        print("Usage: {}")
        print("Usage: {} <IP> <PORT>")

    #set up listener

    if len(argv) == 1:
        pass
    else:
        pass

    running = True
    while running:
        #take commands

