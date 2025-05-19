import os
# import sys
from threading import Thread
# import logging
from common import util

class Fsreplicator(Thread):
    def __init__(self, srcpath,destpath):
        Thread.__init__(self)
        self.destpath = destpath
        self.srcpath = srcpath
    
    def run(self) -> None:
        util.copy_directory(self.srcpath,self.destpath)
    

