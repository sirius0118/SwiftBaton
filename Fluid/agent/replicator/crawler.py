import os
import sys
from threading import Thread
import logging

class Crawler(Thread):
    def __init__(self, dirpath, jobQ):
        Thread.__init__(self)
        self.dirpath = dirpath
        self.jobQ = jobQ
    
    def run(self) -> None:
        try:
            for root, dirs, files in os.walk(self.dirpath):
                for f in files:
                    try:
                        fpath = str(os.path.join(root, f))
                        self.jobQ.append(fpath.split(self.dirpath)[1])
                    except UnicodeDecodeError as err:
                        logging.error(err)
        except Exception as err:
            (type, value, tb) = sys.exc_info()
            logging.error(f"Unhandled exception: {type}, {value}, {tb}")
            sys.exit(1)

