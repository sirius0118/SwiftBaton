import sys
from threading import Thread
from multiprocessing import Process, Manager
import os
from inotify_simple import INotify, flags
import select
import inotify
import inotify.constants


class Monitor(Thread):
    def __init__(self, dirpath, jobq):
        Thread.__init__(self)
        if dirpath.endswith('/'):
            self.mondir = dirpath
        else:
            self.mondir = dirpath + '/'
        self.jobq = jobq
    
    def run(self):
        w = INotify()
        try:
            w.add_watch(self.mondir, inotify.IN_CREATE)
        except OSError as err:
            print(f"{err.filename}: {err.strerror}", file=sys.stderr)
        
        fd = w.fileno()
        poll = select.poll()
        poll.register(fd, select.POLLIN)

        timeout = None
        
        while self.jobq.count() > 0:
            events = poll.poll(timeout)
            for event in w.read():
                fullpath = os.path.join(self.mondir, event.name)
                print(f"File changed:{fullpath}")
                try:
                    self.jobq.remove(event.name)
                except ValueError:
                    pass
            if not events:
                timeout = 10
            else:
                timeout = None
            
