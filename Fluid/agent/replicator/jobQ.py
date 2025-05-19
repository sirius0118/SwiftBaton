"""
    Queue data structure for jobs
"""

import os
import threading
import logging

class JobQ():
    def __init__(self):
        self.q = []
        self.size = 0

    def append(self, job):
        self.q.append(job)
        self.size+=1

    def isEmpty(self):
        return self.size

    def pop(self):
        #self.lock.acquire()
        job = self.q.pop()
        self.size-=1    
        #self.lock.release()
        return job
    
    def remove(self, job):
        #self.lock.acquire()
        try:
            self.q.remove(job)   
            self.size-=1
        except ValueError as e:
            # value is not present in the jobq
            pass
        #finally:
        #    self.lock.release()
    def count(self):
        return self.size

    def printQ(self):
	    for idx in range(self.size):
	        print((self.q[idx]))
