import os
from threading import Thread
from string import Template
import logging
import subprocess
import time
import json
import requests
import urllib.request, urllib.parse, urllib.error

RSYNC_REPO_CMD = Template("rsync -az root@$SERVER:$REMOTE_REPO $LOCAL_REPO")
COPY_CMD = Template("cp $NFS_MOUNT/$FILE_PATH $LOCAL_REPO/$FILE_PATH")
NOTIFY_COMPLETE_URL = Template("http://$SERVER/fulid/replication/$CONTAINER")
SHUTDOWN_SERVICE = Template("service $CONTAINER-$VOLUME stop")
SVC_FILEPATH = Template("/etc/init/$CONTAINER-$VOLUME")

# 这个类继承线程Thread类的作用就是为这个当前类提供线程类的方法，比如start，join等
class Replicator(Thread):
    def __init__(self, jobq, agentid, localrepo, sourehost, sourcepath, containerid, volumeid, server):
        Thread.__init__(self)
        self.jobq = jobq
        self.agentid = agentid
        self.localrepo = localrepo
        self.sourehost = sourehost
        self.sourcepath = sourcepath
        self.containerid = containerid
        self.volumeid = volumeid
        self.server = server
    
    # 更新etcd中的状态，本质上作用不大，这个状态仅仅用来查看，不参与实际代码作用
    
    def notify_server(self, totalCount, currCount, completed):
        url = NOTIFY_COMPLETE_URL.substitute(SERVER=self.server, CONTAINER=self.containerid)
        headers = {"content-Type": "application/json"}
        payload = dict()
        curtime = time.strftime("%Y-%m-%d %H:%M:%S")
        payload['timestamp'] = curtime
        payload['total'] = totalCount
        payload['current'] = currCount
        payload['volume'] = self.sourcepath
        payload['completed'] = completed

        try:
            logging.debug(f"Notify fluid server URL:{url}")
            _ = requests.post(url, data=json.dumps(payload), headers=headers)
        except requests.exceptions.ConnectionError as err:
            logging.error(f"Notify fluid server error:{err}")
    
    def graceful_stop(self):
        svcFile = SVC_FILEPATH.substitute(CONTAINER=self.containerid, VOLUME=self.volumeid)
        try:
            os.remove(svcFile)
        except OSError:
            pass
        cmd = SHUTDOWN_SERVICE.substitute(CONTAINER=self.containerid, VOLUME=self.volumeid)
        status, output = subprocess.getstatusoutput(cmd)
        logging.debug("Executing command %s"%(cmd))
        if status != 0:
           logging.error(f"Error stopping replication service for {self.containerid} {self.volumeid}: {output}")

    def run(self):
        totalCount = len(self.jobq)
        currCount = 0
        self.notify_server(totalCount, currCount, completed=False)

        while len(self.jobq) > 0:
            try:
                job = self.jobq.pop()
            except IndexError as err:
                logging.error(f"Error getting job from jobq: {err}")
                break
            else:
                currCount += 1
                sdatapath = os.path.join(self.sourcepath, job.lstrip('/'))
                tdatapath = os.path.join(self.localrepo, job.lstrip("/"))
                if not os.path.exists(os.path.dirname(tdatapath)):
                    os.makedirs(os.path.dirname(tdatapath))

                cmd = RSYNC_REPO_CMD.substitute(SERVER = self.sourcehost, REMOTE_REPO = sdatapath, LOCAL_REPO = tdatapath)
                logging.debug("Execute command: %s"%(cmd))
                status, output = subprocess.getstatusoutput(cmd)     
                if status != 0:
                    logging.error("Error copying file: %s"%(output))
                if(currCount%100 == 0):
                    self.notify_server(totalCount, currCount, completed = False)
        
        self.notify_server(totalCount, currCount, completed=True)
        # self.graceful_stop()
