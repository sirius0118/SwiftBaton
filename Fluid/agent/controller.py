import os
import logging
import subprocess
import json
from string import Template

from common import codes, util
from clients import dockerclient, fsclient
from criu.extra_config import ExtraConfig

START_LAZY_COPY_CMD = Template("python3 $PWD/replicator/manager.py --mondir $MON_DIR --nfsdir $NFS_DIR --srcdir $SRC_DIR \
                               --destdir &DEST_DIR --srchost $SRC_HOST --container $CONTAINER --server $FLUID_SERVER --volumeid $VOLUME_ID \
                               --agentid $AGENT_ID")

class RequesRouter():
    def __init__(self, config) -> None:
        self.containerClient = dockerclient.DockerClient(config=config['dockerurl'])
        self.fsClient = fsclient.FilesystemClient()
    
    def getAllContainers(self):
        return self.containerClient.listContainers()
    
    def getContainer(self, containerID):
        return self.containerClient.inspectContainer(containerID=containerID)
    
    def _createContainer(self, config):
        return self.containerClient.create(config)

    def _startContainer(self, containerId):
        return self.containerClient.start(containerId)

    def _stopContainer(self, containerId):
        return self.containerClient.stop(containerId)
    
    def _deleteContainer(self, containerId):
        return self.containerClient.remove(containerId)
    
    def _checkpointContainer(self, containerID, checkpointDir):
        return self.containerClient.checkpoint(containerID, checkpointDir)
    
    def _restoreContainer(self, containerID, checkpointDir):
        return self.containerClient.restore(containerID, checkpointDir)
        
    def handleContainerOp(self, payload, containerId):
        reqData = json.loads(payload)
        opcode = reqData["opcode"]
        if opcode == "create":
            return self._createContainer(reqData["params"])
        elif opcode ==  "start":
            return self._startContainer(containerId) 
        elif opcode ==  "stop": 
            return self._stopContainer(containerId)
        elif opcode == "delete":
            return self._deleteContainer(containerId)
        elif opcode == "checkpoint":
            # generate config
            meta = json.loads(self.getContainer(containerId)[1])
            pid = meta["State"]["Pid"]
            config = {"criu": {"lazy-pages": "yes", "address": reqData["address"], "port": reqData["port"],
                       "sync_addr": reqData["sync_addr"],  "sync_port": reqData["sync_port"]}}
            logging.debug("write the config")
            ec = ExtraConfig()
            logging.debug(f"mkdir 'migrate_{pid}'")
            ec.mkdir("/var/lib/criu/migrate_" + str(pid), 1)
            ec.writeConfig(f"/var/lib/criu/migrate_{pid}/config_ck.cfg", config)
            logging.debug(f"checkpoint container {containerId}")
            return self._checkpointContainer(containerId, "migrate_dir")
        elif opcode == "restore":
            # generate config
            meta = json.loads(self.getContainer(containerId)[1])
            pid = reqData["pid"]
            cid = meta["Id"]
            config = {"criu": {"lazy-pages": "yes", "sync_addr": reqData["sync_addr"], "sync_port": reqData["sync_port"],
                      "work_dir": reqData["work_dir"], "imgs_dir": reqData["imgs_dir"], "address": reqData["address"], "port": reqData["port"]}}
            ec = ExtraConfig()
            ec.mkdir(reqData["work_dir"], 1)
            ec.mkdir(f"/var/lib/docker/containers/{cid}/checkpoints/migrate_dir", 0)
            os.system(f"ln -s {reqData['work_dir']} /var/lib/docker/containers/{cid}/checkpoints/migrate_dir")
            ec.writeConfig(f"/var/lib/criu/migrate_{pid}/config_res.cfg", config)
            return self._restoreContainer(containerId, "migrate_dir")
        elif opcode == "pageclient":
            mata = json.loads(self.getContainer(containerId)[1])
            pid = mata["State"]["Pid"]
            img_dir = f"/var/lib/criu/migrate_{pid}/imgs_dir"
            cid = mata["Id"]
            work_dir = f"/run/containerd/io.containerd.runtime.v2.task/moby/{cid}/work"
            log_path = "/var/lib/criu/page-client.log"
            os.system(f"sudo criu lazy-pages -D {img_dir} -W {work_dir} --page-server --address {reqData['address']} --port {reqData['port']} -o {log_path} &")
        elif opcode == "setIPtables":
            path = "./clients/iptables.sh"
            for port in reqData["ports"]:
                cmd = f"sudo bash {path} tcp {port} {reqData['address']} {port}"
                print(f"executing command: {cmd}")
                os.system(cmd)
                cmd = f"sudo bash {path} udp {port} {reqData['address']} {port}"
                print(f"executing command: {cmd}")
                os.system(cmd)
        else:
            return codes.BAD_REQ
    
    def handleFSOp(self, configRaw):
        config = json.loads(configRaw)
        if config["role"] == "source" and config["opcode"] == "EXPORT_FS":
            return self.fsClient.nfsExport(config["params"])
        elif config["role"] == "target" and config["opcode"] == "IMPORT_FS":
            return self.fsClient.prepareTargetFS(config["params"])
        elif config["role"] == "source" and config["opcode"] == "CHECK_NFS":
            return self.fsClient.checkAndGetNFSMeta(config["params"])
        elif config["role"] == "target" and config["opcode"] == "IMPORT_NFS":
            return self.fsClient.mountNFSVolume(config["params"])
        elif config["role"] == "target" and config["opcode"] == "SSH_IMPORT_FS":
            return self.fsClient.mountSSHFSVolume(config["params"])
        elif config["role"] == "target" and config["opcode"] == "ROOTFS_COPY":
            return self.fsClient.rootFSCopy(config["params"])
        elif config["role"] == "target" and config["opcode"] == "REMOUNT":
            return self.fsClient.remountRootFS(config["params"])
        elif config["role"] == "target" and config["opcode"] == "SSHFS_MOUNT":
            return self.fsClient.sshfsMount(config["params"])
        elif config["role"] == "target" and config["opcode"] == "UNMOUNT":
            return self.fsClient.unmount(config["params"])
        elif config["role"] == "target" and config["opcode"] == "MIGRATE_VOLUME":
            return self.fsClient.migrateVolume(config["params"])
    
    def startReplication(self, containerId, volumeId, nodeId, fluidServer, payload):
        payloadJson = json.loads(payload)
        srchost = payloadJson["srchost"]
        volume = payloadJson["volume"]
        volcnt = payloadJson["volcnt"]
        mondir = util.getCOWDir(containerId, volcnt)
        lzcopydir = util.getLazyCopyDir(containerId, volcnt)        
        nfsdir = util.getNFSMountDir(containerId, volcnt)

        cmd = START_LAZY_COPY_CMD.substitute(PWD = os.getcwd(), MON_DIR = mondir, NFS_DIR = nfsdir, SRC_DIR = volume, \
            DEST_DIR = lzcopydir, SRC_HOST = srchost, CONTAINER = containerId,\
            FLUID_SERVER = fluidServer, VOLUMEID = volumeId, AGENTID = nodeId)
        
        print("执行命令:", cmd)
        # 这里没有直接执行这个cmd，而是把这个cmd定义为一个服务，将这个服务添加到机器上运行。这是为了防止机器停电？等情况？感觉没有这个必要吧。。。。
        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            logging.error("Error starting replication service %s: %s"%(status, output))
            return codes.FAILED
        
        logging.debug("Replication service started successfully.")

        # svcName = util.createReplSvc(containerId, volumeId, cmd)
        # rc, output = util.startSvc(svcName)
        # if rc != codes.SUCCESS :
        #     logging.error("Error starting replication service %s: %s"%(svcName, output))
        # else:
        #     logging.debug("Replication service %s started successfully"%(svcName))
        
        return status
    
    def doFailover(self,containerId):
        rc = self._stopContainer(containerId)
        if rc != codes.SUCCESS:
            return rc

        rc  = self.fsClient.failoverVolumes(containerId)
        if rc != codes.SUCCESS:
            return rc
        
        rc = self._startContainer(containerId)
        if rc != codes.SUCCESS:
            return rc

        return rc

    def getStatus(self, path):
        rc = codes.SUCCESS
        if os.path.exists(path):
            return (rc, {"status": 1})
        else:
            return (rc, {"status": 0})

    def getOP(self, config):
        config = json.loads(config)
        rc = codes.SUCCESS
        if config["opcode"] == "GET_FILE":
            with open(config["path"], "r") as f:
                data = f.read()
            if data[-1] == '\n':
                data = data[:-1]
            logging.debug(f"get file {config['path']} data: {data}")
            return (rc, {"value": data})
        else:
            return (codes.FAILED, None)

