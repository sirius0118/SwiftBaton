import json
from string import Template
import requests
import time
import logging
import time


import common.codes as codes
from store import dbclient
import restClient as rclient

GET_CONTAINERS = Template("http://$HOST:$PORT/containers")
DOCKER_HOME_DIR = '/var/lib/docker'

class RequestHandler():
    def __init__(self, config):
        self.dbclient = dbclient.DBClient(config) 

    def register(self, agent):
        agentCfg = json.loads(agent)    
        agentip = agentCfg["ip"]
        agentport = agentCfg["port"]
        agentid = agentCfg["id"]
        return self.dbclient.storeAgent(agentip, agentport, agentid)
   

    def __get_agents(self):
        _, agentList = self.dbclient.getAllAgents()
        return agentList      

    def getAllContainers(self):
        agentList = self.__get_agents()
        containerMap = dict()
        rc = codes.SUCCESS 
        for agent in agentList:
            agentip = str(agentList[agent]["ip"])
            agentport = int(agentList[agent]["port"])
            clientUrl = GET_CONTAINERS.substitute(HOST = agentip, PORT = agentport)
            headers = {"content-type": "application/json"}
            payload = dict()
            try:
                resp = requests.get(clientUrl, data=json.dumps(payload), headers=headers)
            except requests.exceptions.ConnectionError as e:
                print(f"Can not connect to cargo agent at: {e}")
                logging.error(f"Can not connect to cargo agent at: {e}")
                rc = codes.FAILED
            else:
                if resp.status_code == codes.herror(codes.SUCCESS):
                    containerMap[agent] = json.loads(resp.content)   

        return (rc, json.dumps(containerMap))

    def __get_rootfs(self, containerMeta, type):
        if type == 'merged':
            return containerMeta['GraphDriver']['Data']['MergedDir']
        if type == 'upper':
            return containerMeta['GraphDriver']['Data']['UpperDir']
        if type == 'work':
            return containerMeta['GraphDriver']['Data']['WorkDir']
        if type == 'lower':
            return containerMeta['GraphDriver']['Data']['LowerDir']
            
    #the core logic of migrate in apiserver
    def migrate(self, migrateReq):
        rc = codes.SUCCESS
        try:
            # get args
            source = migrateReq["source"]
            target = migrateReq["target"]
            containerName = migrateReq["container"]
            migRootfs = migrateReq.get("rootfs", False)
        except KeyError as err:
            logging.error(f"Invalid request: {err}") 
            rc  = codes.INVALID_REQ
            return rc
        
        # get source/target agent meta
        rc, sourceAgent = self.dbclient.getAgent(source)
        if rc != codes.SUCCESS:
            return rc
        
        rc, targetAgent = self.dbclient.getAgent(target)
        if rc !=  codes.SUCCESS:
            return rc

        # get container meta from source 
        rc, containerMeta = rclient.inspectContainer(sourceAgent["ip"], sourceAgent["port"], containerName)
        if rc != codes.SUCCESS:
            return rc

        # update start time in db
        mounts = containerMeta.get("Mounts", [])
        if len(mounts) == 0:
            logging.info("No data volumes found for container {}".format(containerName))
        volcnt = 1
        # print(containerMeta)
        rc = rclient.createContainer(targetAgent["ip"], targetAgent["port"], containerMeta)
        print("server rc:", rc)
        if rc != codes.SUCCESS: 
            logging.error("Error starting container on target {}".format(targetAgent["ip"]))
            return rc
        rc, newContainerMeta = rclient.inspectContainer(targetAgent["ip"], targetAgent["port"], containerName)
        if rc != codes.SUCCESS:
            return rc
        merged_init=self.__get_rootfs(newContainerMeta, 'lower').split(':')[0]
        if migRootfs:
            user="root"
            rc = rclient.sshImportVolume(targetAgent["ip"], targetAgent["port"], user, sourceAgent["ip"],
                                     self.__get_rootfs(containerMeta, 'merged'), containerName, volcnt, merged_init,True)
            if rc != codes.SUCCESS:
                return rc
        

        # step0: get sync_port, port from etcd_db
        sync_port = self.dbclient.getport("sync_port")
        port = self.dbclient.getport("port")

        # step1: post-copy container here
        config = {"address": "0.0.0.0", "port": port, 
                  "sync_addr": targetAgent["ip"], "sync_port": sync_port}
        rc = rclient.checkpointContainer(sourceAgent["ip"], sourceAgent["port"], 
                                         containerName, config)
        if rc != codes.SUCCESS: 
            logging.error("Error checkpoint container on source {}".format(sourceAgent["ip"]))
            return rc
        else:
            logging.debug("checkpoint container success")

        # step2: share imgs_dir by sshfs
        time.sleep(1)
        logging.debug("start step2")
        pid = containerMeta["State"]["Pid"]
        logging.debug(f"get the value of pid{pid}")
        rc, msg = rclient.getFile(sourceAgent["ip"], sourceAgent["port"],
                                   f"/var/lib/criu/migrate_{pid}/tmpdir.txt")
        tmp_dir = msg["value"]
        logging.debug(f"get the value of tmp_dir{tmp_dir}")
        imgs_dir = f"/var/lib/criu/migrate_{pid}/imgs_dir"
        rc = rclient.sshfsMount(targetAgent["ip"], targetAgent["port"],
                                 user, sourceAgent["ip"], tmp_dir, imgs_dir)

        
        
        
        # step3: restore container here
        work_dir = f"/var/lib/criu/migrate_{pid}/work_dir"
        config = {"imgs_dir": imgs_dir, "work_dir": work_dir, "address": sourceAgent["ip"], "port": port,
                  "sync_addr": sourceAgent["ip"], "sync_port": sync_port, "pid": pid}
        rc = rclient.restoreContainer(targetAgent["ip"], targetAgent["port"], 
                                      containerName, config)
        print("restore container", rc)
        if rc != codes.SUCCESS: 
            logging.error("Error restore container on target {}".format(targetAgent["ip"]))
            return rc
        # step4: set iptables rules to forward traffic
        while True:
            path = imgs_dir + '/stop'
            path = path.replace('/','-')
            rc, status = rclient.getMigrateStatus(targetAgent["ip"], targetAgent["port"], path)
            if status["status"] == 1:
                print("container stopped")
                break
            time.sleep(0.01)
        # print()
        # print(containerMeta)
        # print()
        # print(newContainerMeta)
        # print()
        # print(type(containerMeta))
        # print(type(newContainerMeta))
        # print()
        print(f"start migrate volume {containerMeta['Mounts'][0]['Source']} -> {newContainerMeta['Mounts'][0]['Source']}")
        rclient.migrateVolume(targetAgent["ip"], targetAgent["port"],containerName,user, sourceAgent["ip"], containerMeta['Mounts'][0]["Source"],newContainerMeta['Mounts'][0]["Source"],volcnt)
        # step2.5: copy fs 
        # start = time.perf_counter()
        # # 待测代码
        # rc = rclient.rootFSCopy(targetAgent["ip"], targetAgent["port"], containerName, volcnt, True)
        # if rc != codes.SUCCESS:
        #     return rc
        # #此处紧接着执行remount
        # rc = rclient.remountInitLayer(targetAgent["ip"], targetAgent["port"], containerName, volcnt,merged_init, True)
        # if rc != codes.SUCCESS:
        #     return rc
        # end = time.perf_counter()
        # print(f"FS copy耗时: {(end - start) * 1000:.3f}毫秒")  # 转换为毫秒
        PortBindings = containerMeta["HostConfig"]["PortBindings"]
        ports = []
        for key in PortBindings:
            if PortBindings[key][0]["HostPort"] not in ports:
                ports.append(PortBindings[key][0]["HostPort"])
        config = {"address": targetAgent["ip"], "ports": ports}
        rclient.setIPtables(sourceAgent["ip"], sourceAgent["port"], containerName, config)

        time.sleep(1000000)
        # step5: remove sshfs mount
        while True:
            rc, status = rclient.getMigrateStatus(targetAgent["ip"], targetAgent["port"], work_dir+'/ready')
            if status["status"] == 1:
                print("container ready")
                break
            time.sleep(0.01)
        rclient.Unmount(targetAgent["ip"], targetAgent["port"], imgs_dir)
        
        if migRootfs:
            print("start rootfs copy")
            rc = rclient.rootFSCopy(targetAgent["ip"], targetAgent["port"], containerName, volcnt, True)
            if rc != codes.SUCCESS:
                return rc
            #此处紧接着执行remount
            rc = rclient.remountInitLayer(targetAgent["ip"], targetAgent["port"], containerName, volcnt,merged_init, True)
            if rc != codes.SUCCESS:
                return rc
            # TODO: 源端rootFS文件是否需要清理
        
        # step6: start page-client in target machine
        print("Start page client.\n")
        rc, status = rclient.startPageClient(targetAgent["ip"], targetAgent["port"], containerName, config)
        if rc != codes.SUCCESS:
            return rc

        return codes.SUCCESS
        
    
    def updateStatus(self, container, payload):
        payloadJson = json.loads(payload)
        total = payloadJson["total"]
        current = payloadJson["current"]
        timestamp = payloadJson["timestamp"]
        completed = payloadJson["completed"]

        self.dbclient.updateStatus(container, timestamp, total, current, completed)
        return codes.SUCCESS

    def getStatus(self, container):
        rc, status = self.dbclient.getStatus(container)
        if rc != codes.SUCCESS:
            logging.error("Container status not found")
            return rc, ""
        else:
            return rc, json.dumps(status)

    def doFailover(self, nodeid, container):
        rc, agentMeta = self.dbclient.getAgent(nodeid)
        if rc != codes.SUCCESS:
            logging.error("Agent not found")
            return rc
        agentip = str(agentMeta["ip"])
        agentport = int(agentMeta["port"])
        rc = rclient.failover(agentip, agentport, container)
        return rc 

