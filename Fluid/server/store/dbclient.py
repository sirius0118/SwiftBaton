from common import codes
import etcd
import json
import logging

'''
    etcd storage:
        agent info: </agents/agentID:json(IP,Port)>
        container info: </containers/containerID:json(IP,Port)>
        node info: </nodes/nodeID:json(containerID)
'''
class DBClient(object):
    def __init__(self, config) -> None:
        server = config['dbserver']
        port = config['dbport']
        self.client = etcd.Client(host=server, port=int(port))
    
    def storeAgent(self, agentIP, agentPort, agentID):
        agentProp = dict()
        key = f"/agents/{agentID}"
        agentProp['ip'] = agentIP
        agentProp['port'] = agentPort
        self.client.write(key, json.dumps(agentProp))
        return codes.SUCCESS
    
    def getAllAgents(self):
        key = f"/agents"
        agents = self.client.read(key, recursive=True, sorted=True)
        agentMaps = dict()
        for child in agents.children:
            agentMaps[child.key] = json.loads(child.value)
        
        return (codes.SUCCESS, agentMaps)
    
    def getAgent(self, agentID):
        key = f"/agents/{agentID}"
        agentMeta = dict()
        rc = codes.SUCCESS

        try:
            agent = self.client.read(key)
        except etcd.EtcdKeyNotFound as err:
            logging.error("Agent {} not found".format(agentID)) 
            rc = codes.AGENT_NOT_FOUND
        else:
            agentMeta = json.loads(agent.value)

        return (rc, agentMeta)
    
    def storeMigration(self, srcAgentID, destAgentID, srcContainerID, destContainerID, 
                       port, ts_mem, bandwidth):
        key = f"/migrations/{srcAgentID}:{srcContainerID}-{destAgentID}:{destContainerID}"
        migrationData = dict()
        migrationData['port'] = port
        migrationData['ts_mem'] = ts_mem
        migrationData['bandwidth'] = bandwidth
        self.client.write(key, json.dumps(migrationData))
        return codes.SUCCESS

    def getMigration(self, srcAgentID, srcContainerID, destAgentID, destContainerID):
        key = f"/migrations/{srcAgentID}:{srcContainerID}-{destAgentID}:{destContainerID}"
        migrationData = dict()
        rc = codes.SUCCESS
        try:
            migrationData = json.loads(self.client.read(key).value)
        except etcd.EtcdKeyNotFound as err:
            logging.error(f"Migration {key} not found:{err}")
            rc = codes.MIGRATION_NOT_FOUND
        return (rc, migrationData)

    def updateStatus(self, conainerid, ts, total, curr, completed):
        key = "/status/{CONTAINER}".format(CONTAINER = conainerid)
        status = dict()
        started = False
        try:
            value = self.client.read(key)
        except etcd.EtcdKeyNotFound as err:
            logging.info("Update for new container") 
            started = True
            pass
        else:
            status = json.loads(value.value)
       
        if started:
            status["start"] = ts
            status["update"] = ""
            status["complete"] = ""
        elif not started and not completed:
            status["update"] = ts
        elif completed:
            status["complete"] = ts
            
        status["total"] = total
        status["curr"] = curr
        status["completed"] = completed
        if started:
            self.client.write(key, json.dumps(status))
        else:
            value.value = json.dumps(status)
            self.client.update(value)
        return codes.SUCCESS

    def getStatus(self, conainerid):
        key = "/status/{CONTAINER}".format(CONTAINER = conainerid)
        status = dict()
        rc = codes.SUCCESS
        try:
            result = self.client.read(key)
        except etcd.EtcdKeyNotFound as err:
            logging.error("Status {} not found".format(conainerid)) 
            rc = codes.AGENT_NOT_FOUND
        else:
            status = json.loads(result.value)
        return (rc, status)

    def getport(self, key):
        if key == "sync_port":
            value = 4567
        elif key == "port":
            value = 12345
        try:
            result = self.client.read(key).value
            self.client.write(key, value + 1)
        except etcd.EtcdKeyNotFound:
            self.client.write(key, value)
            result = value
        return result






