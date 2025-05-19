import requests
import logging
import json
from string import Template
import hashlib

from common import codes

OPERATE_CONTAINER = Template("http://$HOST:$PORT/container/$NAME")
EXPORT_FS = Template("http://$HOST:$PORT/fs")
GREP_EXPORT = Template("cat /etc/export | grep $DIR")
LAZY_COPY = Template("http://$HOST:$PORT/replication/$CONTAINER/$VOLUME")
FAILOVER_CONTAINER = Template("http://$HOST:$PORT/failover/$CONTAINER")
GET_STATUS = Template("http://$HOST:$PORT/status/$PATH")
NODE_OP = Template("http://$HOST:$PORT/nodeop")
HEADERS = {"content-type": "application/json"}
ERR_FMT = "{}: Can not connect to fluid agent at: {}"

def inspectContainer(host, port, container):
    url = OPERATE_CONTAINER.substitute(HOST=host, PORT=port, NAME=container)

    containerMeta = dict()
    rc = codes.SUCCESS
    try:
        resp = requests.get(url, headers=HEADERS)
    except requests.exceptions.ConnectionError as err:
        logging.error(ERR_FMT.format(err, host))
    else:
        if resp.status_code == codes.herror(codes.SUCCESS):
            containerMeta = json.loads(resp.content)
    return rc, containerMeta

def exportVolume(host, port, exportpath):
    clientUrl = EXPORT_FS.substitute(HOST = host, PORT = port)
    params = {"exportPath": exportpath}
    payload = {"role": "source", "opcode": "EXPORT_FS", "params": params}
    rc = codes.SUCCESS
    try:
        resp = requests.post(clientUrl, data=json.dumps(payload), headers=HEADERS)
    except requests.exceptions.ConnectionError as e:
        logging.error(ERR_FMT.format(e, host))
        rc = codes.FAILED
    else:
        rc = resp.status_code
    return codes.perror(rc)

def importVolume(host, port, source, path, container, volcnt, isroot = False):
    clientUrl = EXPORT_FS.substitute(HOST = host, PORT = port)
    params = {"sourceHost": source, "exportPath": path, "container": container,
              "volcnt": volcnt, "isroot": isroot}
    payload = {"role": "target", "opcode": "IMPORT_FS", "params": params}

    rc = codes.SUCCESS
    try:
        resp = requests.post(clientUrl, data=json.dumps(payload), headers=HEADERS)
    except requests.exceptions.ConnectionError as e:
        logging.error(ERR_FMT.format(e, host))
        rc = codes.FAILED
    else:
        rc = resp.status_code

    return codes.perror(rc)    

# volcnt is counter used to be part of filename created
def sshImportVolume(host, port, user, source, path, container, volcnt, initlower,isroot = False):
    clientUrl = EXPORT_FS.substitute(HOST = host, PORT = port)
    params = {"user":user, "sourceHost": source, "exportPath": path, "container": container,
              "volcnt": volcnt,"initlower":initlower ,"isroot": isroot} 
    payload = {"role": "target", "opcode": "SSH_IMPORT_FS", "params": params}
    print("参数为：", params)
    rc = codes.SUCCESS
    try:
        resp = requests.post(clientUrl, data=json.dumps(payload), headers=HEADERS)
    except requests.exceptions.ConnectionError as e:
        logging.error(ERR_FMT.format(e, host))
        rc = codes.FAILED
    else:
        rc = resp.status_code

    return codes.perror(rc)

def sshfsMount(host, port, sshUser, sshSource, sshExportPath, sshMountPath):
    clientUrl = EXPORT_FS.substitute(HOST = host, PORT = port)
    params = {"user":sshUser, "sourceHost": sshSource, "exportPath": sshExportPath, "mountPath": sshMountPath}
    payload = {"role": "target", "opcode": "SSHFS_MOUNT", "params": params}
    rc = codes.SUCCESS
    try:
        resp = requests.post(clientUrl, data=json.dumps(payload), headers=HEADERS)
    except requests.exceptions.ConnectionError as e:
        logging.error(ERR_FMT.format(e, host))
        rc = codes.FAILED
    else:
        rc = resp.status_code

    return codes.perror(rc)


def migrateVolume(host, port, container, sshUser, sshSource, sshExportPath, targetVolume,volcnt):
    clientUrl = EXPORT_FS.substitute(HOST = host, PORT = port)
    params = {"user":sshUser, "sourceHost": sshSource, "exportPath": sshExportPath, "targetVolume": targetVolume,"container": container,"volcnt":volcnt}
    payload = {"role": "target", "opcode": "MIGRATE_VOLUME", "params": params}
    rc = codes.SUCCESS
    try:
        resp = requests.post(clientUrl, data=json.dumps(payload), headers=HEADERS)
    except requests.exceptions.ConnectionError as e:
        logging.error(ERR_FMT.format(e, host))
        rc = codes.FAILED
    else:
        rc = resp.status_code

    return codes.perror(rc)


def Unmount(host, port, sshMountPath):
    clientUrl = EXPORT_FS.substitute(HOST = host, PORT = port)
    params = {"mountPath": sshMountPath}
    payload = {"role": "target", "opcode": "UNMOUNT", "params": params}
    rc = codes.SUCCESS
    try:
        resp = requests.post(clientUrl, data=json.dumps(payload), headers=HEADERS)
    except requests.exceptions.ConnectionError as e:
        logging.error(ERR_FMT.format(e, host))
        rc = codes.FAILED
    else:
        rc = resp.status_code

    return codes.perror(rc)

def rootFSCopy(host, port, container, volcnt ,isroot = False):
    clientUrl = EXPORT_FS.substitute(HOST = host, PORT = port)
    params = {"container": container,"volcnt":volcnt,"isroot": isroot} 
    payload = {"role": "target", "opcode": "ROOTFS_COPY", "params": params}

    rc = codes.SUCCESS
    try:
        resp = requests.post(clientUrl, data=json.dumps(payload), headers=HEADERS)
    except requests.exceptions.ConnectionError as e:
        logging.error(ERR_FMT.format(e, host))
        rc = codes.FAILED
    else:
        rc = resp.status_code

    return codes.perror(rc)   

def remountInitLayer(host, port, container, volcnt ,initlower,isroot = False):
    clientUrl = EXPORT_FS.substitute(HOST = host, PORT = port)
    params = {"container": container,"volcnt":volcnt,"initlower":initlower ,"isroot": isroot} 
    payload = {"role": "target", "opcode": "REMOUNT", "params": params}

    rc = codes.SUCCESS
    try:
        resp = requests.post(clientUrl, data=json.dumps(payload), headers=HEADERS)
    except requests.exceptions.ConnectionError as e:
        logging.error(ERR_FMT.format(e, host))
        rc = codes.FAILED
    else:
        rc = resp.status_code

    return codes.perror(rc)   

def isNFSMounted(host, port, volume):
    clientUrl = EXPORT_FS.substitute(HOST = host, PORT = port)
    params = {"volume": volume}
    payload = {"role": "source", "opcode": "CHECK_NFS", "params": params}

    rc = codes.SUCCESS
    nfsMeta  = None

    try:
        resp = requests.get(clientUrl, data=json.dumps(payload), headers=HEADERS)
    except requests.exceptions.ConnectionError as e:
        logging.error(ERR_FMT.format(e, host))
        rc = codes.FAILED
    else:
        if resp.status_code == codes.herror(codes.SUCCESS):
            nfsMeta = json.loads(resp.content)

    return rc, nfsMeta

def nfsImportVolume(host, port, nfsMeta, volume):
    clientUrl = EXPORT_FS.substitute(HOST = host, PORT = port)
    params = {"nfsmeta": nfsMeta, "volume": volume}
    payload = {"role": "target", "opcode": "IMPORT_NFS", "params": params}
    rc = codes.SUCCESS
    try:
        resp = requests.post(clientUrl, data=json.dumps(payload), headers=HEADERS)
    except requests.exceptions.ConnectionError as e:
        logging.error(ERR_FMT.format(e, host))
        rc = codes.FAILED
    else:
        rc = resp.status_code
    return codes.perror(rc)    

def createContainer(host, port, containerCfg):
    name = containerCfg["Name"]
    if name.startswith("/"):
        name = name.split("/")[1]
    clientUrl = OPERATE_CONTAINER.substitute(HOST = host, PORT = port, NAME = name)
    payload = {"opcode": "create", "params": containerCfg}
    rc = codes.SUCCESS
    try:
        resp = requests.post(clientUrl, data=json.dumps(payload), headers=HEADERS)
    except requests.exceptions.ConnectionError as e:
        logging.error(ERR_FMT.format(e, host))
        rc = codes.FAILED
    else:
        rc = resp.status_code
    print("create rc:", rc)
    return codes.perror(rc)    

def startContainer(host, port, name):
    if name.startswith("/"):
        name = name.split("/")[1]
    clientUrl = OPERATE_CONTAINER.substitute(HOST = host, PORT = port, NAME = name)
    payload = {"opcode": "start"}
    rc = codes.SUCCESS
    try:
        resp = requests.post(clientUrl, data=json.dumps(payload), headers=HEADERS)
    except requests.exceptions.ConnectionError as e:
        logging.error(ERR_FMT.format(e, host))
        rc = codes.FAILED
    else:
        rc = resp.status_code
    return codes.perror(rc)

def stopContainer(host, port, name):
    if name.startswith("/"):
        name = name.split("/")[1]
    clientUrl = OPERATE_CONTAINER.substitute(HOST = host, PORT = port, NAME = name)
    payload = {"opcode": "stop"}
    rc = codes.SUCCESS
    try:
        resp = requests.post(clientUrl, data=json.dumps(payload), headers=HEADERS)
    except requests.exceptions.ConnectionError as e:
        logging.error(ERR_FMT.format(e, host))
        rc = codes.FAILED
    else:
        rc = resp.status_code
    return codes.perror(rc)

def startLazycopy(host, port, container, volume, volcnt, srchost):
    volumeId = hashlib.md5(volume).hexdigest()
    clientUrl = LAZY_COPY.substitute(HOST = host, PORT = port, CONTAINER = container, VOLUME = volumeId)
    payload = {"srchost": srchost, "volcnt": volcnt, "volume": volume}
    rc = codes.SUCCESS
    try:
        resp = requests.post(clientUrl, data=json.dumps(payload), headers=HEADERS)
    except requests.exceptions.ConnectionError as e:
        logging.error(ERR_FMT.format(e, host))  
        rc = codes.FAILED
    else:
        rc = resp.status_code
    return codes.perror(rc)

def stopLazyCopy(host, port, container, volume): 
    volumeId = hashlib.md5(volume).hexdigest()
    clientUrl = LAZY_COPY.substitute(HOST = host, PORT = port, CONTAINER = container, VOLUME = volumeId)
    rc = codes.SUCCESS
    try:
        resp = requests.delete(clientUrl, headers=HEADERS)
    except requests.exceptions.ConnectionError as e:
        logging.error(ERR_FMT.format(e, host))  
        rc = codes.FAILED
    else:
        rc = resp.status_code
    return codes.perror(rc)

def failover(host, port, container):
    clientUrl = FAILOVER_CONTAINER.substitute(HOST = host, PORT = port, CONTAINER = container)
    rc = codes.SUCCESS
    try:
        resp = requests.post(clientUrl, headers=HEADERS)
    except requests.exceptions.ConnectionError as e:
        logging.error(ERR_FMT.format(e, host))  
        rc = codes.FAILED
    else:
        rc = resp.status_code
    return codes.perror(rc)

def checkpointContainer(host, port, name, config):
    if name.startswith("/"):
        name = name.split("/")[1]
    clientUrl = OPERATE_CONTAINER.substitute(HOST = host, PORT = port, NAME = name)
    payload = {"opcode": "checkpoint", "address": config["address"], "port": config["port"],
                "sync_addr": config["sync_addr"], "sync_port": config["sync_port"]}
    rc = codes.SUCCESS
    try:
        resp = requests.post(clientUrl, data=json.dumps(payload), headers=HEADERS)
    except requests.exceptions.ConnectionError as e:
        logging.error(ERR_FMT.format(e, host))
        rc = codes.FAILED
    else:
        rc = resp.status_code
    return codes.perror(rc)

def restoreContainer(host, port, name, config):
    if name.startswith("/"):
        name = name.split("/")[1]
    clientUrl = OPERATE_CONTAINER.substitute(HOST = host, PORT = port, NAME = name)
    payload = {"opcode": "restore", "imgs_dir": config["imgs_dir"], "work_dir": config["work_dir"],
                "sync_addr": config["sync_addr"], "sync_port": config["sync_port"], "pid": config["pid"], 
                "address": config["address"], "port": config["port"]}
    rc = codes.SUCCESS
    try:
        resp = requests.post(clientUrl, data=json.dumps(payload), headers=HEADERS)
    except requests.exceptions.ConnectionError as e:
        logging.error(ERR_FMT.format(e, host))
        rc = codes.FAILED
    else:
        rc = resp.status_code
    return codes.perror(rc)

def startPageClient(host, port, name, config):
    if name.startswith("/"):
        name = name.split("/")[1]
    clientUrl = OPERATE_CONTAINER.substitute(HOST = host, PORT = port, NAME = name)
    payload = {"opcode": "pageclient", "imgs_dir": config["imgs_dir"], "work_dir": config["work_dir"],
                "sync_addr": config["sync_addr"], "sync_port": config["sync_port"], "pid": config["pid"], 
                "address": config["address"], "port": config["port"]}
    rc = codes.SUCCESS
    try:
        resp = requests.post(clientUrl, data=json.dumps(payload), headers=HEADERS)
    except requests.exceptions.ConnectionError as e:
        logging.error(ERR_FMT.format(e, host))
        rc = codes.FAILED
    else:
        rc = resp.status_code
    return codes.perror(rc)

def getMigrateStatus(host, port, path):
    clientUrl = GET_STATUS.substitute(HOST = host, PORT = port, PATH = path)
    
    containerMeta = dict()
    rc = codes.SUCCESS
    try:
        resp = requests.get(clientUrl, headers=HEADERS)
    except requests.exceptions.ConnectionError as err:
        logging.error(ERR_FMT.format(err, host))
    else:
        if resp.status_code == codes.herror(codes.SUCCESS):
            containerMeta = json.loads(resp.content)
        else:
            print(resp.content)
    return rc, containerMeta

def setIPtables(host, port, name, config):
    if name.startswith("/"):
        name = name.split("/")[1]
    clientUrl = OPERATE_CONTAINER.substitute(HOST = host, PORT = port, NAME = name)
    payload = {"opcode": "setIPtables", "address": config["address"], "ports": config["ports"]}
    rc = codes.SUCCESS
    try:
        resp = requests.post(clientUrl, data=json.dumps(payload), headers=HEADERS)
    except requests.exceptions.ConnectionError as e:
        logging.error(ERR_FMT.format(e, host))
        rc = codes.FAILED
    else:
        rc = resp.status_code
    return codes.perror(rc)

def getFile(host, port, path):
    clientUrl = NODE_OP.substitute(HOST = host, PORT = port)
    payload = {"opcode": "GET_FILE", "path": path}
    rc = codes.SUCCESS
    data = {}
    try:
        resp = requests.get(clientUrl, data=json.dumps(payload), headers=HEADERS)
        print(resp.content)
    except requests.exceptions.ConnectionError as e:
        logging.error(ERR_FMT.format(e, host))
        rc = codes.FAILED
    else:
        if resp.status_code == codes.herror(codes.SUCCESS):
            data = json.loads(resp.content)
    return rc, data