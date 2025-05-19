import logging
import json
import docker.errors
import requests
from docker import client
import os
import subprocess
import time

from common import codes

FLUID_VOL_DIR = "/var/lib/fluid"

class DockerClient(object):
    def __init__(self, config) -> None:
        self.client = client.APIClient(base_url=config)
        self.logger = logging.getLogger(__name__)
    
    def listContainers(self):
        containers = []
        rc = codes.SUCCESS
        try:
            containers = self.client.containers()
        except docker.errors.NotFound as err:
            rc = codes.NOT_FOUND
            logging.error(err)
        else:
            return (rc, containers)
    
    def inspectContainer(self, containerID: str):
        containerInfo = ""
        rc = 0
        try:
            containerInfo = self.client.inspect_container(containerID)
        except docker.errors.NotFound as err:
            rc = codes.NOT_FOUND
            logging.error(err)
        except requests.exceptions.ConnectionError as err:
            rc = codes.FAILED
            logging.error(err)
        return (rc, json.dumps(containerInfo))

    def start(self, containerId):
        rc = codes.SUCCESS
        try:
            self.client.start(container=containerId)
        except docker.errors.NotFound as err:
            rc = codes.NOT_FOUND
            logging.error(err)
        except requests.exceptions.ConnectionError as err:
            rc = codes.FAILED
            logging.error(err)
        return rc
    
    def create(self, config):
        rc = codes.SUCCESS
        name = config["Name"].strip("/")
        image = config["Config"]["Image"]
        command  = config["Config"]["Cmd"]
        env  = config["Config"]["Env"]
        entrypoint = config["Config"]["Entrypoint"]
        ports = config["NetworkSettings"]["Ports"]
        cports = []
        portmap = {}
        if ports:
            for port in ports:
                cport  = port.split('/tcp')[0]
                # portmap[cport] = None
                hport = ports[port][0]['HostPort']
                portmap[cport] = hport
                cports.append(cport)

        sVolList = []
        volMap = []
        
        mounts = config.get("Mounts", [])

        for volume in mounts:
            dVolume = volume["Destination"]
            isRW = volume["RW"]
            mode = 'rw'
            if not isRW:
                mode = 'ro'
            if not volume["isNFS"]:
                volcnt = volume["Source"]
                sVolume = "{home}/union_{name}_{cnt}".format(home=FLUID_VOL_DIR,name = name, cnt = volcnt)
            else:
                sVolume = volume["Source"]
                #sVolList.append(sVolume)

            volumeMeta = "{}:{}:{}".format(sVolume, dVolume, mode)
            volMap.append(volumeMeta)
        
        '''
        volumes = config["Volumes"]
        for contVol in volumes.keys():
            hostVolume = volumes[contVol]
            rwFlag = config["VolumesRW"][contVol]
            mode = 'rw'
            if not rwFlag:
                mode = 'ro'
            volumeMeta = "{}:{}:{}".format(hostVolume, contVol, mode)
            volMap.append(volumeMeta)
        '''
                
        host_config = self.client.create_host_config(port_bindings= portmap, \
                    binds = volMap)
        try:
            self.client.create_container(name = name, image = image, command = command, environment = env,\
                entrypoint = entrypoint, ports = cports, volumes = sVolList, host_config=host_config)

        except requests.exceptions.ConnectionError as err:
            rc = codes.FAILED
            logging.error(err)
        
        return rc

    def stop(self, containerId):
        rc = codes.SUCCESS
        try:
            self.client.stop(containerId)
        except docker.errors.NotFound as err:
            rc = codes.NOT_FOUND
            logging.error(err)
        except requests.exceptions.ConnectionError as err:
            rc = codes.FAILED
            logging.error(err)
        return rc

    def remove(self, containerID):
        rc = codes.SUCCESS
        try:
            self.client.remove_container(containerID)
        except docker.errors.NotFound as err:
            rc = codes.NOT_FOUND
            logging.error(err)
        except requests.exceptions.ConnectionError as err:
            rc = codes.FAILED
            logging.error(err)
        return rc

    
    def checkpoint(self, containerID: str, checkpointName: str):
        rc = codes.SUCCESS
        cmd = f"docker checkpoint create {containerID} {checkpointName}"
        logging.debug(f"run the command: {cmd}")
        subprocess.Popen(cmd, shell=True)
        return rc
    
    def restore(self, containerID: str, checkpointName: str):
        rc = codes.SUCCESS
        cmd = f"docker start --checkpoint {checkpointName} {containerID}"
        logging.debug(f"run the command: {cmd}")
        subprocess.Popen(cmd, shell=True)
        return rc

