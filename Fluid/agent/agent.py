import sys
import os
import logging
import json
import requests
import argparse
import socket
import uuid
import subprocess
import configparser
from string import Template
from flask import Flask, request
from flask_restful import Api, Resource, reqparse
from flask.helpers import make_response

from common import codes
import controller

app = Flask(__name__)
api = Api(app)

reqHandler = None
fluidServer = None

parser = reqparse.RequestParser()
parser.add_argument('containerID', type=str, help='Container ID')
parser.add_argument('volumeID', type=str, help='Volume ID')

REGISTER_URL = Template("http://$HOST:$PORT/register")
CONFIG_DIR = "/var/lib/fluid"
AGENT_IDFILE = "agent.id"

class ContainersHandler(Resource):
    def get(self):
        rc, msg = reqHandler.getAllContainers()
        return make_response(json.dumps(msg), codes.herror(rc=rc))

class ContainerHandler(Resource):
    def get(self, containerId):
        rc, msg = reqHandler.getContainer(str(containerId))
        return make_response(msg, codes.herror(rc))

    def post(self, containerId):
        reqData = request.data
        rc = reqHandler.handleContainerOp(reqData, containerId)
        return make_response("", codes.herror(rc))

    def delete(self, containerId):
        rc = reqHandler.deleteContainer(None, containerId)
        return make_response("", codes.herror(rc))
	
class FilesystemHandler(Resource):
    def get(self):
        config = request.data
        rc, msg = reqHandler.handleFSOp(config)
        return make_response(json.dumps(msg), codes.herror(rc))

    def post(self):
        config = request.data
        rc = reqHandler.handleFSOp(config)
        return make_response("", codes.herror(rc))

class ReplicationHandler(Resource):
    def post(self, containerId, volumeId):
        payload = request.data
        idfile = os.path.join(CONFIG_DIR, AGENT_IDFILE)
        with open(idfile, 'r') as infile:        
            for line in infile:
                nodeId = line

        rc = reqHandler.startReplication(containerId, volumeId, nodeId, fluidServer, payload)
        return make_response("", codes.herror(rc))
    
    def delete(self, containerId, volumeId):
        rc = reqHandler.stopReplication(containerId, volumeId)
        return make_response("", codes.herror(rc))

class FailoverHandler(Resource):
    def post(self, containerId):
        rc = reqHandler.doFailover(containerId)
        return make_response("", codes.herror(rc))

class GetStatusHandler(Resource):
    def get(self, path):
        path = path.replace("-", "/")
        rc, msg = reqHandler.getStatus(path)
        return make_response(msg, codes.herror(rc))
    
class NodeOPHandler(Resource):
    def get(self):
        config = request.data
        rc, msg = reqHandler.getOP(config)
        return make_response(json.dumps(msg), codes.herror(rc=rc))


api.add_resource(ContainersHandler, '/containers')
api.add_resource(ContainerHandler, '/container/<string:containerId>')
api.add_resource(FilesystemHandler, '/fs')
api.add_resource(FailoverHandler, '/failover/<string:containerId>')
api.add_resource(ReplicationHandler, '/replication/<string:containerId>/<string:volumeId>')
api.add_resource(GetStatusHandler, '/status/<string:path>')
api.add_resource(NodeOPHandler, '/nodeop')

def register(fluidhost, fluidport, serverip, serverport, serverid):
    url = REGISTER_URL.substitute(HOST = fluidhost, PORT = fluidport)
    headers = {"content-type": "application/json"}
    payload = dict()
    payload['ip'] = serverip
    payload['port'] = serverport
    payload['id'] = serverid
    try:
        resp = requests.post(url, data=json.dumps(payload), headers=headers)
    except requests.exceptions.ConnectionError as err:
        logging.error(err)
        return 0
            
    if resp.status_code == 200:
        return 1
    else:
        return 0     

if __name__ == '__main__':
    usage = "usage: python3 %prog -c <config file>"
    parser = argparse.ArgumentParser(description=usage)
    parser.add_argument("-c", "--config", dest="config", help="config file", default="./config.cfg")
    opts, args = parser.parse_known_args()
    cfgfile = opts.config

    cfg = dict()
    config = configparser.RawConfigParser()
    config.read(cfgfile)
    cfg['fluidhost'] = config.get('fluid-server', 'ipaddr')
    cfg['fluidport'] = config.get('fluid-server', 'port')
    cfg['dockerurl'] = config.get('docker-config', 'URL')

    interface = config.get('global', 'interface')
    port = config.get('global', 'port')
    logfile = config.get('global', 'logfile')

    ipaddr = subprocess.getoutput(f"/sbin/ifconfig {interface}").split('\n')[1].split()[1]

    if not os.path.exists(os.path.dirname(logfile)):
        print("Invalid log file path")
        parser.print_help()
        sys.exit(1)

    if not os.path.exists(CONFIG_DIR):
        os.makedirs(CONFIG_DIR)

    idfile = os.path.join(CONFIG_DIR, AGENT_IDFILE)
    if not os.path.exists(idfile):
        nodeid = str(uuid.uuid4())
        with open(idfile, 'w') as outfile:
            outfile.write(nodeid)
    else:
        with open(idfile, 'r') as infile:        
            for line in infile:
                nodeid = line
    
    logging.basicConfig(filename=logfile, level=logging.DEBUG, format='%(asctime)s %(message)s')
    logging.info(f"Starting agent on {ipaddr}:{port}")
    logging.info(f"Agent ID: {nodeid}")
    print(f"Starting agent on {ipaddr}:{port}")

    if not register(cfg['fluidhost'], cfg['fluidport'], ipaddr, port, nodeid):
        logging.error("Failed to register with fluid server")
        sys.exit(1)
    
    reqHandler = controller.RequesRouter(cfg)
    fluidServer = f"{cfg['fluidhost']}:{cfg['fluidport']}"

    try:
        app.run(host=ipaddr, port=int(port), threaded=True, debug=True)
    except socket.error as msg:
        logging.error(f"Error starting the server. Error[{msg[1]}]")
        print("Error starting server. Please check the logs at {logfile}")


