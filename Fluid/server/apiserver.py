import sys
import argparse
import logging
import os
import socket
import configparser
import json
import subprocess

from flask import Flask, request
from flask_restful import Api, Resource, reqparse
from flask.helpers import make_response

from common import codes
import controller


app = Flask(__name__)
api = Api(app)

reqHandler = None
parser = reqparse.RequestParser()
parser.add_argument('nodeid', type=str)
parser.add_argument('containerid', type=str)

class FluidHandler(Resource):
    def get(self):
        rc, msg = reqHandler.getAllContainers()
        return make_response(json.dumps(msg), codes.herror(rc=rc))
    
    def post(self):
        migreq  = json.loads(request.data)
        rc = reqHandler.migrate(migreq)
        return make_response("", codes.herror(rc))

class AgentHandler(Resource):
    def post(self):
        agent = request.data
        rc = reqHandler.register(agent)
        return make_response("", codes.herror(rc))

    def delete(self):
        return make_response("", 200)
	
class FluidStatusHandler(Resource):
    def get(self, containerid):
        rc, msg = reqHandler.getStatus(containerid)
        return make_response(msg, codes.herror(rc))

    def post(self, containerid):
        payload = request.data
        rc = reqHandler.updateStatus(containerid, payload)
        return make_response("", codes.herror(rc))

class FailoverHandler(Resource):
    def post(self, nodeid, containerid):
        rc = reqHandler.doFailover(nodeid, containerid)
        return make_response("", codes.herror(rc))

api.add_resource(AgentHandler, '/register')
api.add_resource(FluidHandler, '/fluid')
api.add_resource(FluidStatusHandler, '/fluid/replication/<string:containerid>')
api.add_resource(FailoverHandler, '/fluid/failover/<string:nodeid>/<string:containerid>')

if __name__ == '__main__':
    usage = "usage: python3 %prog --config <config file>"
    parser = argparse.ArgumentParser(description=usage)
    parser.add_argument("-c", "--config", action="store", dest="config", default="./config.cfg",
                        help="config file(default=./config.cfg)")
    
    opts, args = parser.parse_known_args()
    cfg = dict()
    cfgfile = opts.config

    config = configparser.RawConfigParser()
    config.read(cfgfile)
    cfg['dbserver'] = config.get('etcd', 'server')
    cfg['dbport'] = config.get('etcd', 'port')

    interface = config.get('global', 'interface')
    port = config.get('global', 'port')
    logfile = config.get('global', 'logfile')

    ipaddr = subprocess.getoutput(f"/sbin/ifconfig {interface}").split('\n')[1].split()[1]
    if not os.path.exists(os.path.dirname(logfile)):
        print("Invalid log file path")
        parser.print_help()
        sys.exit(1)
    
    logging.basicConfig(filename=logfile, level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')
    logging.debug(f"Starting server on host address:{ipaddr}:{port}")
    # print(cfg)
    reqHandler = controller.RequestHandler(cfg)
    print(f"Starting fluid server on {ipaddr}:{port}")

    try:
        app.run(host=ipaddr, port=port, debug=True)
    except socket.error as err:
        logging.error(f"Failed to start server on {ipaddr}:{port}")
        print(f"Error starting server. Please check the logs at {logfile}")


