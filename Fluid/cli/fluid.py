import os
import argparse
import logging
import json
import requests
import sys
from string import Template

LIST_CONTAINER_URL = Template("http://$SERVER/fluid")
OPERATE_CONTAINER_URL = Template("http://$SERVER/container/$NAME")
FAILOVER_CONTAINER_URL = Template("http://$SERVER/fluid/failover/$NODE/$CONTAINER")
STATUS_URL = Template("http://$SERVER/fluid/replication/$CONTAINER")

class Fluid():
    def __init__(self, server):
        self.server = server
    
    def pretty_print_list(self, containermap):
        fmt = "%40s\t%30s\t%32s"
        print((fmt % ("HOSTID", "CONTAINER", "STATUS")))
        print((fmt % ("-------", "------------", "------------")))
        containermap = json.loads(containermap)
        for agent in containermap:
            # print((agent.split('/agents/')[1]))
            for container in containermap[agent]:
                print((fmt % (agent.split('/agents/')[1], container['Names'][0].split('/')[1], container['Status'])))

    def listcontainers(self):
        url = LIST_CONTAINER_URL.substitute(SERVER=self.server)
        header = {'content-Type': 'application/json'}
        payload = dict()
        try:
            resp = requests.get(url=url, data=json.dumps(payload), headers=header)
        except requests.exceptions.ConnectionError as err:
            print(f"Can not connect Fluid server: {err}")
            sys.exit(1)
        containermap = json.loads(resp.content) if resp.status_code == 200 else None
        print(resp.status_code)
        self.pretty_print_list(containermap)

    def migrate(self, source, container, target, rootfs=False):
        url = LIST_CONTAINER_URL.substitute(SERVER=self.server)
        payload = {"source": source, "target": target, "container": container, "rootfs": rootfs}
        header = {'content-Type': 'application/json'}
        try:
            resp = requests.post(url=url, data=json.dumps(payload), headers=header)
        except requests.exceptions.ConnectionError as err:
            print(f"Can not connect Fluid server: {err}")
            sys.exit(1)
        if resp.status_code == 200:
            print("Migration started successfully")
            print("Lazy copy is process.")
        else:
            print("Migration failed")
            print("Please check the logs.")
        
    def failover(self, container, target):
        url = FAILOVER_CONTAINER_URL.substitute(SERVER=self.server, CONTAINER=container, NODE=target)
        header = {'content-Type': 'application/json'}
        payload = dict()
        try:
            resp = requests.post(url=url, data=json.dumps(payload), headers=header)
        except requests.exceptions.ConnectionError as err:
            print(f"Can not connect Fluid server: {err}")
            sys.exit(1)
        print((f"Container failover {'succeeded' if resp.status_code == 200 else 'failed'}."))

    def getStatus(self, container):
        url = STATUS_URL.substitute(SERVER=self.server, CONTAINER=container)
        payload = dict()
        headers = {"content-type": "application/json"}
        try:
            resp = requests.get(url=url, data=json.dumps(payload), headers=headers)
        except requests.exceptions.ConnectionError as err:
            print(f"Can not connect Fluid server: {err}")
            sys.exit(1)
        if resp.status_code == 200:
            result = json.loads(resp.content)
            fmt = "%s\t%10s\t%10s\t%20s\t%20s\t%20s"
            print((fmt % ("CONTAINER", "TOTAL FILES", "FILES COPIED", "STARTED AT", "LAST UPDATED",
                         "COMPLETED AT")))
            print((fmt % ("-" * 7 + "\t", "-" * 12, "-" * 12, "-" * 12, "-" * 12, "-" * 12)))
            print((fmt % (container, result["total"], result["curr"], str(result["start"]),
                         str(result["update"]), str(result["complete"]))))


def main():
    usage = "usage: python3 %prog -f <config_file> {--list | --migrate --source <source> --container <container> --target <target> (optional)--rootfs}"

    parser = argparse.ArgumentParser(description=usage)
    parser.add_argument("-l", "--list", action="store_true", dest="listc", default=False, help="list containers")
    parser.add_argument("-m", "--migrate", action="store_true", dest="migrate", default=False, help="migrate container")
    parser.add_argument("-f", "--failover", action="store_true", dest="failover", default=False, help="failover container")
    parser.add_argument("--status", action="store_true", dest="status", default=False, help="query lazy replication status")
    parser.add_argument("--source", action="store", dest="source", default = None, help="Source Host (agent name)")
    parser.add_argument("--container", action="store", dest="container", default = None, help="Container name to be migrated")
    parser.add_argument("--target", action="store", dest="target", default = None, help="Target Host (agent name)")
    parser.add_argument("--rootfs", action="store_true", dest="rootfs", default=False, help="migrate rootfs")
    parser.add_argument("-s", "--server", action="store", dest="server", default="127.0.0.1:5000", help="Cargo server and port")

    opts, _ = parser.parse_known_args()

    listc = opts.listc
    migrate = opts.migrate
    failover = opts.failover
    status = opts.status
    source = opts.source
    container = opts.container
    target = opts.target
    rootfs = opts.rootfs
    server = opts.server

    if not listc and not migrate and not failover and not status:
        parser.print_help()
    
    if migrate and not source and not target and not container:
        parser.print_help()
    
    if failover and not target and not container and not server:
        parser.print_help()

    if status and not container:
        parser.print_help()
    
    fluid = Fluid(server)

    if listc:
        fluid.listcontainers()
        sys.exit(0)
    if migrate:
        fluid.migrate(source, container, target, rootfs)
        sys.exit(0)
    if failover:
        fluid.failover(container, target)
        sys.exit(0)
    if status:
        fluid.getStatus(container)
    
if __name__ == "__main__":
    main()


