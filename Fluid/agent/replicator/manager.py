import os
import argparse
import logging
from multiprocessing import Manager

from .jobQ import JobQ
from .crawler import Crawler
from .replicator import Replicator
from .monitor import Monitor


def main():
    logging.basicConfig(filename='/var/log/fluid-replicator.log', level=logging, format='%(asctime)s %(message)s')
    usage = "usage: python3 %prog -m <monitor path> -c <copy directory> -h <source host>"
    parser = argparse.ArgumentParser(description=usage)
    parser.add_argument("--mondir", action="store", dest="mondir", help="monitor directory path")
    parser.add_argument("--nfsdir", action="store", dest="nfsdir", help="NFS mount directory path")
    parser.add_argument("--srcdir", action="store", dest="srcdir", help="source directory path")
    parser.add_argument("--destdir", action="store", dest="destdir", help="destincation/local directory path")
    parser.add_argument("--container", action="store", dest="container", help="container-id")
    parser.add_argument("--srchost", action="store", dest="srchost", help="source host")
    parser.add_argument("--server", action="store", dest="server", help="fluid server host:port")
    parser.add_argument("--agentid", action="store", dest="agentid", help="local agent id")
    parser.add_argument("--volumeid", action="store", dest="volumeid", help="volume id")

    opts = parser.parse_args()
    mondir = opts.mondir
    nfsdir = opts.nfsdir
    srcdir = opts.srcdir
    destdir = opts.destdir
    container = opts.container
    srchost = opts.srchost
    server = opts.server
    agentid = opts.agentid
    volumeid = opts.volumeid

    if not os.path.exists(destdir):
        os.makedirs(destdir)
    
    mgr = Manager()
    jobq = mgr.list()

    crawler = Crawler(nfsdir, jobq)

    crawler.start()
    crawler.join()

    # monitor的本意是监控Upper中哪些文件发生了变化，如果发生了变化，那么这个文件可以不用传输了，节约流量
    # 但是传也没事，本质会被上层所覆盖。因此该功能可以注释
    # monitor = Monitor(mondir, jobq)
    # monitor.start()

    # 开始迁移
    replicator = Replicator(jobq, agentid, destdir, srchost, srcdir, container, volumeid, server)
    replicator.start()

    # monitor.join()
    replicator.join()

if __name__ == "__main__":
    main()
