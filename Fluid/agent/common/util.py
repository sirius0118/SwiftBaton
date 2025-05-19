import os
import fileinput
import shutil
import subprocess
import sys
from string import Template
import logging
import pickle

CONFIG_DIR = "/var/lib/fluid"
SVC_TEMPLATE = "replicator_svc.conf"
ETC_INIT_DIR = "/etc/init/"
COPY_CMD=Template("cp -r $SRC/* $TARGET/")

def getDir(service, container, volcnt):
    path = f"{CONFIG_DIR}/{service}_{container}_{volcnt}"
    if not os.path.exists(path):
        try:
            os.makedirs(path, exist_ok=True)
        except FileExistsError:
            print("file exists!\n")
    return path

def getNFSMountDir(container, volcnt):
    return getDir("nfs", container, volcnt)

def getSSHFSVolumeDir(container, volcnt):
    return getDir("valume", container, volcnt)

def getSSHFSMountDir(container, volcnt):
    return getDir("sshfs", container, volcnt)

def getCOWDir(container, volcnt):
    return getDir("cow", container, volcnt)

def getWorkDir(container, volcnt):
    return getDir("work", container, volcnt)

def getDiffDir(container, volcnt):
    return getDir("diff", container, volcnt)

def getInitDir(container, volcnt):
    return getDir("init", container, volcnt)

def getUnionMountDir(container, volcnt):
    return getDir("union", container, volcnt)

def getLazyCopyDir(container, volcnt):
    return getDir("lazycopy", container, volcnt)

def getContainerMDFile(container):
    mdfilepath = f"{CONFIG_DIR}/{container}.md"
    return mdfilepath

def getRepProcID(container, volumeID):
    idfile = f"{CONFIG_DIR}/repl_{container}_{volumeID}.pid"
    if not os.path.exists(idfile):
        return 0
    
    with open(idfile, 'r') as infile:
        for line in infile:
            procid = line
    return procid

def storeReplProcID(container, volumeID, procid):
    idfile = f"{CONFIG_DIR}/repl_{container}_{volumeID}.pid"
    if os.path.exists(idfile):
        os.remove(idfile)
    with open(idfile, 'w') as outfile:
        outfile.write(str(procid))

def findAndReplace(infile, searchExp, replaceExp):
    for line in fileinput.input(infile, inplace=True):
        if searchExp in line:
            sys.stdout.write(line.replace(searchExp, replaceExp))

def createReplSvc(container, volumeID, cmd):
    svcName = f"{container}_{volumeID}"
    svcFile = os.path.join(ETC_INIT_DIR, f"{svcName}.conf")
    shutil.copy2(SVC_TEMPLATE, svcFile)
    findAndReplace(svcFile, "CMD", cmd)
    return svcName

def startSvc(name):
    cmd = f"service {name} start"
    status, output = subprocess.getstatusoutput(cmd)
    return status, output


# def copy_directory(src, dst):  
#     """  
#     拷贝目录src到目录dst  
#     :param src: 源目录路径  
#     :param dst: 目标目录路径  
#     """  
#     if not os.path.exists(dst):  
#         os.makedirs(dst)  
       
#     for item in os.listdir(src):  
#         s = os.path.join(src, item)  
#         d = os.path.join(dst, item)  
          
#         if os.path.isfile(s):  
#             shutil.copy2(s, d)    
#         elif os.path.isdir(s):  
#             copy_directory(s, d)

def copy_directory(src, dst):  
    cmd = COPY_CMD.substitute(SRC=src,TARGET=dst)
    print(f"Executing copy commadn: {cmd}")
    logging.debug(f"Executing copy commadn: {cmd}")
    status, output = subprocess.getstatusoutput(cmd)
    if status != 0:
        logging.error(f"copy failed. {output}")

    logging.debug(f"copy successful. {src}")


def delete_contents(directory):  
    """  
    删除给定目录下的所有文件和子目录，但保留目录本身。  
  
    :param directory: 要清理的目录的路径  
    """  
    if not os.path.isdir(directory):  
        print(f"Error: {directory} is not a directory.")  
        return  
  
    for item in os.listdir(directory):  
        full_path = os.path.join(directory, item) 
        if "/var/lib/docker/overlay2" not in full_path:
            print(f"Error: {full_path} is not a docker overlay2 directory.")
            sys.exit(0) 
        if os.path.isfile(full_path):  
            os.remove(full_path)  
            print(f"Deleted file: {full_path}")  
        elif os.path.isdir(full_path):  
            shutil.rmtree(full_path)  
            print(f"Deleted directory: {full_path}") 