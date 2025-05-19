"""
    We need to implement the following functions:
    - Lazy copy the R/W layer of container
    - [Extra] Put the checkpoint directory to the target machine by NFS filesystem system

"""


from string import Template
import os
import subprocess
import logging
import pickle

from common import codes, util

NFS_EXPORT_CONFIG = "/etc/exports"
NFS_EXPORT_FS = "exportfs -a"
NFS_MOUNT_CMD = Template("mount -t nfs -o v3 $EXPORTPATH $MOUNTPATH")
UNION_MOUNT_CMD = Template("mount -t aufs -o br=$UPPER_DIR=rw:$LOWER_DIR=ro -o udba=reval none $MOUNT")
GET_ALL_NFS_MOUNTS = "mount -l -t nfs"
GET_ALL_AUFS_MOUNTS = "mount -l -t aufs | awk '{print $3}'"
UNMOUNT_CMD = Template("umount -l $MOUNT")
COPY_WITH_HARDLINKS = Template("cp -lR --remove-destination $SRC/* $TARGET/")

FLUID_VOL_DIR = "/var/lib/fluid"
 
class FilesystemClient():
    def nfsExport(self, config):
        dirpath = config["exportPath"]

        if not os.path.exists(dirpath):
            return codes.NOT_FOUND
        
        exportcfg = f"{dirpath} *(rw,sync,no_root_squash,subtree_check,nohide)\n"
        fp = open(NFS_EXPORT_CONFIG, "a")
        fp.write(exportcfg)
        fp.close()

        logging.debug("Re-exporting NFS mounts.")
        status, output = subprocess.getstatusoutput(NFS_EXPORT_FS)
        if status != 0:
            logging.error(f"NFS restart failed. {output}")
            return codes.FAILED
    
        return codes.SUCCESS
    

    def __nfs_import(self, exportpath, mountpath):
        if not os.path.exists(mountpath):
            os.makedirs(mountpath)
        
        cmd = NFS_MOUNT_CMD.substitute(EXPORTPATH=exportpath, MOUNTPATH=mountpath)
        logging.debug(f"Executing NFS mount commadn: {cmd}")
        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            logging.error(f"NFS mount failed. {output}")
            return codes.FAILED

        logging.debug(f"NFS mount successful. {mountpath}")
        return codes.SUCCESS

    def __merge_fs(self, upper_dir, lower_dir, mountpath):
        if not os.path.exists(mountpath):
            os.mkdir(mountpath)
        
        if not os.path.exists(upper_dir):
            os.mkdir(upper_dir)
        
        cmd = UNION_MOUNT_CMD.substitute(UPPER_DIR=upper_dir, LOWER_DIR=lower_dir, MOUNT=mountpath)
        logging.debug(f"Executing union mount commadn: {cmd}")
        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            logging.error(f"Union mount failed. {output}")
            return codes.FAILED
        
        logging.debug(f"Union mount successful. {mountpath}")
        return codes.SUCCESS

    def __storeMeta(self, containerName, nfsMount, cowdir, unionMount, lazycopydir):
        mdfile = util.getContainerMDFile(containerName)
        volMap = {}
        newVol = {}
        newVol["nfs"] = nfsMount
        newVol["cow"] = cowdir
        newVol["union"] = unionMount
        newVol["lazy"] = lazycopydir

        if os.path.exists(mdfile):
            volMap = pickle.load(open(mdfile, "rb"))
        volMap[unionMount] = newVol
        pickle.dump(volMap, open(mdfile, "wb"))

    def prepareTargetFS(self, config):
        containerName = config["container"]
        sourceHost = config["sourceHost"]
        exportPath = config["exportPath"]
        volcnt = config["volcnt"]

        nfsMount = util.getNFSMountDir(containerName, volcnt)
        cowdir = util.getCOWDir(containerName, volcnt)
        unionMount = util.getUnionMountDir(containerName, volcnt)
        lazycopydir = util.getLazyCopyDir(containerName, volcnt)

        nfsexport = f"{sourceHost}:{exportPath}"

        if self.__nfs_import(nfsexport, nfsMount) == codes.SUCCESS:
            if self.__merge_fs(nfsMount, cowdir, unionMount) == codes.SUCCESS:
                self.__storeMeta(containerName, nfsMount, cowdir, unionMount, lazycopydir)
                return codes.SUCCESS
        return codes.FAILED

    def checkAndGetNFSMeta(self, config):
        nfsMeta = dict()
        volPath = config["volume"]

        status, output = subprocess.getstatusoutput(GET_ALL_NFS_MOUNTS)
        if status != 0:
            logging.error(f"Failed to get all NFS mounts. {output}")
            return codes.FAILED
        
        if output == None:
            nfsMeta["is_nfs_mounted"] = False
            return (codes.SUCCESS, nfsMeta)
        
        nfsList = output.split("\n")
        for nfsmout in nfsList:
            mountPoint = nfsmout.split()[2]
            if volPath in mountPoint:
                nfsMeta["is_nfs_mounted"] = True
                nfsMeta["nfs_server"] = nfsmout.split()[0].split(":")[0]
                nfsMeta["nfs_exportpath"] = nfsmout.split()[0].split(":")[1]
                nfsMeta["nfs_mountpath"] = mountPoint
                return (codes.SUCCESS, nfsMeta)

    def mountNFSVolume(self, config):
        nfsServer = config["nfsmeta"]["nfs_server"]
        nfsExportPath = config["nfsmeta"]["nfs_exportpath"]
        nfsMountPath = config["nfsmeta"]["nfs_mountpath"]

        nfsexport = f"{nfsServer}:{nfsExportPath}"
        return self.__nfs_import(nfsexport, nfsMountPath)

    def __exec(self, cmd):
        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            logging.error(f"Executing command failed: {cmd} {output}")
        return status

    def failoverVolumes(self, containerID):
        return codes.SUCCESS
        mdfile = util.getContainerMDFile(containerID)

        volMap = {}
        if os.path.exists(mdfile):
            volMap = pickle.load(open(mdfile, "rb"))
        
        for unionMount, mountMap in list(volMap.items()):
            logging.debug(f"Starting failover for volume: {unionMount}")
            # 1. Un-mount aufs mount point
            logging.debug(f"Un-mounting aufs mount point: {unionMount}")
            
            cmd = UNMOUNT_CMD.substitute(MOUNT=unionMount)
            rc = self.__exec(cmd)
            if rc != codes.SUCCESS:
                logging.debug(f"Failed to un-mount aufs mount point: {unionMount}")
            else:
                return rc
            
            # 2. Delete aufs mount directory
            umdir = unionMount.rstrip('/')
            cmd = f"rm -rf {umdir}"
            rc = self.__exec(cmd)
            if rc != codes.SUCCESS:
                logging.debug(f"Failed to delete aufs mount directory: {unionMount}")
            else:
                return rc
            
            # 3. Rename lazy directory to mount point
            lazycopyDir = volMap[unionMount]['lazy'].rstrip('/')
            os.rename(lazycopyDir, umdir)
            logging.debug(f"Lazycopy directory renamed form {lazycopyDir} to {umdir}")
            
            # 4. Hard-link form cow to unin mount directory
            cmd = COPY_WITH_HARDLINKS.substitute(SRC=volMap[unionMount]['cow'], TARGET=umdir)
            rc = self.__exec(cmd=cmd)
            if rc != codes.SUCCESS:
                logging.debug("Data file hard-linked successfully")
            else:
                return rc
            
            # 5. Un-mount nfs
            cmd = UNMOUNT_CMD.substitute(MOUNT=volMap[unionMount]['nfs'])
            self.__exec(cmd=cmd)

            return rc



