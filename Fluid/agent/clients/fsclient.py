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
import sys
from common import codes, util
from .fsreplicator import Fsreplicator

NFS_EXPORT_CONFIG = "/etc/exports"
NFS_EXPORT_FS = "exportfs -a"
NFS_MOUNT_CMD = Template("mount $EXPORTPATH $MOUNTPATH")
SSHFS_IMPORT_CMD = Template("sshfs $USER@$SOURCE:$EXPORTPATH  $MOUNTPATH -o allow_other")
OVERLAY_MOUNT_CMD = Template("sudo mount -t overlay overlay -o lowerdir=$LOWERDIR,upperdir=$UPPERDIR,workdir=$WORKDIR $MERGEDDIR")
OVERLAY_UMOUNT_CMD = Template("umount $MERGEDDIR")
UMOUNT_CMD = Template("umount $MOUNTDIR")
GET_ALL_NFS_MOUNTS = "mount -l -t nfs"
COPY_WITH_HARDLINKS = Template("cp -lR --remove-destination $SRC/* $TARGET/")
# COPY_CMD=Template("sudo cp -r $SRC/ $TARGET/; cp -r $TARGET/diff/* $TARGET; sudo rm -rf $TARGET/diff")
COPY_CMD=Template("sudo cp -r $SRC/* $TARGET/")
SCOPY_CMD=Template("sudo scp -r $SRC/* $TARGET/")

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

    def __sshfs_import(self, user, source, exportpath, mountpath):
        if not os.path.exists(mountpath):
            os.makedirs(mountpath)
        
        cmd = SSHFS_IMPORT_CMD.substitute(USER=user,SOURCE=source,EXPORTPATH=exportpath, MOUNTPATH=mountpath)
        logging.debug(f"Executing SSHFS mount commadn: {cmd}")
        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            logging.error(f"SSHFS mount failed. {output}")
            return codes.FAILED

        logging.debug(f"SSHFS mount successful. {mountpath}")
        return codes.SUCCESS

    def __umount(self, mountpath):
        cmd = UMOUNT_CMD.substitute(MOUNTDIR=mountpath)
        logging.debug(f"Executing umount commadn: {cmd}")
        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            logging.error(f"umount failed. {output}")
            return codes.FAILED

        logging.debug(f"umount successful. {mountpath}")
        return codes.SUCCESS

    def __copy(self, source,target):
        print(f"copy! source: {source}, target: {target}")
        cmd = COPY_CMD.substitute(SRC=source,TARGET=target)
        
        logging.debug(f"Executing copy commadn: {cmd}")
        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            logging.error(f"copy failed. {output}")
            return codes.FAILED

        logging.debug(f"copy successful. {source}")
        return codes.SUCCESS

    
    def __scopy(self, source,target):
        print(f"scopy! source: {source}, target: {target}")
        cmd = SCOPY_CMD.substitute(SRC=source,TARGET=target)
        
        logging.debug(f"Executing copy commadn: {cmd}")
        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            logging.error(f"copy failed. {output}")
            return codes.FAILED

        logging.debug(f"copy successful. {source}")
        return codes.SUCCESS
    
    
    def __merge_fs(self, upper_dir, lower_dir, work_dir, mountpath):
        if not os.path.exists(mountpath):
            os.mkdir(mountpath)
        
        if not os.path.exists(upper_dir):
            os.mkdir(upper_dir)
        
        cmd = OVERLAY_MOUNT_CMD.substitute(UPPERDIR=upper_dir, LOWERDIR=lower_dir, WORKDIR=work_dir, MERGEDDIR=mountpath)
        logging.debug(f"Executing union mount command: {cmd}")
        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            logging.error(f"Union mount failed. {output}")
            return codes.FAILED
        
        logging.debug(f"Union mount successful. {mountpath}")
        return codes.SUCCESS

    def __storeMeta(self, containerName, nfsMount, cowdir, workdir, unionMount, lazycopydir):
        mdfile = util.getContainerMDFile(containerName)
        volMap = {}
        newVol = {}
        newVol["nfs"] = nfsMount
        newVol["cow"] = cowdir
        newVol["union"] = unionMount
        newVol["lazy"] = lazycopydir
        newVol['work'] = workdir

        if os.path.exists(mdfile):
            volMap = pickle.load(open(mdfile, "rb"))
        volMap[unionMount] = newVol
        pickle.dump(volMap, open(mdfile, "wb"))

    # def __storeSSHMeta(self, containerName, sshMount, cowdir, workdir, unionMount, lazycopydir):
    #     mdfile = util.getContainerMDFile(containerName)
    #     volMap = {}
    #     newVol = {}
    #     newVol["ssh"] = sshMount
    #     newVol["cow"] = cowdir
    #     newVol["union"] = unionMount
    #     newVol["lazy"] = lazycopydir
    #     newVol['work'] = workdir

    #     if os.path.exists(mdfile):
    #         volMap = pickle.load(open(mdfile, "rb"))
    #     volMap[unionMount] = newVol
    #     pickle.dump(volMap, open(mdfile, "wb"))
    
    def migrateVolume(self,config):
        sshUser=config["user"]
        sshSource=config["sourceHost"]
        sshExportPath=config["exportPath"]
        containerName=config["container"]
        targetVolume=config["targetVolume"]
        volcnt = config["volcnt"]

        volumeMountPath =util.getSSHFSVolumeDir(containerName, volcnt)

        if self.__sshfs_import(sshUser,sshSource,sshExportPath, volumeMountPath) == codes.SUCCESS:
            print(f"copy! source: {volumeMountPath}, target: {targetVolume}")
            self.__copy(volumeMountPath,targetVolume)
            return codes.SUCCESS
        return codes.FAILED


    def prepareTargetFS(self, config):
        containerName = config["container"]
        sourceHost = config["sourceHost"]
        exportPath = config["exportPath"]
        volcnt = config["volcnt"]

        nfsMount = util.getNFSMountDir(containerName, volcnt)
        cowdir = util.getCOWDir(containerName, volcnt)
        workdir = util.getWorkDir(containerName, volcnt)
        unionMount = util.getUnionMountDir(containerName, volcnt)
        lazycopydir = util.getLazyCopyDir(containerName, volcnt)

        nfsexport = f"{sourceHost}:{exportPath}"

        if self.__nfs_import(nfsexport, nfsMount) == codes.SUCCESS:
            if self.__merge_fs(lower_dir=nfsMount, upper_dir=cowdir, work_dir=workdir, mountpath=unionMount) == codes.SUCCESS:
                self.__storeMeta(containerName, nfsMount, cowdir, workdir, unionMount, lazycopydir)
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

    def sshfsMount(self, config):
        return self.__sshfs_import(config["user"], config["sourceHost"], 
                            config["exportPath"], config["mountPath"])

    def unmount(self, config):
        return self.__umount(config["mountPath"])

    def mountSSHFSVolume(self, config):
        sshUser=config["user"]
        sshSource=config["sourceHost"]
        sshExportPath=config["exportPath"]
        containerName=config["container"]
        volcnt = config["volcnt"]

        sshMountPath = util.getSSHFSMountDir(containerName, volcnt)
        cowdir = util.getCOWDir(containerName, volcnt)
        workdir = util.getWorkDir(containerName, volcnt)
        diffdir= util.getDiffDir(containerName, volcnt)
        initdir=util.getInitDir(containerName, volcnt)
        lazycopydir = util.getLazyCopyDir(containerName, volcnt)

        lowerdir=cowdir+":"+sshMountPath

        if self.__sshfs_import(sshUser,sshSource,sshExportPath, sshMountPath) == codes.SUCCESS:
            unionMount = config["initlower"]
            #TODO:需要处理sudo权限问题
            # util.copy_directory(unionMount,initdir)
            print(f"copy! source: {unionMount}, target: {initdir}")
            if "/var/lib/docker/overlay2" not in unionMount:
                print(f"copy Error: {unionMount} is not a docker overlay2 directory.")
                sys.exit(0) 
            if "/var/lib/criu" not in initdir:
                print(f"copy Error: {initdir} is not in /var/lib/criu")
                sys.exit(0)
            self.__copy(unionMount,initdir)
            util.delete_contents(unionMount)
            if self.__merge_fs(lower_dir=lowerdir, upper_dir=diffdir, work_dir=workdir, mountpath=unionMount) == codes.SUCCESS:
                #TODO:同样考虑sudo问题
                # util.copy_directory(initdir,unionMount)
                self.__copy(initdir,unionMount)
                # self.__storeMeta(containerName, nfsMount, cowdir, workdir, unionMount, lazycopydir)
                return codes.SUCCESS
        return codes.FAILED

    def rootFSCopy(self,config):
        containerName=config["container"]
        volcnt = config["volcnt"]
        cowdir = util.getCOWDir(containerName, volcnt)
        sshMountPath = util.getSSHFSMountDir(containerName, volcnt)
        if "/var/lib/criu" not in sshMountPath:
            print(f"Error! sshMountPath: {sshMountPath} is not in /var/lib/criu")
            sys.exit(0)
        if "/var/lib/criu" not in cowdir:
            print(f"Error! cowdir: {cowdir} is not in /var/lib/criu")
            sys.exit(0)
        self.fsreplicator=Fsreplicator(sshMountPath,cowdir)
        self.fsreplicator.start()
        return codes.SUCCESS

    def remountRootFS(self,config):
        containerName=config["container"]
        volcnt = config["volcnt"]
        unionMount = config["initlower"]
        cowdir = util.getCOWDir(containerName, volcnt)
        sshMountPath = util.getSSHFSMountDir(containerName, volcnt)
        workdir = util.getWorkDir(containerName, volcnt)
        diffdir= util.getDiffDir(containerName, volcnt)
        self.fsreplicator.join()
        #begin remount
        if self.__merge_fs(lower_dir=cowdir, upper_dir=diffdir, work_dir=workdir, mountpath=unionMount) == codes.SUCCESS:
            if self.__umount(sshMountPath)== codes.SUCCESS:
                return codes.SUCCESS
        return codes.FAILED


    def __exec(self, cmd):
        status, output = subprocess.getstatusoutput(cmd)
        if status != 0:
            logging.error(f"Executing command failed: {cmd} {output}")
        return status

    def failoverVolumes(self, containerID):
        mdfile = util.getContainerMDFile(containerID)

        volMap = {}
        if os.path.exists(mdfile):
            volMap = pickle.load(open(mdfile, "rb"))
        
        for unionMount, mountMap in list(volMap.items()):
            logging.debug(f"Starting failover for volume: {unionMount}")
            # 1. Un-mount aufs mount point
            logging.debug(f"Un-mounting aufs mount point: {unionMount}")
            
            cmd = OVERLAY_UMOUNT_CMD.substitute(MOUNT=unionMount)
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
            cmd = OVERLAY_UMOUNT_CMD.substitute(MOUNT=volMap[unionMount]['nfs'])
            self.__exec(cmd=cmd)

            return rc



