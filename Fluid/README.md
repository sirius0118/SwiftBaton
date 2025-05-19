# Fluid: a tool of container migration

## Usage
1. update the config
2. start a etcd for storage metadata
3. start a apiserver in master node
4. start agent in work node
5. migrate a container


```bash
# In master node
$ docker run --net=host -d gcr.io/google_containers/etcd:2.0.12 /usr/local/bin/etcd -addr=127.0.0.1:4001 --bind-addr=0.0.0.0:4001 --data-dir=/var/etcd/data
$ cd server; python3 apiserver.py

# In work node
$ cd agent; python3 agent.py
```

### Show the status
`python3 cli/fluid.py -l --server 192.168.142.133:5000`

### Migrate a container
`python3 cli/fluid.py -m --source 27d05451-dab1-43bc-a39a-55bea17c3b7b --container nginx3 --target 4ecb6da1-8600-44cf-81e8-1e090c5123f1 --server 192.168.142.133:5000`

## API explanation
For agent, add three op for rootfs migration:
- SSH_IMPORT_FS: use sshfs to mount source's merged to dst; use overlay to remount init for new container
- ROOTFS_COPY: start a thread to copy source's rootfs
- REMOUNT: wait for finish of copy; remount init with overlay

