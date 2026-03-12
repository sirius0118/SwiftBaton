# SwiftBaton

This repository is used for reproduction and validation during the paper review stage. The steps below provide a detailed, executable workflow covering Docker component builds, CRIU compilation, Fluid deployment, and container live migration.

## 0. Directory layout

- `docker-ce/`: build `dockerd`, `runc`, `containerd`
- `criu/`: CRIU source
- `Fluid/`: apiserver/agent/cli
- `ArtifactEvalution/`: automation scripts (`run_migration.sh` is provided)

## 1. Build Docker binaries (dockerd/runc/containerd)

It is recommended to build inside a container to avoid polluting the host environment. The workflow below builds a container from the Dockerfile under `components/engine`, then compiles `dockerd`, `runc`, and `containerd` inside that container.

1) Build a dedicated build image from the Dockerfile

```bash
cd docker-ce/components/engine
docker build -t docker-engine-build -f Dockerfile .
cd /home/k8s/exper/zxz/live_migration/SwiftBaton/docker-ce
```

2) Start a build container from that image

```bash
docker run --rm -it \
	-v "$PWD":/work -w /work \
	docker-engine-build bash
```

3) Build inside the container (using `components/engine` as an example)

```bash
cd components/engine
# Common entry points: hack/make.sh or Makefile
if [ -x hack/make.sh ]; then
	hack/make.sh binary
else
	make binary
fi
```

4) Back on the host, locate and copy the binaries to `/bin`

```bash
cd /home/k8s/exper/zxz/live_migration/SwiftBaton
find docker-ce/components/engine -type f \( -name dockerd -o -name runc -o -name containerd \) -perm -111
sudo install -m 0755 <path/to/dockerd> /bin/dockerd
sudo install -m 0755 <path/to/runc> /bin/runc
sudo install -m 0755 <path/to/containerd> /bin/containerd
```

5) Set environment variables (if installed to `/bin` this is usually unnecessary; otherwise add to `PATH`)

```bash
export PATH=/bin:$PATH
```

> Note: build output paths can vary by version. Use `find` to locate the binaries. For stricter build commands, refer to the scripts or `Makefile` under `docker-ce/components/engine`.

## 2. Build CRIU (with RDMA-core dependencies)

1) Install RDMA-core and common build dependencies (Debian/Ubuntu example)

```bash
sudo apt-get update
sudo apt-get install -y \
	rdma-core libibverbs-dev librdmacm-dev \
	build-essential make pkg-config \
	libprotobuf-dev protobuf-c-compiler \
	libnl-3-dev libnet-dev libcap-dev \
	asciidoc xmlto
```

2) Build and install CRIU

```bash
cd /home/k8s/exper/zxz/live_migration/SwiftBaton/criu
make -j"$(nproc)"
sudo make install
```

> Note: install paths can be customized via `PREFIX`, `SBINDIR`, etc. in [criu/INSTALL.md](criu/INSTALL.md).

## 3. Start the Fluid apiserver (master node)

1) Update the config file

- [Fluid/server/config.cfg](Fluid/server/config.cfg)
	- `interface`: NIC name
	- `port`: apiserver port
	- `logfile`: log path
	- `etcd`: etcd host and port

2) Start etcd (example from [Fluid/README.md](Fluid/README.md))

```bash
docker run --net=host -d \
	gcr.io/google_containers/etcd:2.0.12 \
	/usr/local/bin/etcd \
	-addr=127.0.0.1:4001 \
	--bind-addr=0.0.0.0:4001 \
	--data-dir=/var/etcd/data
```

3) Start the apiserver

```bash
cd /home/k8s/exper/zxz/live_migration/SwiftBaton/Fluid/server
python3 apiserver.py
```

## 4. Start the Fluid agent (worker node)

```bash
cd /home/k8s/exper/zxz/live_migration/SwiftBaton/Fluid/agent
python3 agent.py
```

## 5. Start Redis and run YCSB load

1) Start a Redis container

```bash
docker run -d --name redis -p 6379:6379 redis:6
```

2) Run YCSB load against Redis (example image)

```bash
docker run --rm --network host \
	ghcr.io/brianfrankcooper/ycsb:0.17.0 \
	/bin/bash -lc "./bin/ycsb load redis -s -P workloads/workloada -p redis.host=127.0.0.1 -p redis.port=6379"
```

3) Run YCSB run against Redis and migrate during the run

```bash
docker run --rm --network host \
	ghcr.io/brianfrankcooper/ycsb:0.17.0 \
	/bin/bash -lc "./bin/ycsb run redis -s -P workloads/workloada -p redis.host=127.0.0.1 -p redis.port=6379"
```

> Note: adjust the Redis address, port, and YCSB workload to match your environment. Perform the container live migration while the `ycsb run` command is executing.

## 6. Trigger container live migration

Run the CLI on any node (typically the master):

```bash
cd /home/k8s/exper/zxz/live_migration/SwiftBaton/Fluid
python3 cli/fluid.py -m --rootfs \
	--target 4c38f255-df8f-4643-8428-ec202cbad4d4 \
	--source 5d4ca79e-7308-49f2-b267-cc3ef8c5e18e \
	--server 10.0.0.62:5000 \
	--container memcached1
```

- `--rootfs`: enable rootfs migration
- `-m`: perform migration
- `--target`: destination machine UUID
- `--source`: source machine UUID
- `--server`: apiserver address
- `--container`: container name

## 7. Automation script

An executable script is provided at [ArtifactEvalution/run_migration.sh](ArtifactEvalution/run_migration.sh). It supports role-based steps (build/criu/master/agent/migrate) and allows overriding parameters via environment variables.