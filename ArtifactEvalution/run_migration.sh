#!/usr/bin/env bash
set -euo pipefail

# SwiftBaton end-to-end script for build and migration demo.
# Use ROLE to run subsets: all|build|criu|master|agent|redis|ycsb_load|ycsb_run|migrate

ROLE="${ROLE:-all}"
ROOT_DIR="/home/k8s/exper/zxz/live_migration/SwiftBaton"

DOCKER_CE_DIR="$ROOT_DIR/docker-ce"
ENGINE_DIR="$DOCKER_CE_DIR/components/engine"
CRIU_DIR="$ROOT_DIR/criu"
FLUID_DIR="$ROOT_DIR/Fluid"

APISERVER_HOSTPORT="${APISERVER_HOSTPORT:-10.0.0.62:5000}"
TARGET_UUID="${TARGET_UUID:-4c38f255-df8f-4643-8428-ec202cbad4d4}"
SOURCE_UUID="${SOURCE_UUID:-5d4ca79e-7308-49f2-b267-cc3ef8c5e18e}"
CONTAINER_NAME="${CONTAINER_NAME:-memcached1}"

REDIS_IMAGE="${REDIS_IMAGE:-redis:6}"
YCSB_IMAGE="${YCSB_IMAGE:-ghcr.io/brianfrankcooper/ycsb:0.17.0}"
YCSB_WORKLOAD="${YCSB_WORKLOAD:-workloads/workloada}"
REDIS_HOST="${REDIS_HOST:-127.0.0.1}"
REDIS_PORT="${REDIS_PORT:-6379}"

ETCD_IMAGE="${ETCD_IMAGE:-gcr.io/google_containers/etcd:2.0.12}"
ETCD_NAME="${ETCD_NAME:-fluid-etcd}"
REDIS_NAME="${REDIS_NAME:-redis}"

BIN_DIR="${BIN_DIR:-/bin}"

run_build() {
  echo "[build] Build docker-engine image and compile binaries inside it"
  pushd "$ENGINE_DIR" >/dev/null
  docker build -t docker-engine-build -f Dockerfile .
  popd >/dev/null

  docker run --rm -it \
    -v "$DOCKER_CE_DIR":/work -w /work \
    docker-engine-build bash -lc "cd components/engine && if [ -x hack/make.sh ]; then hack/make.sh binary; else make binary; fi"

  echo "[build] Locate and install dockerd/runc/containerd into $BIN_DIR"
  find "$ENGINE_DIR" -type f \( -name dockerd -o -name runc -o -name containerd \) -perm -111
  sudo install -m 0755 "$(find "$ENGINE_DIR" -type f -name dockerd -perm -111 | head -n 1)" "$BIN_DIR/dockerd"
  sudo install -m 0755 "$(find "$ENGINE_DIR" -type f -name runc -perm -111 | head -n 1)" "$BIN_DIR/runc"
  sudo install -m 0755 "$(find "$ENGINE_DIR" -type f -name containerd -perm -111 | head -n 1)" "$BIN_DIR/containerd"
}

run_criu() {
  echo "[criu] Build and install CRIU"
  pushd "$CRIU_DIR" >/dev/null
  make -j"$(nproc)"
  sudo make install
  popd >/dev/null
}

run_master() {
  echo "[master] Start etcd and apiserver"
  docker rm -f "$ETCD_NAME" >/dev/null 2>&1 || true
  docker run --net=host -d --name "$ETCD_NAME" \
    "$ETCD_IMAGE" \
    /usr/local/bin/etcd \
    -addr=127.0.0.1:4001 \
    --bind-addr=0.0.0.0:4001 \
    --data-dir=/var/etcd/data

  pushd "$FLUID_DIR/server" >/dev/null
  python3 apiserver.py
  popd >/dev/null
}

run_agent() {
  echo "[agent] Start agent"
  pushd "$FLUID_DIR/agent" >/dev/null
  python3 agent.py
  popd >/dev/null
}

run_redis() {
  echo "[redis] Start Redis container"
  docker rm -f "$REDIS_NAME" >/dev/null 2>&1 || true
  docker run -d --name "$REDIS_NAME" -p "$REDIS_PORT":6379 "$REDIS_IMAGE"
}

run_ycsb_load() {
  echo "[ycsb] Load data"
  docker run --rm --network host \
    "$YCSB_IMAGE" \
    /bin/bash -lc "./bin/ycsb load redis -s -P $YCSB_WORKLOAD -p redis.host=$REDIS_HOST -p redis.port=$REDIS_PORT"
}

run_ycsb_run() {
  echo "[ycsb] Run workload"
  docker run --rm --network host \
    "$YCSB_IMAGE" \
    /bin/bash -lc "./bin/ycsb run redis -s -P $YCSB_WORKLOAD -p redis.host=$REDIS_HOST -p redis.port=$REDIS_PORT"
}

run_migrate() {
  echo "[migrate] Trigger live migration"
  pushd "$FLUID_DIR" >/dev/null
  python3 cli/fluid.py -m --rootfs \
    --target "$TARGET_UUID" \
    --source "$SOURCE_UUID" \
    --server "$APISERVER_HOSTPORT" \
    --container "$CONTAINER_NAME"
  popd >/dev/null
}

case "$ROLE" in
  all)
    run_build
    run_criu
    run_redis
    run_ycsb_load
    echo "[info] Start ycsb run in another terminal, then run ROLE=migrate"
    ;;
  build) run_build ;;
  criu) run_criu ;;
  master) run_master ;;
  agent) run_agent ;;
  redis) run_redis ;;
  ycsb_load) run_ycsb_load ;;
  ycsb_run) run_ycsb_run ;;
  migrate) run_migrate ;;
  *)
    echo "Unknown ROLE: $ROLE"
    exit 1
    ;;
esac
