#!/bin/sh
# Runs containers through containerd and its runc shim with zrc as the
# runtime binary. Needs root, cgroup v2 and network access; `make
# e2e-containerd` runs it in a privileged container:
#   tests/containerd.sh /path/to/zrc
set -u

ZRC=${1:?usage: containerd.sh /path/to/zrc}
IMAGE=docker.io/library/busybox:1.36
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); echo "ok   $1"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL $1"; shift; for l in "$@"; do echo "     $l"; done; }
expect_eq() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "want: $3" "got:  $2"; fi; }
expect_has() { case $2 in *"$3"*) ok "$1" ;; *) bad "$1" "want substring: $3" "got: $2" ;; esac; }

mkdir -p /sys/fs/cgroup/init
while read -r p; do echo "$p" > /sys/fs/cgroup/init/cgroup.procs 2>/dev/null; done < /sys/fs/cgroup/cgroup.procs

containerd > /tmp/containerd.log 2>&1 &
for _ in $(seq 100); do [ -S /run/containerd/containerd.sock ] && break; sleep 0.1; done
# The native snapshotter, as overlayfs cannot stack on the container's own.
ctr images pull --snapshotter native "$IMAGE" > /dev/null || { echo "pull failed"; exit 1; }
run() { ctr run --snapshotter native --runc-binary "$ZRC" "$@"; }

out=$(run --rm "$IMAGE" c1 sh -c 'echo hello; id -u' 2>&1)
expect_eq "run --rm" "$out" "$(printf 'hello\n0')"
run --rm "$IMAGE" c2 sh -c 'exit 42'
expect_eq "exit code" "$?" "42"
expect_has "seccomp" "$(run --rm --seccomp "$IMAGE" c3 grep Seccomp: /proc/self/status 2>&1)" "$(printf 'Seccomp:\t2')"

run -d "$IMAGE" c4 sleep 300
expect_has "detached: running" "$(ctr task ls)" "RUNNING"
expect_eq "cgroup holds the init" "$(cat /sys/fs/cgroup/default/c4/pids.current)" "1"
ctr task kill -s KILL c4
sleep 0.5
expect_has "kill: stopped" "$(ctr task ls)" "STOPPED"
ctr task rm c4
expect_eq "task rm" "$?" "0"
ctr container rm c4
expect_eq "cgroup removed" "$(test -d /sys/fs/cgroup/default/c4 && echo yes)" ""

out=$(run --rm --memory-limit 67108864 "$IMAGE" c5 true 2>&1)
expect_eq "limits" "$out" ""

echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
