#!/bin/sh
# Compares zrc with runc and crun: time per create, start, wait and delete
# of a container running /bin/true, and the runtime's peak RSS. Needs root,
# cgroup v2, busybox-static, runc, crun, jq and GNU time; `make bench` runs
# it in a privileged container:
#   tests/bench.sh /path/to/zrc [iterations]
set -u

ZRC=${1:?usage: bench.sh /path/to/zrc [iterations]}
N=${2:-200}

mkdir -p /sys/fs/cgroup/init
while read -r p; do echo "$p" > /sys/fs/cgroup/init/cgroup.procs 2>/dev/null; done < /sys/fs/cgroup/cgroup.procs

B=$(mktemp -d)
mkdir -p "$B/rootfs/bin" "$B/rootfs/proc" "$B/rootfs/dev" "$B/rootfs/sys"
cp /bin/busybox "$B/rootfs/bin/"
ln -s busybox "$B/rootfs/bin/true"
(cd "$B" && runc spec)
jq '.process.terminal = false | .process.args = ["/bin/true"] | del(.process.capabilities.ambient)' \
	"$B/config.json" > "$B/c" && mv "$B/c" "$B/config.json"

bench() { # name runtime-command...
	name=$1
	shift
	"$@" run -b "$B" warm > /dev/null || return 1
	start=$(date +%s%N)
	i=0
	while [ $i -lt "$N" ]; do
		"$@" run -b "$B" "b$i" > /dev/null || return 1
		i=$((i + 1))
	done
	end=$(date +%s%N)
	rss=$(/usr/bin/time -f %M "$@" run -b "$B" rss 2>&1 > /dev/null)
	echo "$name: $(((end - start) / N / 1000)) us per container, peak RSS $rss KiB"
}

bench zrc "$ZRC" --root /run/bench-zrc
bench crun crun --root /run/bench-crun
bench runc runc --root /run/bench-runc
