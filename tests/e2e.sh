#!/bin/sh
# End-to-end tests. Runs as root on a cgroup v2 Linux host, normally inside
# the privileged container started by `make e2e`:
#   tests/e2e.sh /path/to/zrc [/path/to/zrc-built-with-sysbox]
set -u

ZRC=${1:?usage: e2e.sh /path/to/zrc [/path/to/zrc-sysbox]}
ZRC_SYSBOX=${2:-}
WORK=$(mktemp -d)
ROOT=$WORK/state
PASS=0
FAIL=0

ok() { PASS=$((PASS + 1)); echo "ok   $1"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL $1"; shift; for l in "$@"; do echo "     $l"; done; }
expect_eq() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "want: $3" "got:  $2"; fi; }
expect_has() { case $2 in *"$3"*) ok "$1" ;; *) bad "$1" "want substring: $3" "got: $2" ;; esac; }

# cgroup v2 forbids processes in a cgroup that delegates controllers, so
# move everything into a leaf first (as docker-in-docker does).
mkdir -p /sys/fs/cgroup/init
while read -r p; do echo "$p" > /sys/fs/cgroup/init/cgroup.procs 2>/dev/null; done < /sys/fs/cgroup/cgroup.procs

# A busybox rootfs.
mkrootfs() {
	mkdir -p "$1/bin" "$1/proc" "$1/sys" "$1/dev" "$1/etc" "$1/tmp"
	cp /bin/busybox "$1/bin/busybox"
	for c in sh echo cat id ls mount mknod head sleep grep sed hostname true false touch wc unshare umask; do
		ln -s busybox "$1/bin/$c"
	done
	echo "root:x:0:0:root:/:/bin/sh" > "$1/etc/passwd"
}

# A bundle with the default runc spec, adjusted by a jq filter, which gets
# any further arguments as $ARGS.positional.
mkbundle() {
	b=$WORK/$1
	f=$2
	shift 2
	mkdir -p "$b"
	mkrootfs "$b/rootfs"
	(cd "$b" && runc spec)
	# runc's ambient caps are not inheritable, which zrc rejects.
	jq '.process.terminal = false | .process.args = ["sh", "-c", "exit 0"] | del(.process.capabilities.ambient) | '"$f" "$b/config.json" --args -- "$@" > "$b/c" &&
		mv "$b/c" "$b/config.json"
	echo "$b"
}

z() { "$ZRC" --root "$ROOT" "$@"; }

# ---- run ----
B=$(mkbundle run '.process.args = ["sh", "-c", "echo hello; exit 3"]')
out=$(z run -b "$B" run1 2>&1); code=$?
expect_eq "run: output" "$out" "hello"
expect_eq "run: exit code" "$code" "3"

# Outside a pid namespace: its init would ignore the signal.
B=$(mkbundle sig '.process.args = ["sh", "-c", "kill -9 $$"] | .linux.namespaces |= map(select(.type != "pid"))')
z run -b "$B" sig1 >/dev/null 2>&1; code=$?
expect_eq "run: killed by signal is 128+9" "$code" "137"

# ---- lifecycle ----
B=$(mkbundle life '.process.args = ["sleep", "100"]')
z create -b "$B" --pid-file "$WORK/pid" life1; code=$?
expect_eq "create" "$code" "0"
expect_has "state: created" "$(z state life1)" '"status":"created"'
pid=$(cat "$WORK/pid")
expect_has "state: pid matches pid file" "$(z state life1)" "\"pid\":$pid"
expect_has "state: absolute bundle" "$(z state life1)" "\"bundle\":\"$B\""
out=$(z create -b "$B" life1 2>&1); code=$?
expect_has "create: duplicate id" "$out" "already exists"
z start life1; code=$?
expect_eq "start" "$code" "0"
expect_has "state: running" "$(z state life1)" '"status":"running"'
expect_has "process is sleep" "$(cat /proc/$pid/cmdline | tr '\0' ' ')" "sleep 100"
out=$(z start life1 2>&1)
expect_has "start: twice" "$out" "container is running, not created"
out=$(z delete life1 2>&1)
expect_has "delete: refuses running" "$out" "is running"
z kill life1 KILL; code=$?
expect_eq "kill" "$code" "0"
sleep 0.2
expect_has "state: stopped" "$(z state life1)" '"status":"stopped"'
out=$(z kill life1 2>&1)
expect_has "kill: stopped" "$out" "container not running"
z delete life1; code=$?
expect_eq "delete" "$code" "0"
out=$(z state life1 2>&1)
expect_has "state: deleted" "$out" "no such container"
expect_eq "delete: cgroup removed" "$(test -d /sys/fs/cgroup/zrc/life1 && echo yes)" ""
z delete --force life1; code=$?
expect_eq "delete --force: missing is fine" "$code" "0"

z create -b "$B" created1
z delete created1; code=$?
expect_eq "delete: created container without --force" "$code" "0"
expect_eq "delete: created container's init is gone" "$(z state created1 2>&1)" "zrc: state: no such container"

z create -b "$B" life2 && z start life2
z delete --force life2; code=$?
expect_eq "delete --force: running" "$code" "0"
expect_eq "delete --force: cgroup removed" "$(test -d /sys/fs/cgroup/zrc/life2 && echo yes)" ""

z create -b "$B" life3 && z start life3
z kill --all life3 KILL; code=$?
expect_eq "kill --all" "$code" "0"
sleep 0.2
expect_has "kill --all: stopped" "$(z state life3)" '"status":"stopped"'
z delete life3

# ---- errors are reported, not swallowed ----
B=$(mkbundle noexec '.process.args = ["/nonexistent"]')
z create -b "$B" noexec1
out=$(z start noexec1 2>&1); code=$?
expect_eq "start: exec failure exits 1" "$code" "1"
expect_has "start: exec failure says why" "$out" "execve: ENOENT"
z delete --force noexec1

B=$(mkbundle nopath '.process.args = ["nonexistent-cmd"]')
out=$(z create -b "$B" nopath1 2>&1)
expect_has "create: PATH lookup failure" "$out" "find executable nonexistent-cmd: ENOENT"
expect_eq "create: failure leaves no state" "$(ls "$ROOT" | grep nopath1)" ""

B=$(mkbundle badcap '.process.capabilities.bounding += ["CAP_NOPE"]')
out=$(z create -b "$B" badcap 2>&1)
expect_has "create: unknown capability" "$out" "unknown capability 'CAP_NOPE'"

B=$(mkbundle ambient '.process.capabilities.ambient = ["CAP_KILL"]')
out=$(z create -b "$B" ambient 2>&1)
expect_has "create: ambient caps must be inheritable" "$out" "missing process.capabilities.ambient entries in permitted and inheritable"

B=$(mkbundle badjson '.')
printf '{"root": {"path": "rootfs"},' > "$B/config.json"
out=$(z create -b "$B" badjson 2>&1)
expect_has "create: truncated json" "$out" "unexpected end of input at byte 28"

B=$(mkbundle badmount '.mounts += [{"destination": "/x", "type": "tmpfs", "source": "tmpfs", "options": ["bogus=1"]}]')
out=$(z create -b "$B" badmount 2>&1)
expect_has "create: bad mount option" "$out" "mount: fsconfig /x 'bogus': EINVAL"

B=$(mkbundle term '.process.terminal = true')
out=$(z create -b "$B" term 2>&1)
expect_has "create: terminal unsupported" "$out" "process.terminal is not supported"

out=$(z delete ../escape 2>&1); code=$?
expect_eq "cli: path-like id is a usage error" "$code" "2"
out=$(z frobnicate 2>&1)
expect_has "cli: unknown command" "$out" "unknown command 'frobnicate'"
out=$(z create --frob x 2>&1)
expect_has "cli: unknown flag" "$out" "unknown option '--frob'"

# ---- isolation ----
inside() { # bundle-name jq-filter command...
	n=$1; f=$2; shift 2
	B=$(mkbundle "$n" "$f"' | .process.args = $ARGS.positional' "$@")
	z run -b "$B" "$n" 2>&1
}
expect_eq "hostname" "$(inside host '.hostname = "boxy"' hostname)" "boxy"
expect_eq "pid 1" "$(inside pid1 '.' sh -c 'echo $$')" "1"
expect_eq "masked /proc/keys" "$(inside mask '.' sh -c 'wc -c < /proc/keys')" "0"
expect_has "readonly /proc/sys" "$(inside ro '.' sh -c 'echo 1 > /proc/sys/kernel/domainname')" "Read-only file system"
expect_has "/dev/null" "$(inside devnull '.' sh -c 'echo x > /dev/null && echo ok')" "ok"
# runc's defaults: CAP_KILL, CAP_NET_BIND_SERVICE, CAP_AUDIT_WRITE.
expect_eq "default caps" "$(inside caps '.' sh -c 'grep CapEff /proc/self/status')" "$(printf 'CapEff:\t0000000020000420')"
expect_eq "bounding set" "$(inside capbnd '.' sh -c 'grep CapBnd /proc/self/status')" "$(printf 'CapBnd:\t0000000020000420')"
expect_eq "umask" "$(inside umask '.' sh -c 'umask')" "0022"
expect_eq "uid/gid" "$(inside user '.process.user = {"uid": 1000, "gid": 1000}' id)" "uid=1000 gid=1000"
expect_eq "no supplementary groups leak" "$(inside groups '.' sh -c 'grep Groups /proc/self/status')" "$(printf 'Groups:\t ')"

expect_has "ro bind mount is read-only" \
	"$(inside robind '.mounts += [{"destination": "/data", "type": "bind", "source": "/etc", "options": ["rbind", "ro", "rprivate"]}]' sh -c 'touch /data/x')" \
	"Read-only file system"
echo hosts-file > "$WORK/hostsfile"
expect_eq "file bind mount" \
	"$(inside filebind '.mounts += [{"destination": "/etc/hosts", "type": "bind", "source": "'"$WORK/hostsfile"'", "options": ["bind", "ro"]}]' cat /etc/hosts)" \
	"hosts-file"

# A symlink in the image must not redirect a mount onto the host.
B=$(mkbundle escape '.mounts += [{"destination": "/evil/inner", "type": "tmpfs", "source": "tmpfs"}] | .process.args = ["true"]')
mkdir -p "$WORK/hostdir" "$B/rootfs$WORK/hostdir"
ln -s "$WORK/hostdir" "$B/rootfs/evil"
out=$(z run -b "$B" escape 2>&1); code=$?
expect_eq "symlink escape: runs" "$code: $out" "0: "
expect_eq "symlink escape: host untouched" "$(ls "$WORK/hostdir")" ""
expect_eq "symlink escape: created inside" "$(test -d "$B/rootfs$WORK/hostdir/inner" && echo yes)" "yes"

# ---- cgroup limits ----
expect_eq "memory limit" "$(inside mem '.linux.resources.memory.limit = 67108864' cat /sys/fs/cgroup/memory.max)" "67108864"
expect_eq "pids limit" "$(inside pids '.linux.resources.pids = {"limit": 7}' cat /sys/fs/cgroup/pids.max)" "7"
expect_eq "cpu quota" "$(inside cpu '.linux.resources.cpu = {"quota": 50000, "period": 100000}' cat /sys/fs/cgroup/cpu.max)" "50000 100000"
expect_eq "swap is limit + swap" \
	"$(inside swap '.linux.resources.memory = {"limit": 67108864, "swap": 100663296}' cat /sys/fs/cgroup/memory.swap.max)" "33554432"
expect_eq "cgroup namespace root" "$(inside cgns '.' cat /proc/self/cgroup)" "0::/"

# CAP_MKNOD is in runc's defaults; the device filter must still stop /dev/sda.
B=$(mkbundle dev '.process.capabilities.bounding += ["CAP_MKNOD"] | .process.capabilities.effective += ["CAP_MKNOD"] | .process.capabilities.permitted += ["CAP_MKNOD"]')
cat > "$B/c.jq" <<'J'
.linux.resources.devices = [{"allow": false, "access": "rwm"}, {"allow": true, "type": "c", "major": 1, "minor": 3, "access": "rwm"}]
| .process.args = ["sh", "-c", "mknod /dev/sda b 8 0; echo x > /dev/null && echo null-ok"]
J
jq -f "$B/c.jq" "$B/config.json" > "$B/c" && mv "$B/c" "$B/config.json"
out=$(z run -b "$B" dev 2>&1)
expect_has "device filter denies mknod" "$out" "mknod: /dev/sda: Operation not permitted"
expect_has "device filter allows /dev/null" "$out" "null-ok"

# ---- user namespace ----
expect_eq "userns: root inside" \
	"$(inside userns '.linux.namespaces += [{"type": "user"}] | .linux.uidMappings = [{"containerID": 0, "hostID": 100000, "size": 65536}] | .linux.gidMappings = [{"containerID": 0, "hostID": 100000, "size": 65536}]' sh -c 'id -u; cat /proc/self/uid_map')" \
	"$(printf '0\n         0     100000      65536')"

# ---- seccomp: Docker's default profile ----
if [ -f /work/default.json ]; then
	# Resolve Docker's includes/excludes the way dockerd would for these
	# caps and this architecture (Docker's names: amd64, arm64).
	cat > "$WORK/resolve.jq" <<'J'
def caps: ["CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE"];
.linux.seccomp = ($profile[0] | .syscalls |= map(select(
	((.includes.caps // []) - caps | length == 0)
	and ((.includes.arches // [$arch]) | index($arch) != null)
	and ((.excludes.caps // []) - ((.excludes.caps // []) - caps) | length == 0)
	and ((.excludes.arches // []) | index($arch) == null)
) | del(.includes, .excludes, .comment)))
J
	B=$(mkbundle seccomp '.')
	jq --arg arch "$(dpkg --print-architecture)" --slurpfile profile /work/default.json -f "$WORK/resolve.jq" "$B/config.json" > "$B/c" && mv "$B/c" "$B/config.json"
	run_sc() { jq '.process.args = $ARGS.positional' "$B/config.json" --args -- "$@" > "$B/c" && mv "$B/c" "$B/config.json"; z run -b "$B" seccomp 2>&1; }
	expect_has "seccomp: filter on" "$(run_sc grep Seccomp: /proc/self/status)" "$(printf 'Seccomp:\t2')"
	expect_has "seccomp: ordinary work" "$(run_sc sh -c 'echo hi | cat; ls / >/dev/null && echo fine')" "hi"
	expect_has "seccomp: unshare(CLONE_NEWUSER) is refused" "$(run_sc unshare -U true)" "Operation not permitted"
else
	echo "skip seccomp (no /work/default.json)"
fi

# ---- review fixes ----
expect_eq "sysctl with /proc/sys read-only" \
	"$(inside sysctl '.linux.sysctl = {"net.ipv4.ip_unprivileged_port_start": "0"}' cat /proc/sys/net/ipv4/ip_unprivileged_port_start)" "0"
expect_has "shared propagation is refused" "$(inside shared '.linux.rootfsPropagation = "rshared"' true)" "shared mount propagation is not supported"
B=$(mkbundle nodev 'del(.linux.resources.devices) | .process.capabilities.bounding += ["CAP_MKNOD"] | .process.capabilities.effective += ["CAP_MKNOD"] | .process.capabilities.permitted += ["CAP_MKNOD"] | .process.args = ["sh", "-c", "mknod /dev/sda b 8 0"]')
expect_has "no device rules still denies by default" "$(z run -b "$B" nodev 2>&1)" "Operation not permitted"
if [ -b /dev/loop0 ]; then
	B=$(mkbundle givendev '.linux.devices = [{"path": "/dev/loop0", "type": "b", "major": 7, "minor": 0}] | .process.args = ["sh", "-c", "head -c1 /dev/loop0 >/dev/null; echo done"]')
	out=$(z run -b "$B" givendev 2>&1)
	case $out in *"Operation not permitted"*) bad "linux.devices are allowed" "$out" ;; *) ok "linux.devices are allowed" ;; esac
fi

# A create killed before its state was written: delete --force still cleans up.
mkdir -p "$ROOT/broken" && echo junk > "$ROOT/broken/state"
z delete --force broken; code=$?
expect_eq "delete --force: corrupt state" "$code: $(ls "$ROOT" | grep broken)" "0: "

# Child cgroups (as systemd or docker in the container would make).
B=$(mkbundle nested '.process.args = ["sleep", "100"]')
z create -b "$B" nested && z start nested
mkdir /sys/fs/cgroup/zrc/nested/child /sys/fs/cgroup/zrc/nested/child/grandchild
sleep 100 & stray=$!
echo $stray > /sys/fs/cgroup/zrc/nested/child/grandchild/cgroup.procs
z delete --force nested; code=$?
expect_eq "delete --force: nested cgroups" "$code: $(test -d /sys/fs/cgroup/zrc/nested && echo left)" "0: "
wait $stray 2>/dev/null
expect_eq "delete --force: killed processes in child cgroups" "$(kill -0 $stray 2>/dev/null && echo alive)" ""

# Joining namespaces: a host-owned network namespace from a new user
# namespace, and another container's user and network namespaces.
B=$(mkbundle nshost '.process.args = ["sleep", "100"]')
z create -b "$B" nshost && z start nshost
hostpid=$(z state nshost | sed 's/.*"pid":\([0-9]*\).*/\1/')
USERNS='.linux.namespaces += [{"type": "user"}] | .linux.uidMappings = [{"containerID": 0, "hostID": 100000, "size": 65536}] | .linux.gidMappings = [{"containerID": 0, "hostID": 100000, "size": 65536}]'
B=$(mkbundle nsuser "$USERNS"' | .process.args = ["sleep", "100"]')
z create -b "$B" nsuser && z start nsuser
userpid=$(z state nsuser | sed 's/.*"pid":\([0-9]*\).*/\1/')
chmod 755 "$WORK"
expect_eq "new user namespace joins a host-owned network namespace" \
	"$(inside joinnet "$USERNS"' | .linux.namespaces |= map(if .type == "network" then .path = "/proc/'"$hostpid"'/ns/net" else . end)' sh -c 'readlink /proc/self/ns/net')" \
	"$(readlink /proc/$hostpid/ns/net)"
expect_eq "joined user namespace with new mount and uts namespaces" \
	"$(inside joinuser '.hostname = "joined" | .linux.namespaces |= (map(if .type == "network" then .path = "/proc/'"$userpid"'/ns/net" else . end) + [{"type": "user", "path": "/proc/'"$userpid"'/ns/user"}])' sh -c 'hostname; id -u; cat /proc/self/uid_map')" \
	"$(printf 'joined\n0\n         0     100000      65536')"
z delete --force nshost
z delete --force nsuser

# ---- sysbox ----
B=$(mkbundle sysbox '.annotations["org.zrc.sysbox"] = "true" | .process.args = ["sh", "-c", "id -u; cat /proc/self/uid_map /proc/self/cgroup"]')
out=$(z run -b "$B" sysbox 2>&1)
expect_has "sysbox: refused without the feature" "$out" "needs zrc built with --features sysbox"
if [ -n "$ZRC_SYSBOX" ]; then
	# Container root is host uid 100000, which needs to reach the bundle.
	chmod 755 "$WORK"
	out=$("$ZRC_SYSBOX" --root "$ROOT" run -b "$B" sysbox 2>&1)
	expect_eq "sysbox: root in a user and cgroup namespace" "$out" "$(printf '0\n         0     100000      65536\n0::/')"
fi

echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
