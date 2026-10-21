# zrc

An OCI container runtime (a runc replacement) with no libc, no heap and no
panics. It speaks runc's command line, so containerd's `runc` shim can drive
it, and it reaches the kernel only through [xorpio](https://github.com/xorps/xorpio)'s
raw syscalls.

🚧 Under development.

| per container (create, start, wait, delete `/bin/true`) | time | peak RSS | binary |
|---|---|---|---|
| zrc | 3.3 ms | 1.3 MB | 113 KB |
| crun 1.21 | 7.1 ms | 3.1 MB | 619 KB |
| runc 1.1.15 | 18.8 ms | 12.7 MB | 10.7 MB |

(Same bundle and host, 200 runs each: `make bench`.)

## Design

- **No heap.** Memory is static or on the stack, sized to the kernel's own
  limits where it has one (`PATH_MAX`, `BPF_MAXINSNS`, 340 id-map extents,
  `NGROUPS_MAX`...). The 5 MB of static buffers are `.bss`: only the pages a
  container actually uses are ever touched.
- **Zero copy.** Arguments are used where the kernel put them. `config.json`
  is read once and parsed in place: strings are unescaped where they sit and
  NUL-terminated over their closing quote, so each one goes to a syscall
  without being copied. Mount options split at `=` the same way.
- **No panics.** Release builds prove it: the panic handler calls a symbol
  that does not exist, so a build that still has a panic path fails to
  link. `make panics` lists where such paths come from.
- **No swallowed errors.** Every function returns an error type with exactly
  the variants it can produce, and every failure names its cause, e.g.
  `zrc: create: init: mount: fsconfig /tmp 'size': EINVAL`. Spec settings
  zrc does not implement are refused, never ignored.

## Security

- Mount targets are resolved inside the rootfs with `openat2(RESOLVE_IN_ROOT)`,
  so symlinks in an image cannot redirect a mount onto the host.
- Mounts are built with the fd-based mount API: attributes such as `ro` are
  set before a mount is attached, so it is never briefly writable.
- The init is cloned straight into its cgroup (`CLONE_INTO_CGROUP`): no
  process of the container ever runs outside its limits.
- Device access is enforced with a cgroup v2 eBPF device filter, denying
  by default as runc does.
- seccomp profiles are compiled with argument conditions; x32 and foreign
  architecture syscalls are killed.
- `kill` and `delete` signal through a pidfd checked against the init's
  start time, so a reused pid is never signalled.
- `maskedPaths`, `readonlyPaths`, supplementary groups and the bounding set
  are applied as in runc.

Not yet done: writes to `/proc` during setup (sysctls, `oom_score_adj`,
LSM labels) go through the container's own procfs mount without checking
that it is procfs.

## Requirements

Linux 5.14 or later (`cgroup.kill`, `mount_setattr`, `clone3` into a
cgroup), cgroup v2, x86_64 or aarch64. zrc runs as root.

## Build and use

```sh
make build                 # release builds for both architectures
make check                 # fmt + clippy
make e2e                   # end-to-end tests as root in a privileged container
make e2e-containerd        # the same through containerd's runc shim
```

The binary is `target/<arch>-unknown-none/release/zrc`. With containerd, set
it as the runc binary, e.g. `ctr run --runc-binary /usr/local/bin/zrc ...` or
`BinaryName` in the runc runtime options.

```
zrc [--root dir] create [-b bundle] [--pid-file file] <id>
zrc [--root dir] start|state|delete [--force]|kill [--all] <id> [signal]
zrc run [-b bundle] <id>     # create, start, wait, delete; exits with the container's status
```

## Sysbox mode

Built with `--features sysbox` (off by default), a container annotated
`org.zrc.sysbox=true` becomes a system container: it gets its own user
namespace, mapping container root to host uids 100000-165535 unless the
spec maps it, and its own cgroup namespace. Without the feature the
annotation is an error.

The rest of Sysbox, emulated `/proc` and `/sys` and seccomp-notify syscall
interception, needs a long-lived agent beside the container, which a
one-shot runtime cannot be.

## Not supported (refused if requested)

Terminals (`process.terminal`, `--console-socket`), hooks, seccomp notify
(`SCMP_ACT_NOTIFY`, `listenerPath`), the systemd cgroup driver, cgroup v1,
new time namespaces, shared mount propagation, id-mapped mounts, `blockIO`/`network`/`rdma` limits,
`linux.mountLabel`, `exec`, `ps`, `update`, `pause`. Seccomp filters allow
only the native architecture (32-bit x86 binaries are killed).
