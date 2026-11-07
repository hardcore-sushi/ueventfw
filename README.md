# ueventfw

Forward kernel uevents to a different network namespace via seccomp system call interception.

Untagged kernel uevents, such as device hotplug events consumed by udev, are only broadcasted to the host/initial user namespace. Therefore, sandboxed applications running in a separate network namespace do not receive them by default.

`ueventfw` allows applications to transparently open `NETLINK_KOBJECT_UEVENT` sockets in the parent network namespace. Thus, they can receive uevents even when they run in a separate network namespace.

## Security notes

This program does not sandbox apps by default. It is intended to be used to launch a sandboxing utility such as [bubblewrap](https://github.com/containers/bubblewrap).

The spawned process and all of its descendants can see the kernel uevents of the namespace where `ueventfw` runs. Those events can reveal hardware and device topology. Only run code that you would trust with that information.

## Build and install

Install `ueventfw` to `/usr/local/bin`:

```sh
make
sudo make install
```

Uninstall:

```sh
sudo make uninstall
```

## Usage

```text
ueventfw <command> [args...]
```

Examples:

```sh
# Show kernel uevents from inside a new user and network namespace.
ueventfw unshare -Un udevadm monitor --kernel

# Run a sandboxed application that needs device hotplug events.
ueventfw bwrap --unshare-all --dev-bind / / --proc /proc -- my-app

# Enter an existing network namespace but keep host uevents.
ueventfw nsenter -t "$PID" -U -n --preserve-credentials udevadm monitor --kernel
```

## Debugging

Set `UEVENTFW_DEBUG=1` to print notification and descriptor-injection details to stderr:

```sh
UEVENTFW_DEBUG=1 ueventfw unshare -Un udevadm monitor --kernel
```

## How it works

1. `ueventfw` forks. The child installs a seccomp filter with `SECCOMP_FILTER_FLAG_NEW_LISTENER` and obtains a notification listener file descriptor.
2. The child passes the listener file descriptor to the supervisor over a `SOCK_SEQPACKET` Unix socketpair using `SCM_RIGHTS`, closes its copy, and executes the command.
3. The supervisor receives the file descriptor with `recvmsg(2)` and closes its side of the socketpair. Notifications are queued by the kernel until the supervisor handles them.
4. When the command or a descendant calls `socket(AF_NETLINK, ..., NETLINK_KOBJECT_UEVENT)`, the kernel stops that syscall and delivers a notification to the supervisor.
5. The supervisor opens the same kind of socket in its own network namespace and injects the descriptor in the child with `SECCOMP_IOCTL_NOTIF_ADDFD`.
6. The supervisor keeps serving notifications until no process with the filter remains. It then reaps the command and exits. It stays alive while any descendant still holds the filter, even after the directly spawned command exits. If the command exited normally, `ueventfw` returns its exit status. If it was killed by a signal, `ueventfw` exits with status 1.

## Limitations

- uevent sockets are opened in the network namespace where `ueventfw` was started. To see host uevents, start it in the host network namespace.
- Only `socket()` is intercepted. A netlink file descriptor received through `SCM_RIGHTS` or inherited from an already-running process is not emulated.
- Requires kernel support for seccomp user notifications and `SECCOMP_IOCTL_NOTIF_ADDFD` with `SECCOMP_ADDFD_FLAG_SEND` (Linux 5.14+).
- The filter matches the native socket syscall number. Compatibility ABIs are not explicitly supported.
- If `ueventfw` cannot install its seccomp filter without `no_new_privs`, typically because it was started without `CAP_SYS_ADMIN`, it sets `PR_SET_NO_NEW_PRIVS` on the command. In that case, setuid/setgid executables and file capabilities cannot grant privileges, which may break sandbox helpers such as a setuid `bwrap` or `newuidmap`.

## License

AGPL-3.0. See [LICENSE.txt](LICENSE.txt).
