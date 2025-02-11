% mkosi-sandbox(1)
%
%

# NAME

mkosi-sandbox — Run commands in a custom sandbox

# SYNOPSIS

`mkosi-sandbox [options…] command [arguments]`

# DESCRIPTION

`mkosi-sandbox` runs the given command in a custom sandbox. The sandbox is configured
by specifying command line options that configure individual parts of the sandbox.

If no command is specified, `mkosi-sandbox` will start `bash` in the sandbox.

Note that this sandbox is not designed to be a security boundary. Its intended purpose
is to allow running commands in an isolated environment so they are not affected by the
host system.

# OPTIONS

`--tmpfs DST`
:   Mounts a new tmpfs at `DST` in the sandbox.

`--dev DST`
:   Sets up a private `/dev` at `DST` in the sandbox. This private `/dev` will only
    contain the basic device nodes required for a functioning sandbox (e.g. `/dev/null`)
    and no actual devices.

`--proc DST`
:  Mounts `/proc` from the host at `DST` in the sandbox.

`--dir DST`
:   Creates a directory and all missing parent directories at `DST` in the sandbox.
    All directories are created with mode 755 unless the path ends with `/tmp` or
    `/var/tmp` in which case it is created with mode 1777.

`--bind SRC DST`
:   The source path `SRC` is recursively bind mounted to `DST` in the sandbox. The
    mountpoint is created in the sandbox if it does not yet exist. Any missing parent
    directories in the sandbox are created as well.

`--bind-try SRC DST`
:   Like `--bind`, but doesn't fail if the source path doesn't exist.

`--ro-bind SRC DST`
:   Like `--bind`, but does a recursive readonly bind mount.

`--ro-bind-try SRC DST`
:   Like `--bind-try`, but does a recursive readonly bind mount.

`--symlink SRC DST`
:   Creates a symlink at `DST` in the sandbox pointing to `SRC`. If `DST` already
    exists and is a file or symlink, a temporary symlink is created and mounted on
    top of `DST`.

`--write DATA DST`
:   Writes the string from `DATA` to `DST` in the sandbox.

`--overlay-lowerdir DIR`
:   Adds `DIR` from the host as a new lower directory for the next overlayfs mount.

`--overlay-upperdir DIR`
:   Sets the upper directory for the next overlayfs mount to `DIR` from the host. If
    set to `tmpfs`, the upperdir and workdir will be subdirectories of a fresh tmpfs
    mount.

`--overlay-workdir DIR`
:   Sets the working directory for the next overlayfs mount to `DIR` from the host.

`--overlay DST`
:   Mounts a new overlay filesystem at `DST` in the sandbox. The lower directories, upper
    directory and working directory are specified using the `--overlay-lowerdir`,
    `--overlay-upperdir` and `--overlay-workdir` options respectively. After each
    `--overlay` option is parsed, the other overlay options are reset.

`--unsetenv NAME`
:   Unsets the `NAME` environment variable in the sandbox.

`--setenv NAME VALUE`
:   Sets the `NAME` environment variable to `VALUE` in the sandbox

`--chdir DIR`
:   Changes the working directory to `DIR` in the sandbox.

`--same-dir`
:   Changes to the working directory in the sandbox to the current working directory that
    `mkosi-sandbox` is invoked in on the host.

`--become-root`
:   Maps the current user to the root user in the sandbox. If this option is not specified,
    the current user is mapped to itself in the sandbox. Regardless of whether this option
    is specified or not, the current user will have a full set of ambient capabilities in
    the sandbox. This includes `CAP_SYS_ADMIN` which means that the invoked process in the
    sandbox will be able to do bind mounts and other operations.

    If `mkosi-sandbox` is invoked as the root user, this option won't do anything.

`--suppress-chown`
:   Specifying this option causes all calls to `chown()` or similar system calls to become a
    noop in the sandbox. This is primarily useful when invoking package managers in the
    sandbox which might try to `chown()` files to different users or groups which would fail
    unless `mkosi-sandbox` is invoked by a privileged user.

`--unshare-net`
:   Specifying this option makes `mkosi-sandbox` unshare a network namespace if possible.

`--unshare-ipc`
:   Specifying this option makes `mkosi-sandbox` unshare an IPC namespace if possible.

`--suspend`
:   Make the `mkosi-sandbox` process suspend itself with `SIGSTOP` just before it calls `execve()`.
    This is useful to wait until all setup logic has completed before continuing execution in the parent
    process invoking `mkosi-sandbox` by using `waitid()` with the `WNOWAIT` AND `WSTOPPED` flags.

`--version`
:   Show package version.

`--help`, `-h`
:   Show brief usage information.

# EXAMPLES

Start `bash` in the current working directory in its own network namespace as the current user.

```sh
mkosi-sandbox --bind / / --same-dir --unshare-net
```

Run `id` as the root user in a sandbox with only `/usr` from the host plus the necessary symlinks
to be able to run commands.

```sh
mkosi-sandbox \
    --ro-bind /usr /usr \
    --symlink usr/bin /bin \
    --symlink usr/bin /bin \
    --symlink usr/lib /lib \
    --symlink usr/lib64 /lib64 \
    --symlink usr/sbin /sbin \
    --dev /dev \
    --proc /proc \
    --tmpfs /tmp \
    --become-root \
    id
```

# SEE ALSO
`mkosi(1)`
