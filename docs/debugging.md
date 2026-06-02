---
title: Debugging failing sandboxed commands
category: Contributing
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Debugging failing sandboxed commands

mkosi runs nearly every external tool (such as `systemd-repart`, `grub2-bios-setup`, or package
managers) inside a sandbox set up by `mkosi-sandbox`. On failure, running the failed command
interactively is the quickest way to investigate.

Re-run mkosi with both `--debug` and `--debug-shell`. When a sandboxed command fails, mkosi logs the
complete sandbox invocation, e.g.:

```
‣ [main] "/usr/bin/some-command --some-option" returned non-zero exit code 1.
‣ [main] Sandbox command: mkosi-sandbox --bind … -- /usr/bin/some-command --some-option
```

You need `--debug-shell` to pause the build inside the sandbox and keep the sandbox's temporary files alive.
You can run many commands right inside that shell.

However, some sandbox mounts only apply to the process mkosi `exec()`s directly, e.g. the fake
`/proc/self/mountinfo` for `grub2-bios-setup`. These do **not** apply to a command you type into the
debug shell, because it runs as a child process with a different PID and so reads the real
`/proc/<pid>/mountinfo`. Reproduce those with the logged `Sandbox command:` line from a separate
host shell instead (in a source checkout, invoke it as `bin/mkosi-sandbox`).

If you want to trace it, use `strace -D` (or `-DD`) so the traced program stays the
directly executed process.

Exit the debug shell once you are done to let mkosi clean up.
