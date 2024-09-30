---
title: Adding new distributions
category: Tutorials
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Adding new distributions

Merging support for a new distribution in mkosi depends on a few
factors. Not all of these are required but depending on how many of
these requirements are satisfied, the chances of us merging support for
your distribution will improve:

1. Is the distribution somewhat popular? mkosi's goal is not to support
   every distribution under the sun, the distribution should have a
   substantial amount of users.
2. Does the distribution differentiate itself somehow from the
   distributions that are already supported? We're generally not
   interested in supporting distributions that only consist of minimal
   configuration changes to another distribution.
3. Is there a long-term maintainer for the distribution in mkosi? When
   proposing support for a new distribution, we expect you to be the
   maintainer for the distribution and to respond when pinged for
   support on distribution specific issues.
4. Does the distribution use a custom package manager or one of the
   already supported ones (apt, dnf, pacman, zypper)? Supporting new
   package managers in mkosi is generally a lot of work. We can support
   new ones if needed for a new distribution, but we will insist on the
   package manager having a somewhat sane design, with official support
   for building in a chroot and running unprivileged in a user namespace
   being the bare minimum features we expect from any new package
   manager.

We will only consider new distributions that satisfy all or most of
these requirements. However, you can still use mkosi with the
distribution by setting the `Distribution` setting to `custom` and
implementing either providing the rootfs via a skeleton tree or base
tree, or by providing the rootfs via a prepare script.

# Implementing new distributions

To actually implement a new distribution, the following checklist can be
used:

- Add the distribution to the `Distribution` enum
- Add the implementation of the distribution in `mkosi/distributions`.
  If the distribution is a variant of an existing distribution, inherit
  from the existing distribution's installer class and only override the
  necessary methods.
- Update any relevant methods on the `Distribution` enum to take the new
  distribution into account.
- Update the documentation in `mkosi/resources/man/mkosi.1.md`
- Update the default initrd, tools and default image configurations in
  `mkosi/resources/mkosi-initrd`, `mkosi/resources/mkosi-tools` and
  `mkosi.conf.d` respectively. If the distribution is a variant of
  another existing distribution, update the `[Match]` blocks for the
  existing distribution to also match against the new distribution. To
  test whether all necessary changes were made, you can run
  `mkosi -d <distribution> --tools-tree -t disk -f qemu`.
