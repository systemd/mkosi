# SPDX-License-Identifier: LGPL-2.1-or-later

kind: compose

build-depends:
- freedesktop-sdk.bst:public-stacks/runtime-gnu.bst
- freedesktop-sdk.bst:components/dbus.bst
- freedesktop-sdk.bst:components/linux-pam.bst
- freedesktop-sdk.bst:components/linux.bst
- freedesktop-sdk.bst:components/os-release.bst
- freedesktop-sdk.bst:components/systemd.bst

config:
  exclude:
  - debug
  - devel
  - doc
  - locale
  - extra
  - tests
