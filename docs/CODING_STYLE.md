---
title: Coding Style
category: Contributing
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Coding Style

## Python Version

- The lowest supported Python version is CPython 3.9.

## Formatting

- Use the accompanying `.editorconfig` or `.dir-locals.el`.
- For Python files we use the style from `ruff format` with a line length of 109 characters and four spaces
  indentation.
- Indentation with tabs is not allowed.
- When it improves readability, judicious use of `# noqa: E501` comments is allowed.
- Long lists, including argument lists, should have a trailing comma to force ruff to split all elements on a
  line of their own.
- List of commandline arguments should not split the argument of a commandline option and the option. This
  needs to be enforced with `# fmt: skip` comments, e.g. do
  ```python
  cmd = [
      "--option", "foo",
  ]  # fmt: skip
  ```
  and do NOT do
  ```python
  cmd = [
      "--option",
      "foo",
  ]
  ```
- When coercing Path-like objects to strings, use `os.fspath`, since this calls the `__fspath__` protocol
  instead of `__str__`. It also ensures more type-safety, since every Python object supports `__str__`, but
  not all support `__fspath__` and this gives the typechecker more information what is expected at this
  point. It also signals the intent to the reader more than a blanket `str()`.
