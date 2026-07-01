# AGENTS.md

This file provides guidance to AI coding agents when working with code in this repository. Only add
instructions to this file if you've seen an AI agent mess up that particular bit of logic in practice.

## Legal

 - Only human beings can ever be credited within commit messages. This means no Co-Developed-By or
   Co-Authored-By or anything similar that lists an AI model instead of a human being.

## Key Documentation

Always consult these files as needed:

- `docs/CODING_STYLE.md` — full style guide (must-read before writing code)
- `docs/debugging.md` — how to replay a command that failed inside mkosi's sandbox

## Build and Test Commands

- Running tests: See the "Hacking on mkosi" section in `README.md` for complete instructions.
- `bin/mkosi box -- pytest` to run all unit tests including linters and type checkers
- append usual pytest options like `-k test_mypy` to run a specific check
- `bin/mkosi box -- ruff format mkosi tests kernel-install/*.install` to format code
- `bin/mkosi box -- ruff check --fix mkosi tests kernel-install/*.install` to fix ruff issues
- `python3 -m pytest -m integration ...` to run integration tests. No need to run these by default.
- `bin/mkosi box -- pytest -m install` to run installation tests (venv/pip/zipapp). Skipped by default as they install from the network. No need to run these by default.

- Never invent your own build commands or try to optimize the build process.
- Never use `head`, `tail`, or pipe (`|`) the output of build or test commands. Always let the full output
display. This is critical for diagnosing build and test failures.

## Pull Request Review Instructions

- Always check out the PR in a git worktree in `worktrees/`, review it locally and remove the worktree when finished.
