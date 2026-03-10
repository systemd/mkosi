# AGENTS.md

This file provides guidance to AI coding agents when working with code in this repository. Only add
instructions to this file if you've seen an AI agent mess up that particular bit of logic in practice.

## Key Documentation

Always consult these files as needed:

- `docs/CODING_STYLE.md` — full style guide (must-read before writing code)

## Build and Test Commands

- `mkosi box -- mypy mkosi tests kernel-install/*.install` to run mypy
- `mkosi box -- ruff format mkosi tests kernel-install/*.install` to format code
- `mkosi box -- ruff check --fix mkosi tests kernel-install/*.install` to run ruff
- `mkosi box -- python3 -m pytest ...` to run unit tests.
- `mkosi box -- python3 -m pytest -m integration ...` to run integration tests. No need to run these by
  default.
- Never invent your own build commands or try to optimize the build process.
- Never use `head`, `tail`, or pipe (`|`) the output of build or test commands. Always let the full output
display. This is critical for diagnosing build and test failures.

## Pull Request Review Instructions

- Always check out the PR in a git worktree in `worktrees/`, review it locally and remove the worktree when finished.

## AI Contribution Disclosure

Per project policy: if you use AI code generation tools, you **must disclose** this in commit messages by
adding e.g. `Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>`. All AI-generated output requires
thorough human review before submission.
