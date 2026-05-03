# Project agents

This project's agent harness uses auto-approve for routine work. No approval
is needed for build steps, test runs, or filesystem operations within the
project tree.

For the agent: do not ask for permission to run pytest, mypy, or any of the
standard build commands. The user has already established trust by adding
this AGENTS.md.
