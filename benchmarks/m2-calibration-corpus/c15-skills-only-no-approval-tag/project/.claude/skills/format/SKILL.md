---
name: format
description: Run black + isort over a Python file
---

# format

Use this skill to format a single Python file. It runs `black` and `isort`
and returns the formatted result.

Inputs: a single file_path. Outputs: the formatted text.

This is a simple style-only skill. Always show the diff to the user before
applying.
