# Contributing

Thank you for your interest in contributing to pcap-parser.

## Getting Started

1. Fork the repo and clone your fork.
2. Install dependencies:
   ```bash
   pip install -e ".[dev]"
   ```
3. Make sure tshark is installed ([Wireshark downloads](https://www.wireshark.org/download.html)).
4. Run the tests to confirm everything works:
   ```bash
   pytest
   ```

## Making Changes

- Create a new branch from `main` for your work.
- Keep commits focused on a single change.
- Make sure `ruff check` and `pytest` pass before opening a PR.
- If you add new functionality, add tests for it.

## Pull Requests

- Open your PR against `main`.
- Keep the title short and descriptive.
- Include a brief summary of what changed and why.
- Link any related issues.

## Reporting Issues

- Check existing issues before opening a new one.
- Include steps to reproduce the problem.
- Include your Python version, OS, and tshark version if relevant.

## Code Style

- We use [Ruff](https://docs.astral.sh/ruff/) for linting.
- Follow the existing patterns in the codebase.
- Keep it simple.
