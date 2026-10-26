# Contributing to OneConfig

Thanks for helping. OneConfig changes live network devices, so changes come with tests, and nothing that touches a push goes in without one.

A security problem goes through [SECURITY.md](SECURITY.md), not an issue or a pull request.

## Set up

Python 3.10 or later. Install the locked versions, with their checksums checked, then OneConfig itself:

```bash
python -m venv .venv
.venv/bin/pip install --require-hashes -r requirements/dev.lock
.venv/bin/pip install -e . --no-deps
.venv/bin/python -m playwright install chromium
```

Run it with `.venv/bin/oneconfig serve`.

## Run the tests

```bash
.venv/bin/python -m pytest -q tests --ignore-glob="tests/test_push*.py"   # about 4 minutes, UI tests included
.venv/bin/python -m pytest -q tests/test_push*.py                          # about 20 minutes: pushes to simulated devices over SSH
```

GitHub runs the first set on every push and pull request, and everything nightly. The syntax checks in `tests/test_syntax.py` skip until you build their checkers once with the scripts in `tests/syntax/` (Batfish's grammars, Palo Alto's and Fortinet's specs; they need Java and git).

Tests never touch your real `~/.oneconfig` or OS keychain: `tests/conftest.py` points every state file at a temporary folder and swaps in an in-memory keychain.

## Make a change

- Keep changes small and focused, and add a test that fails without the change.
- Generated config is checked against golden files in `tests/fixtures/golden/`. If a template change is intended, update them in the same pull request and say why.
- Anything that reaches a device — templates, plan, push, rollback — needs a test with the simulated devices in `tests/fakelab.py`.
- Values that end up in a device's config must pass the model's patterns in `oneconfig/model.py`; don't loosen them without a test showing the new value can't add a command.
- Never paste real device configs, passwords, keys, serial numbers or public addresses into fixtures or issues.

## Add a vendor or OS

Adding an OS means a template in `oneconfig/templates/`, its interface names in `oneconfig/model.py` (`IF_KINDS`, `EXAMPLE_IF`, `PO_NAME`), its best-practice checks in `oneconfig/audit.py`, and a STIG module if DISA publishes one. Discovery and push support come after, each with its own tests. The [README](README.md#layout) shows where each part lives.

## Update dependencies

Edit the ranges in `pyproject.toml`, then recompile both locks. They work on Linux, macOS and Windows:

```bash
.venv/bin/pip install uv
for x in dev app; do .venv/bin/uv pip compile pyproject.toml --extra $x --universal --generate-hashes --python-version 3.10 -c requirements/constraints.txt -o requirements/$x.lock; done
```

Dependabot opens update pull requests weekly; recompile the locks on its branch before merging.

## Build the Mac app

```bash
.venv/bin/pip install --require-hashes -r requirements/app.lock
.venv/bin/pip install -e . --no-deps
.venv/bin/pyinstaller packaging/OneConfig.spec --noconfirm
dist/OneConfig.app/Contents/MacOS/OneConfig --selfcheck
```

The icon is drawn by `packaging/make_icon.py`.

## Licence

By contributing, you agree your work is released under the [MIT license](LICENSE). Third-party material goes in [NOTICE](NOTICE).
