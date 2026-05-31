# Contributing to nodus-auth

## Setup

```bash
git clone https://github.com/Masterplanner25/nodus-auth.git
cd nodus-auth
pip install -e ".[dev]"
```

## Running tests

```bash
pytest tests/ -q
```

## Dependency notes

- `bcrypt` is pinned `<5.0` — do not upgrade. `passlib 1.7.4` is incompatible
  with bcrypt 5.x and the fix requires a passlib update that is not yet released.

## Code style

- Python 3.11+
- Type hints on all public functions
- Pydantic v2 for schemas

## Submitting changes

1. Fork the repo and create a branch from `main`
2. Add tests for any new behaviour
3. Ensure `pytest tests/ -q` passes
4. Open a pull request with a description of what changes and why
