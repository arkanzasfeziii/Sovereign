# Contributing to Sovereign

## Setup

```bash
git clone https://github.com/arkanzasfeziii/Sovereign.git
cd Sovereign
pip install -r requirements.txt
pip install ruff pytest
make test
```

## Adding a New Module

1. Create `sovereign/modules/your_module.py` extending `BaseModule`
2. Implement `run(ctx, **kwargs) -> List[AttackResult]`
3. Register in `sovereign/cli.py: MODULE_REGISTRY`
4. Update `sovereign/modules/__init__.py`
5. Add tests

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/).
