# Contributing to OpenSOC Forge

Thank you for contributing to OpenSOC Forge!

## Non-Negotiable Engineering Standards

Before submitting a pull request, ensure your code adheres to:

1. **Adapter Interface**: All component adapters must inherit from `BaseComponentAdapter` in `adapters/base.py` and implement all 17 methods. Never implement an unsupported operation as a silent no-op; return structured `AdapterStatus.UNSUPPORTED` with diagnostic explanation.
2. **Configuration Safety**: Any configuration writer must implement syntax validation before applying changes and must preserve previous working configuration upon validation failure.
3. **No Destructive Reinstalls**: Never write scripts or routines that execute `rm -rf` on data directories or `apt-get purge` without affirmative confirmation tokens.
4. **Automated Testing**: Every new feature, adapter, or rule must include automated unit tests in `tests/unit/` or integration tests in `tests/integration/`.
5. **No Plaintext Secrets**: Ensure no credentials, tokens, or private keys are committed.

## Running Tests

```bash
# Run the test suite
python -m pytest tests/ -v

# Run the CLI test
python scripts/opensoc_cli.py status
python scripts/opensoc_cli.py test-integration --component suricata
```
