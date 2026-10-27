# Adding a plugin

A new AI tool needs three things: one plugin module, its unit test, and one line in the registry.

## 1. Write the module

Create `src/aitrace/plugins/<group>/<name>.py`. Look at a small existing plugin such as `src/aitrace/plugins/ai/local_llm.py` for the shape. The module must define:

- a class with `name`, `version` and `description` attributes, and the method the runner calls to produce artifacts and events;
- a module-level `PLUGIN` instance, which the registry loads.

Rules that the runner and store enforce:

- Read through the filesystem abstraction, never the host filesystem. Don't write to the evidence.
- Copy SQLite files from the image to a temp directory before opening them (helpers live in `aitrace.plugins.common`).
- Every artifact needs a non-empty `provenance.source_path` and a non-empty plugin version, or the store rejects it with a ValueError.
- Use the data keys defined for each artifact kind. Put anything extra under `extra`.
- Normalize paths with `aitrace.core.paths.normalize`.
- Redact secrets. Make no network calls.
- Turn parse failures into `PARSE_WARNING` artifacts. Don't use a bare `except`, and don't swallow errors.

## 2. Write the unit test

Add `tests/unit/plugins/test_<name>.py`. Build a small in-memory filesystem, run the plugin, and assert the artifacts. Add a case for a corrupt input that must give a PARSE_WARNING and no crash. Tests must be deterministic: no sleeps, no clock dependence.

## 3. Register it

Add the dotted module path to `BUILTIN_PLUGINS` in `src/aitrace/plugins/registry.py`. Order matters: the list is the run order. Third-party packages can instead expose an entry point in the `aitrace.plugins` group.

## 4. Check it

```
uv run aitrace plugins
uv run pytest tests/unit/plugins
uv run ruff check .
```

Then add a row to the table in [artifacts.md](artifacts.md) and an entry to [CHANGELOG.md](../CHANGELOG.md).
