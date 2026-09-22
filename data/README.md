# Data areas

- `raw/` holds imported logs and is ignored by Git.
- `processed/` holds rebuildable normalized events or feature exports and is ignored by Git.
- `synthetic/` is reserved for small, deterministic, non-sensitive fixtures that support the live demo and automated tests.

The runtime SQLite database is also ignored and should be created through the storage layer, not committed.

