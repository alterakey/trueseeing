# trueseeing

## Development workflow

**Main entrypoint**: `trueseeing.app.shell:entry` runs the REPL. Basic usage described in README.md:28-99.

**Interactive commands**: Lazy-discovered in `trueseeing/app/cmd/` via `get_public_subclasses(Command)`. No explicit `__init__.py` imports needed. New commands must:
- Inherit `Command` and implement abstract methods including `get_commands()`
- Follow naming pattern matching module + class: `trueseeing.app.cmd.<module>.<ClassName>` (e.g., `trueseeing.app.cmd.android.app.AppDebugCommand`)
- Diagnose errors immediately: `get_missing_methods(c)` assertion in `trueseeing/app/cmd/__init__.py:18` raises if required methods omitted

**Validating changes** (ordered check): `uv run zuban check trueseeing && uv run ruff check trueseeing`

**Building a wheel**: `flit build` (via project config) - builds directly from `src` layout, not a monorepo. Building from Dockerfile uses `uv sync --locked --no-dev` under `/usr/lib/ts2` directory.

## Architecture notes

**Context types**: Only two known concrete path types—are used for type checks in signatures. If adding new context types, implement `FileFormatHandler` discovery entrypoint, register format pattern in `get_formats()` return value dict (key is regex pattern like `r'\.apk$'`), and add `require_type('type-name')` with parenthesized cast in signature code.

**Extension placement**: Extensions work both as directory (container `/ext` or `~/.trueseeing2/extensions/`) and as module (prefix `trueseeing_ext0_`). Types exported via `trueseeing.api` (Command, Signature, FileFormatHandler) must be imported inside function implementations, not top-level package scope, to avoid import-time registration issues.

## Docker quirks

**Container environment variables**: `TS2_IN_DOCKER`, `TS2_CACHEDIR`, `TS2_HOME`, `TS2_EXTDIR`, `TS2_FRIDA_IOS_DUMP_PATH`, `TS2_SWIFT_DEMANGLER_URL` explicitly set in Dockerfile:16-22. Mount point `/cache` is critical for scan speed—omitting it in `docker run` leads to slower operations but still works. The image requires `adbd` running on the host for Android device control.
