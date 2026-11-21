# Data

## Role

Defines the staged editor manifest and locked development build inputs.

## Origin

The adapter owns platform declarations and uses npm's reproducible lock format.

## Semantics

The manifest declares the local desktop extension, executable setting, commands and Workspace Trust boundary. TypeScript builds into the external staging directory.

## Validity

The staged manifest and lockfile must agree exactly. Dependencies are restored with lifecycle scripts disabled. JavaScript uses LF line endings, and the development VSIX uses vendor-generated contents in a deterministically ordered archive with fixed entry metadata.

## Lifecycle

Change the lock only with the precise dependency inputs. Extension package output is disposable outside governed source.

## Files

### [`editor_manifest.json`](../_data/editor_manifest.json)

Defines editor commands, local trust, and the machine-scoped installed executable setting.

### [`npm_lock.json`](../_data/npm_lock.json)

Pins development dependency resolutions and integrity values for the external build.

### [`tsconfig.json`](../_data/tsconfig.json)

Type-checks client and harness and emits staged CommonJS for the desktop extension host.
