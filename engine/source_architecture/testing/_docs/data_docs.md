# Data

## Role

Frozen independent source-only Python import expectations for Source
Architecture Testing.

## Origin

The finite protocol was frozen before native CPython FileFinder trials on
Windows x64 and Linux x64. The reference uses a source-only loader whose
source reading and executable methods are disabled. The fixture SHA-256 is
`90dbaaf6489a999ffa53aedb64c82014463764d22b83ab826cb5b4c1ac38d742`.
[CPython FileFinder](https://docs.python.org/3.13/library/importlib.html#importlib.machinery.FileFinder) · [PEP 420](https://peps.python.org/pep-0420/)

## Semantics

Each case specifies exact source text, ordered roots, one import or dynamic
control, optional origin input and the scoped expected result. Fixture source
would create a sentinel if executed. The product tests use those bytes only
as immutable inputs. Source context is rendered as the associated lexical
report in the individual test view.

## Validity

The fixture must match its recorded digest and contain the complete
32-case population. No case accepts dynamic execution or runtime binding.

## Lifecycle

Retain the original protocol identity and expected results when adding new
qualification controls.

## Files

### [`python_import_reference_v1.json`](../_data/python_import_reference_v1.json)

Frozen source-only FileFinder qualification inputs and results.
