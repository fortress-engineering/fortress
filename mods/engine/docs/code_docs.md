# Engine Code

`lib.rs` is the provider-independent crate facade. Explicit Rust `path`
attributes compose source files owned by child Modules without introducing an
uncontrolled source taxonomy or hiding architectural decomposition beneath
`code/`.

The crate forbids unsafe code and denies missing documentation, broken rustdoc
links, and warnings.
