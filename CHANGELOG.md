# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Prelude including traits which provide extra syntax.
- Add JwsSigner/JwsSignerSync which adds the JWS algorithm on top of basic signer abilities.

## [0.1.0] - 2026-01-04

### Added

- Async and sync signer traits.
- Secret source trait.
- Secret encoding trait.
- Binary, string, base64, hex secret encodings.
- Auto-selection of send/sync based on platform.

[unreleased]: https://github.com/chewie-rs/chewie-crypto/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/chewie-rs/chewie-crypto/tag/v0.1.0
