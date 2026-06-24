# Changelog

## [2.0.0] - 2026-06-23

### Changed
- Complete rewrite from single-file to modular package
- Each AD attack phase is an independent module under sovereign/modules/
- LDAP helpers extracted to sovereign/utils/ldap_helpers.py
- AD constants extracted to sovereign/data/

### Added
- 14 unit tests (models, helpers, data, CLI)
- pyproject.toml, Makefile, CI, Dockerfile
- docs/ARCHITECTURE.md
- LICENSE, CONTRIBUTING, SECURITY, CHANGELOG

## [1.0.0] - 2026-06-20

### Added
- Initial release: LDAP enum, Kerberoasting, AS-REP roasting,
  DCSync, ACL abuse, lateral movement
