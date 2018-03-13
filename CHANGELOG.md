# Changelog

## [0.1.1]

### Changed

- Users can now specify the MAC address of a guest network interface via the PUT network interface API request. Previously, the guest MAC address parameter was ignored.

### Fixed

- Fixed a guest memory allocation issue, which previously led to a potentially significant memory chunk being wasted.
- Fixed an issue which caused compilation problems, due to a compatibility breaking transitive dependency in the tokio suite of crates.


