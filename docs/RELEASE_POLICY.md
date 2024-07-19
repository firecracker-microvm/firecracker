# Firecracker Release Policy

This document describes Firecracker release planning, API support, and the
Firecracker release lifetime. Firecracker provides this Release Policy to help
customers effectively plan their Firecracker based operations.

## Firecracker releases

Firecracker uses
[semantic versioning 2.0.0](https://semver.org/spec/v2.0.0.html) for all
releases. By definition, the API version implemented by a Firecracker binary is
equivalent to that binary’s version. Semantic versions are comprised of three
fields in the form: `vMAJOR.MINOR.PATCH`. Additional labels for pre-release and
build metadata are available as extensions to the MAJOR.MINOR.PATCH format.

For example: v0.20.0, v0.22.0-beta5, and v99.123.77+foo.bar.baz.5.

Firecracker publishes major, minor and patch releases:

- Patch release - The `PATCH` field is incremented whenever critical bugs and/or
  security issues are found in a supported release. The fixes in a PATCH release
  do not change existing behavior or the user interface. Upgrade is recommended.
- Minor release - When the `MINOR` field is incremented, the new release adds
  new features, bug fixes, or both without changing the existing user interface
  or user facing functionality. Adding new APIs can be done in a `MINOR`
  Firecracker release as long as it doesn’t change the functionality of the APIs
  available in the previous release. Minor releases are shipped when features
  are ready for production. Multiple features may be bundled in the same
  release.
- Major release - When the `MAJOR` field is incremented, the new release adds
  new features and/or bug fixes, changing the existing user interface or user
  facing functionality. This may make the new release it incompatible with
  previous ones. A major release will likely require changes from other
  components interacting with Firecracker, e.g. API request, commands, or guest
  components. The changes will be detailed in the release notes. Major releases
  are published whenever features or bug fixes that changes the existing user
  interface, or user facing functionality, are ready for production.

## Release support

The Firecracker maintainers will only provide support for Firecracker releases
under our
[repository's release page](https://github.com/firecracker-microvm/firecracker/releases).

The Firecracker maintainers will provide patch releases for critical bugs and
security issues when they are found, for:

- the last two Firecracker `vMAJOR.MINOR` releases for up to 1 year from release
  date;
- any Firecracker `vMAJOR.MINOR` release for at least 6 months from release
  date;
- for each `vMAJOR`, the latest `MINOR` for 1 year since release date;

Starting with release v1.0, for each major and minor release, we will also be
specifying the supported kernel versions.

### Examples

1. Considering an example where the last Firecracker releases are:

- v2.10.0 released on 2022-05-01
- v2.11.0 released on 2022-07-10
- v2.12.0 released on 2022-09-11

In case of an event occurring in 2022-10-03, all three releases will be patched
since less than 6 months elapsed from their MINOR release time.

1. Considering an example where the last Firecracker releases are:

- v2.10.0 released on 2022-05-01
- v2.11.0 released on 2022-07-10
- v2.12.0 released on 2022-09-11

In case of of an event occurring in 2023-05-04, v2.11 and v2.12 will be patched
since those were the last 2 Firecracker major releases and less than an year
passed since their release time.

1. Considering an example where the last Firecracker releases are:

- v2.14.0 released on 2022-05-01
- v3.0.0 released on 2022-07-10
- v3.1.0 released on 2022-09-11

In case of of an event occurring in 2023-01-13, v2.14 will be patched since is
the last minor of v2 and has less than one year since release while v3.0 and
v3.1 will be patched since were the last two Firecracker releases and less than
6 months have passed since release time.

## Release Status

| Release | Release Date | Latest Patch | Min. end of support | Official end of Support         |
| ------: | -----------: | -----------: | ------------------: | :------------------------------ |
|    v1.8 |   2024-07-10 |       v1.8.0 |          2025-01-10 | Supported                       |
|    v1.7 |   2024-03-18 |       v1.7.0 |          2024-09-18 | Supported                       |
|    v1.6 |   2023-12-20 |       v1.6.0 |          2024-06-20 | 2024-07-10 (v1.8 released)      |
|    v1.5 |   2023-10-09 |       v1.5.1 |          2024-04-09 | 2024-04-09 (end of 6mo support) |
|    v1.4 |   2023-07-20 |       v1.4.1 |          2024-01-20 | 2024-01-20 (end of 6mo support) |
|    v1.3 |   2023-03-02 |       v1.3.3 |          2023-09-02 | 2023-10-09 (v1.5 released)      |
|    v1.2 |   2022-11-30 |       v1.2.1 |          2023-05-30 | 2023-07-20 (v1.4 released)      |
|    v1.1 |   2022-05-06 |       v1.1.4 |          2022-11-06 | 2023-03-02 (v1.3 released)      |
|    v1.0 |   2022-01-31 |       v1.0.2 |          2022-07-31 | 2022-11-30 (v1.2 released)      |
|   v0.25 |   2021-03-13 |      v0.25.2 |          2021-09-13 | 2022-03-13 (end of 1y support)  |

## API support

The Firecracker API follows the semantic versioning standard. For a new release,
we will increment the:

- MAJOR version when we make breaking changes in our API;
- MINOR version when we add or change functionality in a backwards compatible
  manner;
- PATCH version when we make backwards compatible bug fixes.

Given a Firecracker version X.Y.Z user-generated client, it is guaranteed to
work as expected with all Firecracker binary versions X.V.W, where V >= Y.

### Deprecation of elements in the API

Firecracker uses
[semantic versioning 2.0.0](https://semver.org/spec/v2.0.0.html) in terms of
deprecating and removing API elements. We will consider a deprecated API element
to be an element which still has backing functionality and will be supported at
least until the next MAJOR version, where they _will be removed_. The support
period of deprecated API elements is tied to
[the Firecracker release support](https://github.com/firecracker-microvm/firecracker/blob/main/docs/RELEASE_POLICY.md#release-support).

## Developer preview features

A feature is "in" developer preview if it’s marked as such in the
[Firecracker roadmap](https://github.com/orgs/firecracker-microvm/projects/42)
and/or in the
[Firecracker release notes](https://github.com/firecracker-microvm/firecracker/releases).

Features in developer preview should not be used in production as they are not
supported. Firecracker team may not provide patch releases for critical bug
fixes or security issues found in features marked as developer preview.

Features in developer preview may be subject to changes at any time. Changes in
existing user interface or user facing functionality of a feature marked as
developer preview can be released without changing the major version.

## Release planning

Firecracker feature planning is outlined in the
[Firecracker roadmap](https://github.com/firecracker-microvm/firecracker/projects).
