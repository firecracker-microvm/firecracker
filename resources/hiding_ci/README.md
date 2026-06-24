# Secret Hiding kernel CI

This directory builds the "Secret Freedom" / direct-map-removal kernels used by
Firecracker's secret-hiding CI. Its layout lets you build **multiple kernel
variants of different versions** while sharing as much as possible between them.

## Layout

```
resources/hiding_ci/
├── build_and_install_kernel.sh   # builds (and optionally installs) a variant
├── apply_kernel_patches.sh       # applies a variant's patch series to a kernel tree
├── dkms.conf                     # shared ENA driver DKMS config (AL2023)
├── install_ena.sh                # shared ENA driver installer (AL2023)
├── kernel_url                    # shared default git repo to clone from
├── base_config                   # shared base kernel config overrides
└── kernels/
    └── <version>-<feature>/      # one subfolder per variant, e.g. 6.18-secret-hiding
        ├── kernel_commit_hash    # REQUIRED: base commit to check out
        ├── kernel_url            # OPTIONAL: repo override (defaults to ../../kernel_url)
        ├── config_overrides      # OPTIONAL: config overrides merged on top of base_config
        └── linux_patches/        # REQUIRED: patch series applied on top of the base commit
            ├── GPL-2.0           # license for the patches (travels with them)
            ├── README.md
            └── NN-feature/*.patch
```

### Shared vs per-variant

- **Shared (root):** the build scripts, the ENA helpers, the default
  `kernel_url`, and `base_config` (config knobs common to every hiding kernel).
- **Per-variant (`kernels/<variant>/`):** the base commit, the patch series, and
  any version-specific config or repo overrides.

The build layers config overrides **base first, then the variant's
`config_overrides` on top** (later values win), matching
`scripts/kconfig/merge_config.sh -m` semantics. `resources/rebuild.sh` uses the
same approach for guest kernels.

## Naming convention

Name variant folders `<base-version>-<feature>`, e.g. `6.18-secret-hiding`. The
version prefix is the upstream kernel version of the pinned base commit
(`make -s kernelversion` at that commit).

## Adding a new variant

1. Create `kernels/<version>-<feature>/`.
1. Add `kernel_commit_hash` with the base commit to check out.
1. Add a `linux_patches/` directory with the patch series (include a `GPL-2.0`
   copy alongside the patches, since the license must travel with them).
1. Optionally add `kernel_url` if the variant pulls from a different repo than
   the shared root default.
1. Optionally add `config_overrides` for config knobs specific to this variant;
   anything common to all variants belongs in the root `base_config`.

The pytest test (`tests/integration_tests/build/test_hiding_kernel.py`) and the
Buildkite PR pipeline (`.buildkite/pipeline_pr.py`) discover variants from
`kernels/`, so a new variant gets its own build job with no further wiring.

## Building locally

```sh
cd resources/hiding_ci
# Build a specific variant without installing it, cleaning up the temp tree after:
./build_and_install_kernel.sh 6.18-secret-hiding --no-install --tidy

# If exactly one variant exists, the selector may be omitted:
./build_and_install_kernel.sh --no-install --tidy
```

Pass `--install` (or answer the prompt) to install the built kernel. Use
`apply_kernel_patches.sh <variant>` from inside an already checked-out kernel
tree to apply the patch series on its own.
