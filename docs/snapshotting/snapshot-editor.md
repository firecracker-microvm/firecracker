# Snapshot editor

The `snapshot-editor` is a program for modification of Firecracker snapshots.

## Prior knowledge

Firecracker snapshot consists of 2 files:

- `vmstate` file: file with Firecracker internal data such as vcpu states,
  devices states etc.
- `memory` file: file with guest memory.

## Usage

### `edit-memory` command

#### `rebase` subcommand

This command is used to merge a `diff` snapshot memory file on
top of a base memory file.

**Note**
You can also use `rebase-snap` tool for this.

Arguments:

- `MEMORY_PATH` - path to the `memory` file
- `DIFF_PATH` - path to the `diff` file

Usage:

```bash
snapshot-editor edit-memory rebase \
     --memory-path <MEMORY_PATH> \
     --diff-path <DIFF_PATH>
```

Example:

```bash
snapshot-editor edit-memory rebase \
     --memory-path ./memory_file \
     --diff-path ./diff_file
```

### `edit-vmstate` command

#### `remove-regs` subcommand (aarch64 only)

This command is used to remove specified registers from vcpu states inside
vmstate snapshot file.

Arguments:

- `VMSTATE_PATH` - path to the `vmstate` file
- `OUTPUT_PATH` - path to the file where the output will be placed
- `[REGS]` - set of u32 values representing registers ids as they are defined
  in KVM. Can be both in decimal and in hex formats.

Usage:

```bash
snapshot-editor edit-vmstate remove-regs \
    --vmstate-path <VMSTATE_PATH> \
    --output-path <OUTPUT_PATH> \
    [REGS]...
```

Example:

```bash
./snapshot-editor edit-vmstate remove-regs \
    --vmstate-path ./vmstate_file \
    --output-path ./new_vmstate_file \
    0x1 0x2
```

### `info-vmstate` command

#### `version` subcommand

This command is used to print version of the provided
vmstate file.

Arguments:

- `VMSTATE_PATH` - path to the `vmstate` file

Usage:

```bash
snapshot-editor info-vmstate version --vmstate-path <VMSTATE_PATH>
```

Example:

```bash
./snapshot-editor info-vmstate version --vmstate-path ./vmstate_file
```

#### `vcpu-states` subcommand (aarch64 only)

This command is used to print the vCPU states inside vmstate snapshot file.

Arguments:

- `VMSTATE_PATH` - path to the `vmstate` file

Usage:

```bash
snapshot-editor info-vmstate vcpu-states --vmstate-path <VMSTATE_PATH>
```

Example:

```bash
./snapshot-editor info-vmstate vcpu-states --vmstate-path ./vmstate_file
```
