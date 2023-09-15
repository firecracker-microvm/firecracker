# Firecracker Integration Tests

The tests herein are meant to uphold the security, quality, and performance
contracts of Firecracker.

## Running

To run all tests:

``` sh
tools/devtool test
```

This will download test microvm images from the default test resource S3 bucket
and run all available tests.

To run tests from specific directories and/or files:

``` sh
tools/devtool test -- <test_dir_or_file_path>...
```

To run a single specific test from a file:

``` sh
tools/devtool test -- <test_file_path>::<test_name>
```

The testing system is built around [pytest](https://docs.pytest.org/en/latest/).
Any parameters passed to `tools/devtool test --` are passed to the `pytest`
command. `devtool` is used to automate fetching of test dependencies (useful
for continuous integration) and to sandbox test runs (useful for development
environments). If you are not interested in these capabilities, use pytest
directly, either from inside the container:

```sh
tools/devtool shell -p
pytest [<pytest argument>...]
```

Or natively on your dev box:

``` sh
python3 -m pytest [<pytest argument>...]
```

For help on usage, see `tools/devtool help`.

### Output

- Output, including testrun results, goes to `stdout`. Errors go to `stderr`.

### Dependencies

- A bare-metal `Linux` host with `uname -r` >= 4.14 and KVM enabled
  (`/dev/kvm` device node exists).
- Docker.

## Rustacean Integration Tests

The `pytest`-powered integration tests rely on Firecracker's HTTP API for
configuring and communicating with the VMM. Alongside these, the `vmm` crate
also includes several [native-Rust integration tests](../src/vmm/tests/), which
exercise its programmatic API without the HTTP integration. `Cargo`
automatically picks up these tests when `cargo test` is issued. They also count
towards code coverage.

To run *only* the Rust integration tests:

```bash
cargo test --test integration_tests
```

Unlike unit tests, Rust integration tests are each run in a separate process.
`Cargo` also packages them in a new crate. This has several known side effects:

1. Only the `pub` functions can be called. This is fine, as it allows the VMM
   to be consumed as a programmatic user would. If any function is necessary
   but not `pub`, please consider carefully whether it conceptually *needs* to
   be in the public interface before making it so.
1. The correct functioning scenario of the `vmm` implies that it `exit`s with
   code `0`. This is necessary for proper resource cleanup. However, `cargo`
   doesn't expect the test process to initiate its own demise, therefore it
   will not be able to properly collect test output.

   Example:

   ```bash
   cargo test --test integration_tests
   running 3 tests
   test test_setup_serial_device ... ok
   ```

To learn more about Rustacean integration test, see
[the Rust book](https://doc.rust-lang.org/book/ch11-03-test-organization.html#integration-tests).

## Adding Python Tests

Tests can be added in any (existing or new) sub-directory of `tests/`, in files
named `test_*.py`.

## Adding Rust Tests

Add a new function annotated with `#[test]` in
[`integration_tests.rs`](../src/vmm/tests/integration_tests.rs).

## Adding Fixtures

By default, `pytest` makes all fixtures in `conftest.py` available to all test
functions. You can also create `conftest.py` in sub-directories containing
tests, or define fixtures directly in test files. See `pytest` documentation
for details.

## Working With Guest Files

There are helper methods for writing to and reading from a guest filesystem.
For example, to overwrite the guest init process and later extract a log:

``` python
def test_with_any_microvm_and_my_init(test_microvm_any):
    # [...]
    test_microvm_any.slot.fsfiles['mounted_root_fs'].copy_to(my_init, 'sbin/')
    # [...]
    test_microvm_any.slot.fsfiles['mounted_root_fs'].copy_from('logs/', 'log')
```

`copy_to()` source paths are relative to the host root and destination paths
are relative to the `mounted_root_fs` root. Vice versa for `copy_from()`.

Copying files to/from a guest file system while the guest is running results in
undefined behavior.

## Example Manual Testrun

Running on an EC2 `.metal` instance with an `Amazon Linux 2` AMI:

``` sh
# Get firecracker
yum install -y git
git clone https://github.com/firecracker-microvm/firecracker.git

# Run all tests
cd firecracker
tools/devtool test
```

## Terminology

- **Testrun**: A sandboxed run of all (or a selection of) integration tests.
- **Test Session**: A `pytest` testing session. One per **testrun**. A
  **Testrun** will start a **Test Session** once the sandbox is created.
- **Test**: A function named `test_` from this tree, that ensures a feature,
  functional parameter, or quality metric of Firecracker. Should assert or
  raise an exception if it fails.
- **Fixture**: A function that returns an object that makes it very easy to add
  **Tests**: E.g., a spawned Firecracker microvm. Fixtures are functions marked
  with `@pytest.fixture` from a files named either `conftest.py`, or from files
  where tests are found. See `pytest` documentation on fixtures.
- **Test Case**: An element from the cartesian product of a **Test** and all
  possible states of its parameters (including its fixtures).

## FAQ

`Q1:`
*I have a shell script that runs my tests and I don't want to rewrite it.*
`A1:`
Insofar as it makes sense, you should write it as a python test function.
However, you can always call the script from a shim python test function. You
can also add it as a microvm image resource in the s3 bucket (and it will be
made available under `microvm.slot.path`) or copy it over to a guest filesystem
as part of your test.

`Q2:`
*I want to add more tests that I don't want to commit to the Firecracker
repository.*
`A2:`
Before a testrun or test session, just add your test directory under `tests/`.
`pytest` will discover all tests in this tree.

`Q3:`
*I want to have my own test fixtures, and not commit them in the repo.*
`A3:`
Add a `conftest.py` file in your test directory, and place your fixtures there.
`pytest` will bring them into scope for all your tests.

`Q4:`
*I want to use more/other microvm test images, but I don't want to add them to
the common s3 bucket.*
`A4:`
Add your custom images to the `build/img` subdirectory in the Firecracker
source tree. This directory is bind-mounted in the container and used as a
local image cache.

`Q5:`
*How can I get live logger output from the tests?*
`A5:`
Accessing **pytest.ini** will allow you to modify logger settings.

`Q6:`
*Is there a way to speed up integration tests execution time?*

`A6:`
You can narrow down the test selection as described in the **Running**
section, or in the **Troubleshooting Tests** section. For example:

1. Pass the `-k substring` option to Pytest to only run a subset of tests by
   specifying a part of their name.

1. Only run the tests contained in a file or directory.

## Implementation Goals

- Easily run tests manually on a development/test machine, and in a continuous
  integration environments.
- Each test should be independent, and self-contained. Tests will time out,
  expect a clean environment, and leave a clean environment behind.
- Always run with the latest dependencies and resources.

### Choice of Pytest & Dependencies

Pytest was chosen because:

- Python makes it easy to work in the clouds.
- Python has built-in sandbox (virtual environment) support.
- `pytest` has great test discovery and allows for simple, function-like tests.
- `pytest` has powerful test fixture support.

## Test System TODOs

**Note**: The below TODOs are also mentioned in their respective code files.

### Features

- Use the Firecracker Open API spec to populate Microvm API resource URLs.
- Do the testrun in a container for better insulation.
- Event-based monitoring of microvm socket file creation to avoid while spins.
- Self-tests (e.g., Tests that test the testing system).

### Implementation

- Looking into `pytest-ordering` to ensure test order.
- Create an integrated, layered `say` system across the test runner and pytest
  (probably based on an environment variable).
- Per test function dependency installation would make tests easier to write.
- Type hinting is used sparsely across tests/* python module. The code would be
  more easily understood with consistent type hints everywhere.

### Bug fixes

## Further Reading

Contributing to this testing system requires a dive deep on `pytest`.

## Troubleshooting tests

### How to select tests

When troubleshooting tests, it is important to only narrow down the ones that
are of interest. `pytest` offers several features to do that:

#### single file

```sh
./tools/devtool -y test -- integration_tests/performance/test_boottime.py
```

#### single test

```sh
./tools/devtool -y test -- integration_tests/performance/test_boottime.py::test_boottime
```

#### single test + parameter(s)

Use the `-k` parameter to match part of the test (including the parameters!):

```sh
./tools/devtool -y test -- -k 1024 integration_tests/performance/test_boottime.py::test_boottime
```

#### --last-failed

One can use the `--last-failed` parameter to only run the tests that failed from
the previous run. Useful when several tests fail after making large changes.

### Run tests from within the container

To avoid having to enter/exit Docker every test run, you can run the tests
directly within a Docker session:

```sh
./tools/devtool -y shell --privileged
./tools/test.sh integration_tests/functional/test_api.py
```

### How to use the Python debugger (pdb) for debugging

Just append `--pdb`, and when a test fails it will drop you in pdb, where you
can examine local variables and the stack, and can use the normal Python REPL.

```
./tools/devtool -y test -- -k 1024 integration_tests/performance/test_boottime.py::test_boottime --pdb
```

### How to use ipython's ipdb instead of pdb

```sh
./tools/devtool -y shell --privileged
export PYTEST_ADDOPTS=--pdbcls=IPython.terminal.debugger:TerminalPdb
./tools/test.sh -k 1024 integration_tests/performance/test_boottime.py::test_boottime
```

There is a helper command in devtool that does just that, and is easier to type:

```sh
./tools/devtool -y test_debug -k 1024 integration_tests/performance/test_boottime.py::test_boottime
```

### How to connect to the console interactively

There is a helper to enable the console, but it has to be run **before**
spawning the Firecracker process:

```python
uvm.help.enable_console()
uvm.spawn()
uvm.basic_config()
uvm.start()
...
```

Once that is done, if you get dropped into pdb, you can do this to open a `tmux`
tab connected to the console (via `screen`).

```python
uvm.help.tmux_console()
```

### How to reproduce intermittent (aka flaky) tests

Just run the test in a loop, and make it drop you into pdb when it fails.

```sh
while true; do
    ./tools/devtool -y test -- integration_tests/functional/test_balloon.py::test_deflate_on_oom -k False --pdb
done
```

### How to run tests in parallel with `-n`

We can run the tests in parallel via `pytest-xdist`. Not all tests can run in
parallel (the ones in `build` and `performance` are not supposed to run in
parallel).

By default, the tests run sequentially. One can use the `-n` to control the
parallelism. Just `-n` will run as many workers as CPUs, which may be too many.
As a rough heuristic, use half the available CPUs. I use -n4 for my 8 CPU
(HT-enabled) laptop. In metals 8 is a good number; more than that just gives
diminishing returns.

```sh
./tools/devtool -y test -- integration_tests/functional -n$(expr $(nproc) / 2) --dist worksteal
```

### How to attach gdb to a running uvm

First, make the test fail and drop you into PDB. For example:

```sh
./tools/devtool -y test_debug integration_tests/functional/test_api.py::test_api_happy_start --pdb
```

Then,

```
ipdb> test_microvm.help.gdbserver()
```

You get some instructions on how to run GDB to attach to gdbserver.

## Sandbox

```sh
./tools/devtool sandbox
```

That should drop you in an IPython REPL, where you can interact with a microvm:

```python
uvm.help.print_log()
uvm.get_all_metrics()
uvm.ssh.run("ls")
snap = uvm.snapshot_full()
uvm.help.tmux_ssh()
```
