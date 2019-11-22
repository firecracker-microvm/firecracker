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

- A bare-metal `Linux` host with `uname -r` >= 4.14.
- Docker.

## Adding Tests

Tests can be added in any (existing or new) sub-directory of `tests/`, in files
named `test_*.py`.

Fixtures can be used to quickly build Firecracker microvm integration tests
that run on all microvm images in `s3://spec.ccfc.min/img/`.

For example, the test below makes use of the `test_microvm_any` fixture and will
be run on every microvm image in the bucket, each as a separate test case.

``` python
def test_with_any_microvm(test_microvm_any):
    response = test_microvm_any.machine_cfg.put(
        vcpu_count=2
    )
    assert(test_microvm_any.api_session.is_good_response(response.status_code))

    # [...]

    response = test_microvm_any.actions.put(action_type='InstanceStart')
    assert(test_microvm_any.api_session.is_good_response(response.status_code))
```

If instead of `test_microvm_any`, a capability-based fixture would be used,
e.g., `test_microvm_with_net`, then the test would instead run on all microvm
images with the `capability:net` tag.

To see what fixtures are available, inspect `conftest.py`.

## Adding Microvm Images

Simply place the microvm image under `s3://spec.ccfc.min/img/`.
The layout is:

``` tree
s3://<bucket-url>/img/
    <microvm_test_image_folder_n>/
        kernel/
            <optional_kernel_name.>vmlinux.bin
        fsfiles/
            <rootfs_name>rootfs.ext4
            <other_fsfile_n>
            ...
        <other_resource_n>
        ...
    ...
```

Then, tag  `<microvm_test_image_folder_n>` with:

``` json
TagSet = [{"key": "capability:<cap_name>", "value": ""}, ...]
```

For example, this can be done from the AWS CLI with:

```sh
aws s3api put-object-tagging                    \
    --bucket ${bucket_name}                     \
    --key img/${microvm_test_image_folder_n}    \
    --tagging "TagSet=[{Key=capability:${cap_name},Value=''}]"
```

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
There are two options to achieve this:

1. Pass the `-i` / `--local-images-path` option to `testrun.sh`. This will use
   local versions of the images found in the common s3 bucket.
2. Leverage pytest to build a self-contained set of tests that use your own test
   bucket.
   - Create the s3 test bucket.
   - Create a new test directory as per `A2`, and a fixture file as per `A3`.
   - Within the new fixture, instantiate a `MicrovmImageS3Fetcher` for your s3
     bucket.
   - Using that `MicrovmImageS3Fetcher` object, create a fixture
     similar to the `test_microvm_*` fixtures in in `conftest.py`, and pass that
     as an argument to your tests.

`Q5:`
*Is there a way to speed up integration tests execution time?*
`A5:`
You can speed up tests execution time with any of these:

1. Run the tests from inside the container and set the environment variable
   `KEEP_TEST_SESSION` to a non-empty value.

   Each **Testrun** begins by building the firecracker and unit tests binaries,
   and ends by deleting all the built artifacts.
   If you run the tests [from inside the container](#running), you can prevent
   the binaries from being deleted exporting the `KEEP_TEST_SESSION` variable.
   This way, all the following **Testrun** will be significantly faster as they
   will not need to rebuild everything.
   If any Rust source file is changed, the build is done incrementally.

2. Pass the `-k substring` option to Pytest to only run a subset of tests by
   specifying a part of their name.

3. Only run the tests contained in a file or directory, as specified in the
   **Running** section.


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

- Modify `MicrovmImageS3Fetcher` to make the above FAQ possible (the borg
  pattern is wrong for this).
- A fixture for interacting with microvms via SSH.
- Support generating fixtures with more than one capability. This is supported
  by the MicrovmImageS3Fetcher, but not plumbed through.
- Use the Firecracker Open API spec to populate Microvm API resource URLs.
- Manage output better: handle quietness levels, and use pytest reports.
- Do the testrun in a container for better insulation.
- Add support for non-Rust style checks.
- Event-based monitoring of microvm socket file creation to avoid while spins.
- Self-tests (e.g., Tests that test the testing system, python3 style tests).

### Implementation

- Run build tests / unit tests with `--release` once
  `https://github.com/edef1c/libfringe/issues/75` is fixed.
- Ensure that we're running in the correct path of the Firecracker repo.
- Looking into `pytest-ordering` to ensure test order.
- `#[test] fn enable_disable_stdin_test()` from `vmm/src/lib.rs` fails if
  `pytest` is allowed to record stdin and stdout. Currently this is worked
  around by running pytest with `--capture=no`, which uglifies the output.
- The code would be less repetitive with a function that wraps
  `subprocess.run('<command>, shell=True, check=True)`.
- Create an integrated, layered `say` system across the test runner and pytest
  (probably based on an environment variable).
- Per test function dependency installation would make tests easer to write.
- Type hinting is used sparsely across tests/* python module. The code would be
  more easily understood with consistent type hints everywhere.

### Bug fixes

- Fix the /install-kcov.sh bug.

## Further Reading

Contributing to this testing system requires a dive deep on `pytest`.
