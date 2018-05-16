# Firecracker Integration Tests

The test herein are meant to uphold the security, quality, and performance
contracts of Firecracker.

## Running

To run all tests:

``` sh
./testrun.sh
```

To run tests from specific directories and/or files:

``` sh
./testrun.sh <dir_or_file_path_n> ...
```

The `pytest` test runner is used. Any parameters passed to `testrun.sh` are
passed to the `pytest` command.

### Output

- Output, including testrun results, goes to `stdout`. Errors go to `stderr`.
- `testrun.sh` will exit with the correct return code.

### Dependencies

- A bare-metal `Linux` host with `uname -r` >= 4.11.
- Availability of either `yum` or `apt-get` to install packages, and `curl`.
- Root mode.

Each testrun will create a temporary sandbox and install all other required
dependencies.

### Caveats

- The sandbox is currently just a best effort. Littering is possible. We should
  move to a real sandbox, like a Firecracker microvm.
- Packages installed via `yum` and `apt-get` are **not** uninstalled. See
  `testrun.sh` for details.

## Adding Tests

Tests can be added in any (existing or new) sub-directory of `tests/`, in files
named `test_*.py`.

Fixtures can be used to quickly build Firecracker microvm integration tests
that run on all microvm images in `s3://spec.firecracker/microvm-images/`.

For example, the test below makes use of the `test_microvm_any` test microvm
fixture, this test will be run on on every microvm image in the bucket, each as
a separate test case.

``` python
def test_with_any_microvm(test_microvm_any, uhttp):
    uhttp.put(test_microvm_any.microvm_cfg_url, json={'vcpu_count': 2})
    assert(uhttp.is_good_response(response.status_code))

    # [...]

    uhttp.put(
        test_microvm_any.actions_url + '/1',
        json={'action_id': '1', 'action_type': 'InstanceStart'}
    )
    assert(uhttp.is_good_response(response.status_code))
```

If instead of `test_microvm_any`, a capability-based fixture would be used,
e.g., `test_microvm_with_net`, then the test would instead run on all microvm
images with the `capability:net` tag.

To see what fixtures are available, inspect `conftest.py`.

## Adding Microvm Images

Simply place the microvm image under `s3://spec.firecracker/microvm-images/`.
The layout is:

``` tree
s3://<bucket-url>/microvm-images/
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

## Adding Fixtures

By default, `pytest` will include `conftest.py` and make all fixtures therein
available to all test functions, so that's a good place to add fixtures. You
can also create `conftest.py` in sub-directories containing tests, or define
fixtures directly in test files. See `pytest` documentation for details.

## Example Manual Testrun

Running on an EC2 `.metal` instance with an `Amazon Linux 2` AMI:

``` sh
# Tests need to run as root, just switch to su
sudo su

# Get firecracker
yum install -y git
git clone https://<user>:<token>@github.com/aws/<firecracker repo>.git

# Run all tests
cd <firecracker repo>/tests
./testrun.sh
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

`Q1:` I have a shell script that runs my tests and I don't want to rewrite it.
`A1:` Insofar as it makes sense, you should write it as a python test function.
      However, you can always call the script from a shim python test function.
      You can also add it as a microvm image resource in the s3 bucket, and it
      will be made available under `microvm.slot.path`.

`Q2:` I want to add more tests that I don't want to commit to the Firecracker
      repository.
`A2:` Before running the integration tests, just add your test directory under
      `tests/`. `pytest` will discover all tests in this tree.

`Q3:` I want to have my own test fixtures, and not commit them in the repo.
`A3:` Add a `conftest.py` file in your test directory, and place your fixtures
      there. `pytest` will bring the into scope for all your tests.

`Q4:` I want to use more microvm test images, but I don't want to add them to
      the common s3 bucket.
`A4:` Create a new test directory as per `A2`. Then, create a `conftest.py`
      file, and within, a `MicrovmImageFetcher` object using your own s3
      bucket. Finally create a fixture similar to the `test_microvm_*` fixtures
      in `tests/conftest.py`, and use that fixture in your tests.

## Implementation Goals

- Easily run tests manually on a development/test machine, and in a continuous
  integration environments.
- Each test should be independent, and self-contained. Tests will time out,
  expect a clean environment, and leave a clean environment behind.
- Always run with the latest dependencies and resources.

### Choice of Pytest & Dependencies

Pytest was chosen because:

- Python makes it easy to work with AWS and other clouds.
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
- `#[test] fn enable_disable_stdin_test()` from `vmm/src/lib.rs` fails if
  `pytest` is allowed to record stdin and stdout. Currently this is worked
  around by running pytest with `--capture=no`, which uglifies the output. A
  better way would be a bonus (Pytest can have really nice reports!).
- In `testrun.sh`, allow explicit package manager selection via arguments.
- Do the testrun in a container for better insulation.
- Add support for non-Rust style checks.
- Event-based monitoring of microvm socket file creation to avoid while spins.
- Command line with help and quiet options for this script.
- Self-tests (e.g., Tests that test the testing system, python3 style tests).

### Implementation

- Ensure that we're running in the correct path of the Firecracker repo.
- Looking into `pytest-ordering` to ensure test order.
- The code would be less repetitive with a function that wraps
  `subprocess.run('<command>, shell=True, check=True)`, controls
  output verbosity by appending `>/dev/null [&2>1]` (or by leveraging python
  logging to control output).
- Add a quiet (=`>dev/null 2>&1`) version to the `testrun.sh` `say`.
- Create an integrated, layered `say` system across the test runner and pytest
  (probably based on an environment variable).
- Per test function dependency installation would make tests easer to write.
- Type hinting is used sparsely across tests/* python module. The code would be
  more easily understood with consistent type hints everywhere.

### Bug fixes

- Fix the /install-kcov.sh bug.

## Further Reading

Contributing to this testing system requires a dive deep on `pytest`.
