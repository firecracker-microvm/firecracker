# Tracing

## Introduction

Firecracker implements a framework for instrumentation based tracing with the
aim to improve its debugability.

Instrumentation based tracing was defined by
[Sheng Liang on usenix.org](https://www.usenix.org/legacy/publications/library/proceedings/coots99/full_papers/liang/liang_html/node9.html)
as:

> There are two ways to obtain profiling information: either statistical
> sampling or code instrumentation. Statistical sampling is less disruptive to
> program execution, but cannot provide completely accurate information. Code
> instrumentation, on the other hand, may be more disruptive, but allows the
> profiler to record all the events it is interested in. Specifically in CPU
> time profiling, statistical sampling may reveal, for example, the relative
> percentage of time spent in frequently-called methods, whereas code
> instrumentation can report the exact number of time each method is invoked.

Enabling tracing adds logs output on each functions entry and exit. This assists
debugging problems that relate to deadlocks or high latencies by quickly
identifying elongated function calls.

## Implementation

Firecracker implements instrumentation based tracing via
[`log`](https://github.com/rust-lang/log) and
[`log_instrument`](../src/log-instrument), outputting a `Trace` level log when
entering and exiting every function.

Adding traces impacts Firecracker binary size and its performance, so
instrumentation is not present by default. Instrumentation is also not present
on the release binaries.

You can use `cargo run --bin clippy-tracing --` to build and run the latest
version in the repo or you can run `cargo install --path src/clippy-tracing` to
install the binary then use `clippy-tracing` to run this binary.

You can run `clippy-tracing --help` for help.

To enable tracing in Firecracker, add instrumentation with:

```
clippy-tracing \
  --action fix \
  --path ./src \
  --exclude benches \
  --exclude virtio/generated,bindings.rs,net/generated \
  --exclude log-instrument-macros/,log-instrument/,clippy-tracing/ \
  --exclude vmm_config/logger.rs,logger/,signal_handler.rs,time.rs
```

`--exclude` can be used to avoid adding instrumentation to specific files, here
it is used to avoid adding instrumentation in:

- tests.
- bindings.
- the instrumentation tooling.
- logger functionality that may form an infinite loop.

After adding instrumentation re-compile with `--features tracing`:

```
cargo build --features tracing
```

This will result in an increase in the binary size (~100kb) and a significant
regression in performance (>10x). To mitigate the performance impact you can
filter the tracing output as described in the next section.

## Filtering

You can filter tracing output both at run-time and compile-time. This can be
used to mitigate the performance impact of logging many traces.

Run-time filtering is implemented with the `/logger` API call, this can
significantly mitigate the impact on execution time but cannot mitigate the
impact on memory usage. Execution time impact is mitigated by avoiding
constructing and writing the trace log, it still needs to check the condition in
every place it would output a log. Memory usage impact is not mitigated as the
instrumentation remains in the binary unchanged.

Compile-time filtering is a manual process using the
[`clippy-tracing`](https://github.com/JonathanWoollett-Light/clippy-tracing)
tool. This can almost entirely mitigate the impact on execution time and the
impact on memory usage.

### Run-time

You can filter by module path and/or file path at runtime, e.g.:

```bash
curl -X PUT --unix-socket "${API_SOCKET}" \
    --data "{
        \"level\": \"Trace\",
        \"module\": \"api_server::request\",
    }" \
    "http://localhost/logger"
```

Instrumentation logs are `Trace` level logs, at runtime the level must be set to
`Trace` to see them. The module filter applied here ensures only logs from the
`request` modules within the `api_server` crate will be output.

This will mitigate most of the performance regression.

### Compile-time

Specific environments can restrict run-time configuration. In these environments
it becomes necessary to support targeted tracing without run-time
re-configuration, for this compile-time filtering must be used.

To reproduce the same filtering as run-time at compile-time, you can use
[`clippy-tracing`](../src/clippy-tracing) at compile-time like:

```bash
# Remove all instrumentation.
clippy-tracing --action strip --path ./src
# Adds instrumentation to the specific file/s.
clippy-tracing --action fix --path ./src/firecracker/src/api_server/src/request
# Build Firecracker.
cargo build --features tracing
```

Then at run-time:

```bash
curl -X PUT --unix-socket "${API_SOCKET}" \
    --data "{
        \"level\": \"Trace\",
    }" \
    "http://localhost/logger"
```

The instrumentation has been stripped from all files other than those at
`./src/firecracker/src/api_server/src/request` so we do not need to apply a
run-time filter. Runtime filtering could be applied but in this case it yields
no additional benefit.

## Example

In this example we start Firecracker with tracing then make a simple API call.

### API call

```
~/Projects/firecracker$ sudo curl -X GET --unix-socket "/run/firecracker.socket" "http://localhost/"
{"id":"anonymous-instance","state":"Not started","vmm_version":"1.6.0-dev","app_name":"Firecracker"}
```

### Firecracker

```
~/Projects/firecracker$ sudo ./firecracker/build/cargo_target/release/firecracker --level Trace
2023-10-13T14:15:38.851263983 [anonymous-instance:main] Running Firecracker v1.6.0-dev
2023-10-13T14:15:38.851316122 [anonymous-instance:main] ThreadId(1)::main::main_exec>>single_value
2023-10-13T14:15:38.851322264 [anonymous-instance:main] ThreadId(1)::main::main_exec::single_value>>value_of
2023-10-13T14:15:38.851325119 [anonymous-instance:main] ThreadId(1)::main::main_exec::single_value<<value_of
2023-10-13T14:15:38.851328776 [anonymous-instance:main] ThreadId(1)::main::main_exec<<single_value
2023-10-13T14:15:38.851331351 [anonymous-instance:main] ThreadId(1)::main::main_exec>>flag_present
2023-10-13T14:15:38.851335809 [anonymous-instance:main] ThreadId(1)::main::main_exec::flag_present>>value_of
2023-10-13T14:15:38.851338254 [anonymous-instance:main] ThreadId(1)::main::main_exec::flag_present<<value_of
2023-10-13T14:15:38.851342091 [anonymous-instance:main] ThreadId(1)::main::main_exec<<flag_present
2023-10-13T14:15:38.851345638 [anonymous-instance:main] ThreadId(1)::main::main_exec>>single_value
2023-10-13T14:15:38.851349245 [anonymous-instance:main] ThreadId(1)::main::main_exec::single_value>>value_of
2023-10-13T14:15:38.851352721 [anonymous-instance:main] ThreadId(1)::main::main_exec::single_value<<value_of
2023-10-13T14:15:38.851355827 [anonymous-instance:main] ThreadId(1)::main::main_exec<<single_value
2023-10-13T14:15:38.851359444 [anonymous-instance:main] ThreadId(1)::main::main_exec>>from_args
2023-10-13T14:15:38.851362931 [anonymous-instance:main] ThreadId(1)::main::main_exec<<from_args
2023-10-13T14:15:38.851366207 [anonymous-instance:main] ThreadId(1)::main::main_exec>>get_filters
2023-10-13T14:15:38.851368401 [anonymous-instance:main] ThreadId(1)::main::main_exec::get_filters>>get_default_filters
2023-10-13T14:15:38.851372068 [anonymous-instance:main] ThreadId(1)::main::main_exec::get_filters::get_default_filters>>deserialize_binary
2023-10-13T14:15:38.851380033 [anonymous-instance:main] ThreadId(1)::main::main_exec::get_filters::get_default_filters<<deserialize_binary
2023-10-13T14:15:38.851383990 [anonymous-instance:main] ThreadId(1)::main::main_exec::get_filters::get_default_filters>>filter_thread_categories
2023-10-13T14:15:38.851388098 [anonymous-instance:main] ThreadId(1)::main::main_exec::get_filters::get_default_filters<<filter_thread_categories
2023-10-13T14:15:38.851391845 [anonymous-instance:main] ThreadId(1)::main::main_exec::get_filters<<get_default_filters
2023-10-13T14:15:38.851394360 [anonymous-instance:main] ThreadId(1)::main::main_exec<<get_filters
2023-10-13T14:15:38.851398077 [anonymous-instance:main] ThreadId(1)::main::main_exec>>single_value
2023-10-13T14:15:38.851400462 [anonymous-instance:main] ThreadId(1)::main::main_exec::single_value>>value_of
2023-10-13T14:15:38.851403507 [anonymous-instance:main] ThreadId(1)::main::main_exec::single_value<<value_of
2023-10-13T14:15:38.851410961 [anonymous-instance:main] ThreadId(1)::main::main_exec<<single_value
2023-10-13T14:15:38.851414107 [anonymous-instance:main] ThreadId(1)::main::main_exec>>single_value
2023-10-13T14:15:38.851417955 [anonymous-instance:main] ThreadId(1)::main::main_exec::single_value>>value_of
2023-10-13T14:15:38.851420650 [anonymous-instance:main] ThreadId(1)::main::main_exec::single_value<<value_of
2023-10-13T14:15:38.851426130 [anonymous-instance:main] ThreadId(1)::main::main_exec<<single_value
2023-10-13T14:15:38.851428434 [anonymous-instance:main] ThreadId(1)::main::main_exec>>flag_present
2023-10-13T14:15:38.851430949 [anonymous-instance:main] ThreadId(1)::main::main_exec::flag_present>>value_of
2023-10-13T14:15:38.851434766 [anonymous-instance:main] ThreadId(1)::main::main_exec::flag_present<<value_of
2023-10-13T14:15:38.851438133 [anonymous-instance:main] ThreadId(1)::main::main_exec<<flag_present
2023-10-13T14:15:38.851440577 [anonymous-instance:main] ThreadId(1)::main::main_exec>>flag_present
2023-10-13T14:15:38.851444575 [anonymous-instance:main] ThreadId(1)::main::main_exec::flag_present>>value_of
2023-10-13T14:15:38.851447941 [anonymous-instance:main] ThreadId(1)::main::main_exec::flag_present<<value_of
2023-10-13T14:15:38.851450005 [anonymous-instance:main] ThreadId(1)::main::main_exec<<flag_present
2023-10-13T14:15:38.851453772 [anonymous-instance:main] ThreadId(1)::main::main_exec>>arguments
2023-10-13T14:15:38.851456488 [anonymous-instance:main] ThreadId(1)::main::main_exec<<arguments
2023-10-13T14:15:38.851458902 [anonymous-instance:main] ThreadId(1)::main::main_exec>>single_value
2023-10-13T14:15:38.851462679 [anonymous-instance:main] ThreadId(1)::main::main_exec::single_value>>value_of
2023-10-13T14:15:38.851466587 [anonymous-instance:main] ThreadId(1)::main::main_exec::single_value<<value_of
2023-10-13T14:15:38.851470324 [anonymous-instance:main] ThreadId(1)::main::main_exec::single_value>>as_single_value
2023-10-13T14:15:38.851473239 [anonymous-instance:main] ThreadId(1)::main::main_exec::single_value<<as_single_value
2023-10-13T14:15:38.851476896 [anonymous-instance:main] ThreadId(1)::main::main_exec<<single_value
2023-10-13T14:15:38.851479521 [anonymous-instance:main] ThreadId(1)::main::main_exec>>arguments
2023-10-13T14:15:38.851485062 [anonymous-instance:main] ThreadId(1)::main::main_exec<<arguments
2023-10-13T14:15:38.851488398 [anonymous-instance:main] ThreadId(1)::main::main_exec>>single_value
2023-10-13T14:15:38.851491925 [anonymous-instance:main] ThreadId(1)::main::main_exec::single_value>>value_of
2023-10-13T14:15:38.851494900 [anonymous-instance:main] ThreadId(1)::main::main_exec::single_value<<value_of
2023-10-13T14:15:38.851496934 [anonymous-instance:main] ThreadId(1)::main::main_exec<<single_value
2023-10-13T14:15:38.851499689 [anonymous-instance:main] ThreadId(1)::main::main_exec>>single_value
2023-10-13T14:15:38.851502374 [anonymous-instance:main] ThreadId(1)::main::main_exec::single_value>>value_of
2023-10-13T14:15:38.851504629 [anonymous-instance:main] ThreadId(1)::main::main_exec::single_value<<value_of
2023-10-13T14:15:38.851507234 [anonymous-instance:main] ThreadId(1)::main::main_exec::single_value>>as_single_value
2023-10-13T14:15:38.851508897 [anonymous-instance:main] ThreadId(1)::main::main_exec::single_value<<as_single_value
2023-10-13T14:15:38.851510630 [anonymous-instance:main] ThreadId(1)::main::main_exec<<single_value
2023-10-13T14:15:38.851513576 [anonymous-instance:main] ThreadId(1)::main::main_exec>>single_value
2023-10-13T14:15:38.851515559 [anonymous-instance:main] ThreadId(1)::main::main_exec::single_value>>value_of
2023-10-13T14:15:38.851517503 [anonymous-instance:main] ThreadId(1)::main::main_exec::single_value<<value_of
2023-10-13T14:15:38.851520068 [anonymous-instance:main] ThreadId(1)::main::main_exec<<single_value
2023-10-13T14:15:38.851521731 [anonymous-instance:main] ThreadId(1)::main::main_exec>>single_value
2023-10-13T14:15:38.851525628 [anonymous-instance:main] ThreadId(1)::main::main_exec::single_value>>value_of
2023-10-13T14:15:38.851529045 [anonymous-instance:main] ThreadId(1)::main::main_exec::single_value<<value_of
2023-10-13T14:15:38.851533153 [anonymous-instance:main] ThreadId(1)::main::main_exec<<single_value
2023-10-13T14:15:38.851536339 [anonymous-instance:main] ThreadId(1)::main::main_exec>>single_value
2023-10-13T14:15:38.851538883 [anonymous-instance:main] ThreadId(1)::main::main_exec::single_value>>value_of
2023-10-13T14:15:38.851542330 [anonymous-instance:main] ThreadId(1)::main::main_exec::single_value<<value_of
2023-10-13T14:15:38.851544704 [anonymous-instance:main] ThreadId(1)::main::main_exec<<single_value
2023-10-13T14:15:38.851548572 [anonymous-instance:main] ThreadId(1)::main::main_exec>>run_with_api
2023-10-13T14:15:38.851664621 [anonymous-instance:main] ThreadId(1)::main::main_exec::run_with_api>>new
2023-10-13T14:15:38.851672586 [anonymous-instance:main] ThreadId(1)::main::main_exec::run_with_api<<new
2023-10-13T14:15:38.851677876 [anonymous-instance:main] ThreadId(1)::main::main_exec::run_with_api>>init
2023-10-13T14:15:38.851684739 [anonymous-instance:main] ThreadId(1)::main::main_exec::run_with_api<<init
2023-10-13T14:15:38.851724064 [anonymous-instance:main] ThreadId(1)::main::main_exec::run_with_api>>build_microvm_from_requests
2023-10-13T14:15:38.851728171 [anonymous-instance:main] ThreadId(1)::main::main_exec::run_with_api::build_microvm_from_requests>>default
2023-10-13T14:15:38.851731888 [anonymous-instance:main] ThreadId(1)::main::main_exec::run_with_api::build_microvm_from_requests<<default
2023-10-13T14:15:38.851734634 [anonymous-instance:main] ThreadId(1)::main::main_exec::run_with_api::build_microvm_from_requests>>new
2023-10-13T14:15:38.851737830 [anonymous-instance:main] ThreadId(1)::main::main_exec::run_with_api::build_microvm_from_requests<<new
2023-10-13T14:15:38.851748550 [anonymous-instance:fc_api] ThreadId(2)>>new
2023-10-13T14:15:38.851761404 [anonymous-instance:fc_api] ThreadId(2)<<new
2023-10-13T14:15:38.851764861 [anonymous-instance:fc_api] ThreadId(2)>>run
2023-10-13T14:15:38.851775200 [anonymous-instance:fc_api] ThreadId(2)::run>>apply_filter
2023-10-13T14:15:38.851823462 [anonymous-instance:fc_api] ThreadId(2)::run<<apply_filter
2023-10-13T14:15:55.422397039 [anonymous-instance:fc_api] ThreadId(2)::run>>handle_request
2023-10-13T14:15:55.422417909 [anonymous-instance:fc_api] ThreadId(2)::run::handle_request>>try_from
2023-10-13T14:15:55.422420554 [anonymous-instance:fc_api] ThreadId(2)::run::handle_request::try_from>>describe
2023-10-13T14:15:55.422424551 [anonymous-instance:fc_api] ThreadId(2)::run::handle_request::try_from<<describe
2023-10-13T14:15:55.422426395 [anonymous-instance:fc_api] ThreadId(2)::run::handle_request::try_from>>log_received_api_request
2023-10-13T14:15:55.422429270 [anonymous-instance:fc_api] The API server received a Get request on "/".
2023-10-13T14:15:55.422431354 [anonymous-instance:fc_api] ThreadId(2)::run::handle_request::try_from<<log_received_api_request
2023-10-13T14:15:55.422433298 [anonymous-instance:fc_api] ThreadId(2)::run::handle_request::try_from>>parse_get_instance_info
2023-10-13T14:15:55.422435211 [anonymous-instance:fc_api] ThreadId(2)::run::handle_request::try_from::parse_get_instance_info>>new_sync
2023-10-13T14:15:55.422437165 [anonymous-instance:fc_api] ThreadId(2)::run::handle_request::try_from::parse_get_instance_info::new_sync>>new
2023-10-13T14:15:55.422439289 [anonymous-instance:fc_api] ThreadId(2)::run::handle_request::try_from::parse_get_instance_info::new_sync<<new
2023-10-13T14:15:55.422441123 [anonymous-instance:fc_api] ThreadId(2)::run::handle_request::try_from::parse_get_instance_info<<new_sync
2023-10-13T14:15:55.422444459 [anonymous-instance:fc_api] ThreadId(2)::run::handle_request::try_from<<parse_get_instance_info
2023-10-13T14:15:55.422446833 [anonymous-instance:fc_api] ThreadId(2)::run::handle_request<<try_from
2023-10-13T14:15:55.422448837 [anonymous-instance:fc_api] ThreadId(2)::run::handle_request>>into_parts
2023-10-13T14:15:55.422450921 [anonymous-instance:fc_api] ThreadId(2)::run::handle_request<<into_parts
2023-10-13T14:15:55.422453967 [anonymous-instance:fc_api] ThreadId(2)::run::handle_request>>serve_vmm_action_request
2023-10-13T14:15:55.422472552 [anonymous-instance:main] ThreadId(1)::main::main_exec::run_with_api::build_microvm_from_requests>>handle_preboot_request
2023-10-13T14:15:55.422480477 [anonymous-instance:main] ThreadId(1)::main::main_exec::run_with_api::build_microvm_from_requests<<handle_preboot_request
2023-10-13T14:15:55.422488963 [anonymous-instance:fc_api] ThreadId(2)::run::handle_request::serve_vmm_action_request>>convert_to_response
2023-10-13T14:15:55.422492289 [anonymous-instance:fc_api] ThreadId(2)::run::handle_request::serve_vmm_action_request::convert_to_response>>success_response_with_data
2023-10-13T14:15:55.422493983 [anonymous-instance:fc_api] The request was executed successfully. Status code: 200 OK.
2023-10-13T14:15:55.422498331 [anonymous-instance:fc_api] ThreadId(2)::run::handle_request::serve_vmm_action_request::convert_to_response::success_response_with_data>>serialize
2023-10-13T14:15:55.422501387 [anonymous-instance:fc_api] ThreadId(2)::run::handle_request::serve_vmm_action_request::convert_to_response::success_response_with_data::serialize>>fmt
2023-10-13T14:15:55.422506086 [anonymous-instance:fc_api] ThreadId(2)::run::handle_request::serve_vmm_action_request::convert_to_response::success_response_with_data::serialize<<fmt
2023-10-13T14:15:55.422509171 [anonymous-instance:fc_api] ThreadId(2)::run::handle_request::serve_vmm_action_request::convert_to_response::success_response_with_data<<serialize
2023-10-13T14:15:55.422511776 [anonymous-instance:fc_api] ThreadId(2)::run::handle_request::serve_vmm_action_request::convert_to_response<<success_response_with_data
2023-10-13T14:15:55.422514371 [anonymous-instance:fc_api] ThreadId(2)::run::handle_request::serve_vmm_action_request<<convert_to_response
2023-10-13T14:15:55.422516385 [anonymous-instance:fc_api] ThreadId(2)::run::handle_request<<serve_vmm_action_request
2023-10-13T14:15:55.422518719 [anonymous-instance:fc_api] ThreadId(2)::run::handle_request>>take_deprecation_message
2023-10-13T14:15:55.422520533 [anonymous-instance:fc_api] ThreadId(2)::run::handle_request<<take_deprecation_message
2023-10-13T14:15:55.422522847 [anonymous-instance:fc_api] ThreadId(2)::run<<handle_request
2023-10-13T14:15:55.422525422 [anonymous-instance:fc_api] Total previous API call duration: 132 us.

```
