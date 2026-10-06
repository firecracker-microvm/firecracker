// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::CStr;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;

mod bindings;
use bindings::*;

pub mod bpf;
pub mod types;
pub use types::*;

// This byte limit is passed to `bitcode` to guard against a potential memory
// allocation DOS caused by binary filters that are too large.
// This limit can be safely determined since the maximum length of a BPF
// filter is 4096 instructions and Firecracker has a finite number of threads.
const DESERIALIZATION_BYTES_LIMIT: usize = 100_000;

/// Binary filter compilation errors.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum CompilationError {
    /// Cannot open input file: {0}
    IntputOpen(std::io::Error),
    /// Cannot read input file: {0}
    InputRead(std::io::Error),
    /// Cannot deserialize json: {0}
    JsonDeserialize(serde_json::Error),
    /// Cannot parse arch: {0}
    ArchParse(String),
    /// Cannot create libseccomp context
    LibSeccompContext,
    /// Cannot add libseccomp arch
    LibSeccompArch,
    /// Cannot add libseccomp syscall
    LibSeccompSycall,
    /// Cannot resolve syscall {0:?} for the target architecture
    SyscallResolve(String),
    /// Cannot add libseccomp syscall rule
    LibSeccompRule,
    /// Cannot export libseccomp bpf
    LibSeccompExport,
    /// Rule for {0:?} has an empty feature tag
    EmptyFeatures(String),
    /// A filter with feature-tagged rules needs distinct default and filter actions
    SameActions,
    /// Cannot generate BPF for feature-tagged rules: {0}
    Bpf(bpf::BpfError),
    /// Cannot create output file: {0}
    OutputCreate(std::io::Error),
    /// Cannot serialize bfp: {0}
    BitcodeSerialize(bitcode::Error),
    /// Serialized BPF exceeds size limit of {0} bytes
    SizeLimitExceeded(usize),
}

/// Compile the JSON filters in `input_path` for `arch` into `out_path`.
///
/// Untagged rules are compiled with libseccomp into the base program of their thread. Rules tagged
/// with features are compiled into separate, position independent BPF fragments that Firecracker
/// appends to the base program at runtime when one of their features is in use (see
/// [`BpfFilter`]). `basic` drops all argument checks (deprecated) and `split_output` writes one raw
/// program per thread with every fragment included instead of the serialized [`BpfMap`].
pub fn compile_bpf(
    input_path: &str,
    arch: &str,
    out_path: &str,
    basic: bool,
    split_output: bool,
) -> Result<(), CompilationError> {
    let mut file_content = String::new();
    File::open(input_path)
        .map_err(CompilationError::IntputOpen)?
        .read_to_string(&mut file_content)
        .map_err(CompilationError::InputRead)?;
    let bpf_map_json: BpfJson =
        serde_json::from_str(&file_content).map_err(CompilationError::JsonDeserialize)?;

    let arch = TargetArch::from_str(arch).map_err(CompilationError::ArchParse)?;

    let mut bpf_map = BpfMap::new();
    for (name, filter) in bpf_map_json.0.iter() {
        bpf_map.insert(name.clone(), compile_filter(filter, &arch, basic)?);
    }

    if split_output {
        // Output individual files for each thread (for testing)
        let base_path = Path::new(out_path);
        let parent = base_path.parent().unwrap_or_else(|| Path::new("."));

        for (thread_name, bpf_filter) in &bpf_map {
            let thread_file_path = parent.join(format!("{}.bpf", thread_name));
            let mut thread_file =
                File::create(&thread_file_path).map_err(CompilationError::OutputCreate)?;

            // Write raw BPF data as bytes
            use zerocopy::IntoBytes;
            std::io::Write::write_all(&mut thread_file, bpf_filter.compose_all().as_bytes())
                .map_err(CompilationError::OutputCreate)?;
        }
    } else {
        // Create and write the main bitcode output file
        let mut output_file = File::create(out_path).map_err(CompilationError::OutputCreate)?;
        let encoded = bitcode::serialize(&bpf_map).map_err(CompilationError::BitcodeSerialize)?;

        // Check size limit to prevent DOS attacks
        let header_len = BPF_FILTER_MAGIC.len() + std::mem::size_of::<u32>();
        if encoded.len() + header_len > DESERIALIZATION_BYTES_LIMIT {
            return Err(CompilationError::SizeLimitExceeded(
                DESERIALIZATION_BYTES_LIMIT,
            ));
        }

        std::io::Write::write_all(&mut output_file, &BPF_FILTER_MAGIC)
            .and_then(|()| {
                std::io::Write::write_all(
                    &mut output_file,
                    &BPF_FILTER_FORMAT_VERSION.to_le_bytes(),
                )
            })
            .and_then(|()| std::io::Write::write_all(&mut output_file, &encoded))
            .map_err(CompilationError::OutputCreate)?;
    }

    Ok(())
}

/// Compile the filter of one thread category.
fn compile_filter(
    filter: &Filter,
    arch: &TargetArch,
    basic: bool,
) -> Result<BpfFilter, CompilationError> {
    let default_action = filter.default_action.to_scmp_type();
    let filter_action = filter.filter_action.to_scmp_type();
    for rule in &filter.filter {
        if rule
            .features
            .as_ref()
            .is_some_and(|features| features.is_empty() || features.iter().any(String::is_empty))
        {
            return Err(CompilationError::EmptyFeatures(
                rule.syscall.to_string_lossy().into_owned(),
            ));
        }
    }
    let (tagged, untagged): (Vec<&SyscallRule>, Vec<&SyscallRule>) = filter
        .filter
        .iter()
        .partition(|rule| rule.features.is_some());

    let mut base = libseccomp_program(&untagged, arch, default_action, filter_action, basic)?;
    if tagged.is_empty() {
        return Ok(BpfFilter {
            base,
            fragments: Vec::new(),
            epilogue: Vec::new(),
        });
    }

    // The fragments return the filter action and the epilogue the default action; with identical
    // actions the tags would be meaningless.
    if default_action == filter_action {
        return Err(CompilationError::SameActions);
    }

    // Let the base fall through into the appended code instead of returning the default action,
    // and re-check the architecture there since libseccomp may share the default and bad-arch
    // returns.
    bpf::redirect_default_returns(&mut base, default_action).map_err(CompilationError::Bpf)?;
    base.extend(bpf::suffix_prologue(arch, default_action));

    let fragments = tagged
        .iter()
        .map(|rule| {
            let syscall = resolve_syscall_for_arch(arch, &rule.syscall)?;
            let conditions = match (&rule.args, basic) {
                (Some(conditions), false) => conditions.as_slice(),
                _ => &[],
            };
            let code = bpf::rule_fragment(syscall, conditions, filter_action)
                .map_err(CompilationError::Bpf)?;
            Ok(BpfFragment {
                // Tagged rules were partitioned by `features.is_some()`.
                features: rule.features.clone().unwrap_or_default(),
                code,
            })
        })
        .collect::<Result<Vec<_>, CompilationError>>()?;

    let compiled = BpfFilter {
        base,
        fragments,
        epilogue: bpf::epilogue(default_action),
    };

    // The program with every fragment included is the longest one Firecracker can install; make
    // sure the kernel will accept it. Leaving fragments out only shortens it.
    bpf::validate(&compiled.compose_all()).map_err(CompilationError::Bpf)?;

    Ok(compiled)
}

/// The syscall number of `name` on `arch`.
fn resolve_syscall_for_arch(arch: &TargetArch, name: &CStr) -> Result<u32, CompilationError> {
    // SAFETY: Safe as all args are correct.
    let syscall = unsafe { seccomp_syscall_resolve_name_arch(arch.to_scmp_type(), name.as_ptr()) };
    // Pseudo syscall numbers are negative too; they have no place in a BPF fragment.
    u32::try_from(syscall)
        .map_err(|_| CompilationError::SyscallResolve(name.to_string_lossy().into_owned()))
}

/// Compile `rules` with libseccomp into a complete program.
fn libseccomp_program(
    rules: &[&SyscallRule],
    arch: &TargetArch,
    default_action: u32,
    filter_action: u32,
    basic: bool,
) -> Result<Vec<u64>, CompilationError> {
    // SAFETY: Safe as all args are correct.
    let bpf_filter = {
        let r = seccomp_init(default_action);
        if r.is_null() {
            return Err(CompilationError::LibSeccompContext);
        }
        r
    };

    // SAFETY: Safe as all args are correct.
    unsafe {
        let r = seccomp_arch_add(bpf_filter, arch.to_scmp_type());
        if r != 0 && r != MINUS_EEXIST {
            return Err(CompilationError::LibSeccompArch);
        }
    }

    // libseccomp seeds every context with the build host's architecture. A filter is only ever
    // installed on its target architecture, so drop the host's when it is a different one.
    // SAFETY: Safe as all args are correct.
    unsafe {
        let native = seccomp_arch_native();
        if native != arch.to_scmp_type() {
            let r = seccomp_arch_remove(bpf_filter, native);
            if r != 0 && r != MINUS_EEXIST {
                return Err(CompilationError::LibSeccompArch);
            }
        }
    }

    for rule in rules {
        // SAFETY: Safe as all args are correct.
        let syscall = unsafe {
            let r = seccomp_syscall_resolve_name(rule.syscall.as_ptr());
            if r == __NR_SCMP_ERROR {
                return Err(CompilationError::LibSeccompSycall);
            }
            r
        };

        // TODO remove when we drop deprecated "basic" arg from cli.
        // "basic" bpf means it ignores condition checks.
        if basic {
            // SAFETY: Safe as all args are correct.
            unsafe {
                if seccomp_rule_add(bpf_filter, filter_action, syscall, 0) != 0 {
                    return Err(CompilationError::LibSeccompRule);
                }
            }
        } else if let Some(rules) = &rule.args {
            let comparators = rules
                .iter()
                .map(|rule| rule.to_scmp_type())
                .collect::<Vec<scmp_arg_cmp>>();

            // SAFETY: Safe as all args are correct.
            // We can assume no one will define u32::MAX
            // filters for a syscall.
            #[allow(clippy::cast_possible_truncation)]
            unsafe {
                if seccomp_rule_add_array(
                    bpf_filter,
                    filter_action,
                    syscall,
                    comparators.len() as u32,
                    comparators.as_ptr(),
                ) != 0
                {
                    return Err(CompilationError::LibSeccompRule);
                }
            }
        } else {
            // SAFETY: Safe as all args are correct.
            unsafe {
                if seccomp_rule_add(bpf_filter, filter_action, syscall, 0) != 0 {
                    return Err(CompilationError::LibSeccompRule);
                }
            }
        }
    }

    let mut len: usize = 0;
    // First call obtains the size of the buffer we need to give
    // SAFETY: safe as all args are correct
    unsafe {
        if seccomp_export_bpf_mem(bpf_filter, std::ptr::null_mut(), &mut len) != 0 {
            return Err(CompilationError::LibSeccompExport);
        }
    }
    // If this is not true, we found a bug in libseccomp.
    assert!(len.is_multiple_of(std::mem::size_of::<u64>()));
    // Bpf instructions are 8 byte values and 4 byte alignment.
    // We use u64 to satisfy these requirements.
    let mut bpf = vec![0_u64; len / std::mem::size_of::<u64>()];
    // SAFETY: safe as all args are correct
    unsafe {
        if seccomp_export_bpf_mem(bpf_filter, bpf.as_mut_ptr().cast(), &mut len) != 0 {
            return Err(CompilationError::LibSeccompExport);
        }
    }

    Ok(bpf)
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::io::Write;

    use vmm_sys_util::tempfile::TempFile;

    use super::bpf::tests::{SeccompData, simulate};
    use super::bpf::{AUDIT_ARCH_AARCH64, BPF_RET_K, X32_SYSCALL_BIT, audit_arch, decode};
    use super::*;

    const SECCOMP_RET_KILL_THREAD: u32 = 0x0000_0000;
    const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

    /// An architecture no filter is compiled for.
    const AUDIT_ARCH_I386: u32 = 0x4000_0003;

    // x86_64 syscall numbers.
    const NR_WRITE: i32 = 1;
    const NR_OPEN: i32 = 2;
    const NR_IOCTL: i32 = 16;
    const NR_GETPID: i32 = 39;
    // aarch64 syscall numbers.
    const NR_IOCTL_AARCH64: i32 = 29;
    const NR_GETPID_AARCH64: i32 = 172;

    const KVM_RUN: u64 = 44672;
    const TUNSETOFFLOAD: u64 = 1074025680;

    const TAGGED_JSON: &str = r#"{
        "main": {
            "default_action": "trap",
            "filter_action": "allow",
            "filter": [
                { "syscall": "write" },
                {
                    "syscall": "ioctl",
                    "args": [{ "index": 1, "type": "dword", "op": "eq", "val": 44672 }]
                },
                {
                    "syscall": "ioctl",
                    "feature": "net",
                    "args": [{ "index": 1, "type": "dword", "op": "eq", "val": 1074025680 }]
                },
                { "syscall": "getpid", "features": ["pmem", "memory-hotplug"] }
            ]
        },
        "untagged": {
            "default_action": "trap",
            "filter_action": "allow",
            "filter": [{ "syscall": "write" }]
        }
    }"#;

    /// Compile `json` for `arch` and read back the serialized map.
    fn compile(json: &str, arch: &str, basic: bool) -> Result<BpfMap, CompilationError> {
        let input = TempFile::new().unwrap();
        input.as_file().write_all(json.as_bytes()).unwrap();
        let output = TempFile::new().unwrap();
        compile_bpf(
            input.as_path().to_str().unwrap(),
            arch,
            output.as_path().to_str().unwrap(),
            basic,
            false,
        )?;
        let encoded = std::fs::read(output.as_path()).unwrap();
        assert_eq!(&encoded[..4], &BPF_FILTER_MAGIC);
        assert_eq!(&encoded[4..8], &BPF_FILTER_FORMAT_VERSION.to_le_bytes());
        Ok(bitcode::deserialize(&encoded[8..]).unwrap())
    }

    /// The default filter of `arch` as JSON text.
    fn default_filter_json(arch: &str) -> String {
        std::fs::read_to_string(format!(
            "{}/../../resources/seccomp/{arch}-unknown-linux-musl.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    /// `json` with every feature tag removed, so that every rule is compiled by libseccomp.
    fn untagged(json: &str) -> String {
        let mut value: serde_json::Value = serde_json::from_str(json).unwrap();
        for filter in value.as_object_mut().unwrap().values_mut() {
            for rule in filter["filter"].as_array_mut().unwrap() {
                let rule = rule.as_object_mut().unwrap();
                rule.remove("feature");
                rule.remove("features");
            }
        }
        value.to_string()
    }

    fn ioctl(nr: i32, request: u64) -> SeccompData {
        SeccompData::x86_64(nr, [3, request, 0, 0, 0, 0])
    }

    fn syscall(nr: i32) -> SeccompData {
        SeccompData::x86_64(nr, [0; 6])
    }

    /// The program of `filter` with only the fragments of `enabled` included.
    fn compose(filter: &BpfFilter, enabled: &[&str]) -> Vec<u64> {
        let mut program = filter.base.clone();
        for fragment in &filter.fragments {
            if fragment
                .features
                .iter()
                .any(|feature| enabled.contains(&feature.as_str()))
            {
                program.extend_from_slice(&fragment.code);
            }
        }
        program.extend_from_slice(&filter.epilogue);
        program
    }

    #[test]
    fn test_compile_untagged_filter() {
        let map = compile(TAGGED_JSON, "x86_64", false).unwrap();
        let filter = &map["untagged"];

        // A filter without tagged rules is a plain libseccomp program.
        assert!(filter.fragments.is_empty());
        assert!(filter.epilogue.is_empty());
        assert_eq!(filter.compose_all(), filter.base);
        bpf::validate(&filter.base).unwrap();

        assert_eq!(
            simulate(&filter.base, &syscall(NR_WRITE)),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(simulate(&filter.base, &syscall(NR_OPEN)), SECCOMP_RET_TRAP);
        assert_eq!(
            simulate(
                &filter.base,
                &SeccompData::new(AUDIT_ARCH_I386, NR_WRITE, [0; 6])
            ),
            SECCOMP_RET_KILL_THREAD
        );
    }

    #[test]
    fn test_compile_tagged_filter() {
        let map = compile(TAGGED_JSON, "x86_64", false).unwrap();
        let filter = &map["main"];

        assert_eq!(filter.fragments.len(), 2);
        assert_eq!(filter.fragments[0].features, ["net"]);
        assert_eq!(filter.fragments[1].features, ["pmem", "memory-hotplug"]);
        assert_eq!(filter.epilogue, bpf::epilogue(SECCOMP_RET_TRAP));
        // The base no longer returns the default action; its own returns are the filter action
        // and the bad-arch kill, plus the prologue's default returns.
        let returns = filter
            .base
            .iter()
            .map(|&insn| decode(insn))
            .filter(|(code, ..)| *code == BPF_RET_K)
            .map(|(.., k)| k)
            .collect::<Vec<_>>();
        assert!(returns.contains(&SECCOMP_RET_ALLOW));
        assert!(returns.contains(&SECCOMP_RET_KILL_THREAD));
        assert_eq!(
            returns.iter().filter(|&&k| k == SECCOMP_RET_TRAP).count(),
            2,
            "x86_64 prologue returns the default action for a foreign arch and for x32"
        );

        for enabled in [&[][..], &["net"], &["pmem"], &["memory-hotplug", "net"]] {
            let program = compose(filter, enabled);
            bpf::validate(&program).unwrap();

            // The untagged rules are unaffected by the enabled features.
            assert_eq!(simulate(&program, &syscall(NR_WRITE)), SECCOMP_RET_ALLOW);
            assert_eq!(
                simulate(&program, &ioctl(NR_IOCTL, KVM_RUN)),
                SECCOMP_RET_ALLOW
            );
            assert_eq!(simulate(&program, &syscall(NR_OPEN)), SECCOMP_RET_TRAP);
            assert_eq!(simulate(&program, &ioctl(NR_IOCTL, 7)), SECCOMP_RET_TRAP);
            // libseccomp's own arch and x32 checks still come first.
            assert_eq!(
                simulate(
                    &program,
                    &SeccompData::new(AUDIT_ARCH_I386, NR_WRITE, [0; 6])
                ),
                SECCOMP_RET_KILL_THREAD
            );
            assert_eq!(
                simulate(
                    &program,
                    &syscall(NR_GETPID | i32::try_from(X32_SYSCALL_BIT).unwrap())
                ),
                SECCOMP_RET_KILL_THREAD
            );

            // The tagged rules are only there when one of their features is enabled.
            let net = if enabled.contains(&"net") {
                SECCOMP_RET_ALLOW
            } else {
                SECCOMP_RET_TRAP
            };
            assert_eq!(simulate(&program, &ioctl(NR_IOCTL, TUNSETOFFLOAD)), net);
            // musl leaves garbage in the upper half of ioctl's request argument.
            assert_eq!(
                simulate(&program, &ioctl(NR_IOCTL, TUNSETOFFLOAD | 0xdead << 32)),
                net
            );
            let getpid = if enabled.contains(&"pmem") || enabled.contains(&"memory-hotplug") {
                SECCOMP_RET_ALLOW
            } else {
                SECCOMP_RET_TRAP
            };
            assert_eq!(simulate(&program, &syscall(NR_GETPID)), getpid);
        }
    }

    #[test]
    fn test_compile_tagged_filter_aarch64() {
        let map = compile(TAGGED_JSON, "aarch64", false).unwrap();
        let filter = &map["main"];
        let program = filter.compose_all();
        bpf::validate(&program).unwrap();

        // Syscalls of tagged rules are resolved for the target architecture, not the host.
        let data = |nr, args| SeccompData::new(AUDIT_ARCH_AARCH64, nr, args);
        assert_eq!(
            simulate(
                &program,
                &data(NR_IOCTL_AARCH64, [3, TUNSETOFFLOAD, 0, 0, 0, 0])
            ),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(
            simulate(&program, &data(NR_GETPID_AARCH64, [0; 6])),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(
            simulate(&program, &data(NR_IOCTL, [3, TUNSETOFFLOAD, 0, 0, 0, 0])),
            SECCOMP_RET_TRAP
        );
        // A foreign architecture is killed by libseccomp's own check, with or without fragments.
        assert_eq!(
            simulate(
                &program,
                &SeccompData::new(AUDIT_ARCH_I386, NR_GETPID_AARCH64, [0; 6])
            ),
            SECCOMP_RET_KILL_THREAD
        );
        assert_eq!(
            simulate(
                &compose(filter, &[]),
                &SeccompData::new(AUDIT_ARCH_I386, NR_GETPID_AARCH64, [0; 6])
            ),
            SECCOMP_RET_KILL_THREAD
        );
    }

    #[test]
    fn test_compile_basic_drops_conditions() {
        let map = compile(TAGGED_JSON, "x86_64", true).unwrap();
        let program = map["main"].compose_all();
        bpf::validate(&program).unwrap();
        assert_eq!(simulate(&program, &ioctl(NR_IOCTL, 7)), SECCOMP_RET_ALLOW);
        // ld nr, jeq nr, ret: no argument checks.
        assert_eq!(map["main"].fragments[0].code.len(), 3);
    }

    #[test]
    fn test_compile_errors() {
        let same_actions = r#"{ "main": { "default_action": "allow", "filter_action": "allow",
            "filter": [{ "syscall": "write", "feature": "net" }] } }"#;
        assert!(matches!(
            compile(same_actions, "x86_64", false).unwrap_err(),
            CompilationError::SameActions
        ));

        let unknown_syscall = r#"{ "main": { "default_action": "trap", "filter_action": "allow",
            "filter": [{ "syscall": "no_such_syscall", "feature": "net" }] } }"#;
        assert!(matches!(
            compile(unknown_syscall, "x86_64", false).unwrap_err(),
            CompilationError::SyscallResolve(name) if name == "no_such_syscall"
        ));

        let both_keys = r#"{ "main": { "default_action": "trap", "filter_action": "allow",
            "filter": [{ "syscall": "write", "feature": "net", "features": ["pci"] }] } }"#;
        assert!(matches!(
            compile(both_keys, "x86_64", false).unwrap_err(),
            CompilationError::JsonDeserialize(_)
        ));
    }

    #[test]
    fn test_compile_unknown_keys() {
        // Comments are accepted on rules and conditions.
        let commented = r#"{ "main": { "default_action": "trap", "filter_action": "allow",
            "filter": [{ "syscall": "ioctl", "comment": "rule", "feature": "net",
                "args": [{ "index": 1, "type": "dword", "op": "eq", "val": 1,
                    "comment": "condition" }] }] } }"#;
        compile(commented, "x86_64", false).unwrap();

        // A misspelled key is an error rather than silently ignored: a mistyped tag would
        // otherwise turn the rule into an always installed one, a mistyped condition key would
        // drop the condition.
        for json in [
            r#"{ "main": { "default_action": "trap", "filter_action": "allow",
                "filter": [{ "syscall": "write", "featrue": "net" }] } }"#,
            r#"{ "main": { "default_action": "trap", "filter_action": "allow",
                "filter": [{ "syscall": "ioctl", "arg": [] }] } }"#,
            r#"{ "main": { "default_action": "trap", "filter_action": "allow",
                "filter": [{ "syscall": "ioctl",
                    "args": [{ "index": 1, "type": "dword", "op": "eq", "val": 1,
                        "mask": 3 }] }] } }"#,
            r#"{ "main": { "default_action": "trap", "filter_action": "allow",
                "default": "allow", "filter": [] } }"#,
        ] {
            assert!(
                matches!(
                    compile(json, "x86_64", false).unwrap_err(),
                    CompilationError::JsonDeserialize(_)
                ),
                "{json}"
            );
        }
    }

    #[test]
    fn test_compile_empty_feature_tag() {
        for tag in [
            r#""features": []"#,
            r#""feature": """#,
            r#""features": ["net", ""]"#,
        ] {
            let json = format!(
                r#"{{ "main": {{ "default_action": "trap", "filter_action": "allow",
                "filter": [{{ "syscall": "write", {tag} }}] }} }}"#
            );
            assert!(matches!(
                compile(&json, "x86_64", false).unwrap_err(),
                CompilationError::EmptyFeatures(name) if name == "write"
            ));
        }
    }

    /// Every syscall and argument combination the default filters mention, plus the awkward
    /// cases: values next to the ones in the rules, garbage in the upper half of an argument,
    /// the x32 bit, `nr == -1` and a foreign architecture.
    fn default_filter_corpus(json: &str, arch: &TargetArch) -> Vec<SeccompData> {
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        let mut corpus = vec![
            SeccompData::new(audit_arch(arch), -1, [0; 6]),
            SeccompData::new(
                audit_arch(arch),
                NR_WRITE | i32::try_from(X32_SYSCALL_BIT).unwrap(),
                [0; 6],
            ),
            SeccompData::new(AUDIT_ARCH_I386, NR_WRITE, [0; 6]),
            SeccompData::new(AUDIT_ARCH_I386, NR_IOCTL, [3, KVM_RUN, 0, 0, 0, 0]),
        ];
        for filter in value.as_object().unwrap().values() {
            for rule in filter["filter"].as_array().unwrap() {
                let name = CString::new(rule["syscall"].as_str().unwrap()).unwrap();
                let nr = i32::try_from(resolve_syscall_for_arch(arch, &name).unwrap()).unwrap();
                let mut args = [0u64; 6];
                let conditions = rule["args"].as_array().cloned().unwrap_or_default();
                for condition in &conditions {
                    let index = usize::try_from(condition["index"].as_u64().unwrap()).unwrap();
                    args[index] = condition["val"].as_u64().unwrap();
                }
                corpus.push(SeccompData::new(audit_arch(arch), nr, args));
                corpus.push(SeccompData::new(audit_arch(arch), nr, [u64::MAX; 6]));
                for condition in &conditions {
                    let index = usize::try_from(condition["index"].as_u64().unwrap()).unwrap();
                    for variant in [
                        args[index].wrapping_add(1),
                        args[index].wrapping_sub(1),
                        args[index] | 0xdead_beef << 32,
                        args[index] ^ 1 << 31,
                    ] {
                        let mut args = args;
                        args[index] = variant;
                        corpus.push(SeccompData::new(audit_arch(arch), nr, args));
                    }
                }
            }
        }
        corpus
    }

    /// With every fragment included, a default filter behaves exactly like the monolithic
    /// libseccomp program of the same rules; with none included it is never more permissive.
    #[test]
    fn test_default_filters_match_monolithic_programs() {
        for (arch_name, arch) in [
            ("x86_64", TargetArch::X86_64),
            ("aarch64", TargetArch::Aarch64),
        ] {
            let json = default_filter_json(arch_name);
            let tagged = compile(&json, arch_name, false).unwrap();
            let monolithic = compile(&untagged(&json), arch_name, false).unwrap();
            let corpus = default_filter_corpus(&json, &arch);
            assert!(corpus.len() > 100);

            for (thread, filter) in &tagged {
                let monolithic = &monolithic[thread];
                assert!(monolithic.fragments.is_empty());
                let everything = filter.compose_all();
                let mut nothing = filter.base.clone();
                nothing.extend_from_slice(&filter.epilogue);
                bpf::validate(&everything).unwrap();
                bpf::validate(&nothing).unwrap();

                for data in &corpus {
                    let expected = simulate(&monolithic.base, data);
                    assert_eq!(
                        simulate(&everything, data),
                        expected,
                        "{arch_name}/{thread}: nr {} args {:x?}",
                        data.nr,
                        data.args
                    );
                    let restricted = simulate(&nothing, data);
                    assert!(
                        restricted == expected || restricted == SECCOMP_RET_TRAP,
                        "{arch_name}/{thread}: nr {} args {:x?} gave {restricted:#x} without \
                         fragments but {expected:#x} with all of them",
                        data.nr,
                        data.args
                    );
                }
            }
        }
    }
}
