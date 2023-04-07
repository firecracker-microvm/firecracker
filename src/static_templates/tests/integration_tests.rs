// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(target_arch = "x86_64")]
mod main_branch;

#[cfg(target_arch = "x86_64")]
mod x86_64 {
    use static_templates::{c3, t2, t2a, t2cl, t2s};
    use vmm::guest_config::templates::CpuTemplate;

    fn load_json_template(template_type: &str) -> CpuTemplate {
        use std::fs::read_to_string;
        use std::path::PathBuf;

        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push(format!("tests/json/{template_type}.json"));

        let json_string = read_to_string(path).unwrap();
        serde_json::from_str(&json_string).unwrap()
    }

    #[test]
    fn test_c3_json() {
        let json_template = load_json_template("c3");
        assert_eq!(json_template, c3::c3());
    }

    #[test]
    fn test_t2_json() {
        let json_template = load_json_template("t2");
        assert_eq!(json_template, t2::t2());
    }

    #[test]
    fn test_t2a_json() {
        let json_template = load_json_template("t2a");
        assert_eq!(json_template, t2a::t2a());
    }

    #[test]
    fn test_t2cl_json() {
        let json_template = load_json_template("t2cl");
        assert_eq!(json_template, t2cl::t2cl());
    }

    #[test]
    fn test_t2s_json() {
        let json_template = load_json_template("t2s");
        assert_eq!(json_template, t2s::t2s());
    }

    #[test]
    fn test_c3_main_branch() {
        let main_template = crate::main_branch::intel::c3::c3();
        assert_eq!(main_template, c3::c3());
    }

    #[test]
    fn test_t2_main_branch() {
        let main_template = crate::main_branch::intel::t2::t2();
        assert_eq!(main_template, t2::t2());
    }

    #[test]
    fn test_t2s_main_branch() {
        let main_template = crate::main_branch::intel::t2s::t2s();
        assert_eq!(main_template, t2s::t2s());
    }

    #[test]
    fn test_t2cl_main_branch() {
        let main_template = crate::main_branch::intel::t2cl::t2cl();
        assert_eq!(main_template, t2cl::t2cl());
    }

    #[test]
    fn test_t2a_main_branch() {
        let main_template = crate::main_branch::amd::t2a::t2a();
        assert_eq!(main_template, t2a::t2a());
    }
}
