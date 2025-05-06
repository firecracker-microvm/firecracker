// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! A tool to add, remove and check for `tracing::instrument` in large projects where it is
//! infeasible to manually add it to thousands of functions.

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use syn::spanned::Spanned;
use syn::visit::Visit;
use walkdir::WalkDir;

/// The command line arguments for the application.
#[derive(Parser)]
struct CommandLineArgs {
    /// The action to take.
    #[arg(long)]
    action: Action,
    /// The path to look in.
    #[arg(long)]
    path: Option<PathBuf>,
    /// When adding instrumentation use a custom suffix e.g.
    /// `--suffix my::custom::suffix::`.
    ///
    /// The tool may be unable to strip instrumentation with an invalid suffix.
    #[arg(long)]
    suffix: Option<String>,
    /// Whether to add a `cfg_attr` condition e.g.
    /// `#[cfg_attr(feature = "tracing", log_instrument::instrument)]` vs
    /// `#[log_instrument::instrument]`.
    #[arg(long)]
    cfg_attr: Option<String>,
    /// Sub-paths which contain any of the strings from this list will be ignored.
    #[arg(long, value_delimiter = ',')]
    exclude: Vec<String>,
}

/// The action to take.
#[derive(Clone, ValueEnum)]
enum Action {
    /// Checks `tracing::instrument` is on all functions.
    Check,
    /// Adds `tracing::instrument` to all functions.
    Fix,
    /// Removes `tracing::instrument` from all functions.
    Strip,
}

/// A list of text lines split so that newlines can be efficiently inserted between them.
struct SegmentedList {
    /// The first new line.
    first: String,
    /// The inner vector used to contain the original lines `.0` and the new lines `.1`.
    inner: Vec<(String, String)>,
}
impl SegmentedList {
    /// Sets the text line before `line` to `text`.
    fn set_before(&mut self, line: usize, text: String) -> bool {
        let s = if let Some(i) = line.checked_sub(1) {
            let Some(mut_ref) = self.inner.get_mut(i) else {
                return false;
            };
            &mut mut_ref.1
        } else {
            &mut self.first
        };
        *s = text;
        true
    }
}
impl From<SegmentedList> for String {
    fn from(list: SegmentedList) -> String {
        let iter = list
            .inner
            .into_iter()
            .map(|(x, y)| format!("{x}{}{y}", if y.is_empty() { "" } else { "\n" }));
        format!(
            "{}{}{}",
            list.first,
            if list.first.is_empty() { "" } else { "\n" },
            itertools::intersperse(iter, String::from("\n")).collect::<String>()
        )
    }
}

/// Visitor for the `strip` action.
struct StripVisitor(HashMap<usize, String>);
impl From<StripVisitor> for String {
    fn from(visitor: StripVisitor) -> String {
        let mut vec = visitor.0.into_iter().collect::<Vec<_>>();
        vec.sort_by_key(|(i, _)| *i);
        itertools::intersperse(vec.into_iter().map(|(_, x)| x), String::from("\n"))
            .collect::<String>()
    }
}

macro_rules! create_strip_visitor_function {
    ($func_name:ident, $item:ident) => {
        fn $func_name(&mut self, i: &syn::$item) {
            if let Some(instrument) = find_instrumented(&i.attrs) {
                let start = instrument.span().start().line - 1;
                let end = instrument.span().end().line;
                for line in start..end {
                    self.0.remove(&line);
                }
            }
            self.visit_block(&i.block);
        }
    };
}

impl syn::visit::Visit<'_> for StripVisitor {
    create_strip_visitor_function!(visit_impl_item_fn, ImplItemFn);
    create_strip_visitor_function!(visit_item_fn, ItemFn);
}

/// Visitor for the `check` action.
struct CheckVisitor(Option<proc_macro2::Span>);

macro_rules! create_check_visitor_function {
    ($func_name:ident, $item:ident) => {
        fn $func_name(&mut self, i: &syn::$item) {
            let attr = check_attributes(&i.attrs);
            if !attr.instrumented && !attr.test && i.sig.constness.is_none() {
                self.0 = Some(i.span());
            } else {
                self.visit_block(&i.block);
            }
        }
    };
}

impl syn::visit::Visit<'_> for CheckVisitor {
    create_check_visitor_function!(visit_impl_item_fn, ImplItemFn);
    create_check_visitor_function!(visit_item_fn, ItemFn);
}

/// Visitor for the `fix` action.
struct FixVisitor<'a> {
    /// A custom path suffix.
    suffix: &'a Option<String>,
    /// A `cfg_attr` condition.
    cfg_attr: &'a Option<String>,
    /// Source
    list: SegmentedList,
}
impl From<FixVisitor<'_>> for String {
    fn from(visitor: FixVisitor) -> String {
        String::from(visitor.list)
    }
}

macro_rules! create_fix_visitor_function {
    ($func_name:ident, $item:ident) => {
        fn $func_name(&mut self, i: &syn::$item) {
            let attr = check_attributes(&i.attrs);

            if !attr.instrumented && !attr.test && i.sig.constness.is_none() {
                let line = i.span().start().line;

                let attr_string = instrument(&i.sig, self.suffix, self.cfg_attr);
                let indent = i.span().start().column;
                let indent_attr = format!("{}{attr_string}", " ".repeat(indent));
                self.list.set_before(line - 1, indent_attr);
            }
            self.visit_block(&i.block);
        }
    };
}

impl syn::visit::Visit<'_> for FixVisitor<'_> {
    create_fix_visitor_function!(visit_impl_item_fn, ImplItemFn);
    create_fix_visitor_function!(visit_item_fn, ItemFn);
}

fn instrument(sig: &syn::Signature, suffix: &Option<String>, cfg_attr: &Option<String>) -> String {
    let instr = inner_instrument(sig, suffix);
    if let Some(cfg_attr) = cfg_attr {
        format!("#[cfg_attr({cfg_attr}, {instr})]")
    } else {
        format!("#[{instr}]")
    }
}

/// Returns the instrument macro for a given function signature.
fn inner_instrument(_sig: &syn::Signature, suffix: &Option<String>) -> String {
    format!(
        "{}instrument",
        suffix.as_ref().map_or("log_instrument::", String::as_str)
    )
}

/// Type to return from `main` to support returning an error then handling it.
#[repr(u8)]
enum Exit {
    /// Process completed successfully.
    Ok = 0,
    /// Process encountered an error.
    Error = 1,
    /// Process ran `check` action and found missing instrumentation.
    Check = 2,
}
#[allow(clippy::as_conversions)]
impl std::process::Termination for Exit {
    fn report(self) -> ExitCode {
        ExitCode::from(self as u8)
    }
}

fn main() -> Exit {
    match exec() {
        Err(err) => {
            eprintln!("Error: {err}");
            Exit::Error
        }
        Ok(None) => Exit::Ok,
        Ok(Some((path, line, column))) => {
            println!(
                "Missing instrumentation at {}:{line}:{column}.",
                path.display()
            );
            Exit::Check
        }
    }
}

/// Error for [`exec`].
#[derive(Debug)]
enum ExecError {
    /// Failed to read entry in file path.
    Entry(walkdir::Error),
    /// Failed to parse file path to string.
    String,
    /// Failed to open file.
    File(std::io::Error),
    /// Failed to run apply function.
    Apply(ApplyError),
}
impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Entry(entry) => write!(f, "Failed to read entry in file path: {entry}"),
            Self::String => write!(f, "Failed to parse file path to string."),
            Self::File(file) => write!(f, "Failed to open file: {file}"),
            Self::Apply(apply) => write!(f, "Failed to run apply function: {apply}"),
        }
    }
}

impl Error for ExecError {}

/// Wraps functionality from `main` to support returning an error then handling it.
fn exec() -> Result<Option<(PathBuf, usize, usize)>, ExecError> {
    let args = CommandLineArgs::parse();

    let path = args.path.unwrap_or(PathBuf::from("."));
    for entry_res in WalkDir::new(path).follow_links(true) {
        let entry = entry_res.map_err(ExecError::Entry)?;
        let entry_path = entry.into_path();

        let path_str = entry_path.to_str().ok_or(ExecError::String)?;
        // File paths must not contain any excluded strings.
        let no_excluded_strings = !args.exclude.iter().any(|e| path_str.contains(e));
        // The file must not be a `build.rs` file.
        let not_build_file = !entry_path.ends_with("build.rs");
        // The file must be a `.rs` file.
        let is_rs_file = entry_path.extension().is_some_and(|ext| ext == "rs");

        if no_excluded_strings && not_build_file && is_rs_file {
            let file = OpenOptions::new()
                .read(true)
                .open(&entry_path)
                .map_err(ExecError::File)?;
            let res = apply(&args.action, &args.suffix, &args.cfg_attr, file, |_| {
                OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .open(&entry_path)
            })
            .map_err(ExecError::Apply)?;

            if let Some(span) = res {
                return Ok(Some((entry_path, span.start().line, span.start().column)));
            }
        }
    }
    Ok(None)
}

/// Error for [`apply`].
#[derive(Debug)]
enum ApplyError {
    /// Failed to read file.
    Read(std::io::Error),
    /// Failed to parse file to utf8.
    Utf(core::str::Utf8Error),
    /// Failed to parse file to syn ast.
    Syn(syn::parse::Error),
    /// Failed to get write target.
    Target(std::io::Error),
    /// Failed to write result to target.
    Write(std::io::Error),
}
impl fmt::Display for ApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(read) => write!(f, "Failed to read file: {read}"),
            Self::Utf(utf) => write!(f, "Failed to parse file to utf8: {utf}"),
            Self::Syn(syn) => write!(f, "Failed to parse file to syn ast: {syn}"),
            Self::Target(target) => write!(f, "Failed to get write target: {target}"),
            Self::Write(write) => write!(f, "Failed to write result to target: {write}"),
        }
    }
}

impl Error for ApplyError {}

/// Apply the given action to the given source and outputs the result to the target produced by the
/// given closure.
fn apply<R: Read, W: Write>(
    action: &Action,
    suffix: &Option<String>,
    cfg_attr: &Option<String>,
    mut source: R,
    target: impl Fn(R) -> Result<W, std::io::Error>,
) -> Result<Option<proc_macro2::Span>, ApplyError> {
    let mut buf = Vec::new();
    source.read_to_end(&mut buf).map_err(ApplyError::Read)?;
    let text = core::str::from_utf8(&buf).map_err(ApplyError::Utf)?;

    let ast = syn::parse_file(text).map_err(ApplyError::Syn)?;

    match action {
        Action::Strip => {
            let mut visitor = StripVisitor(
                text.split('\n')
                    .enumerate()
                    .map(|(i, x)| (i, String::from(x)))
                    .collect(),
            );
            visitor.visit_file(&ast);
            let out = String::from(visitor);
            target(source)
                .map_err(ApplyError::Target)?
                .write_all(out.as_bytes())
                .map_err(ApplyError::Write)?;
            Ok(None)
        }
        Action::Check => {
            let mut visitor = CheckVisitor(None);
            visitor.visit_file(&ast);
            Ok(visitor.0)
        }
        Action::Fix => {
            let mut visitor = FixVisitor {
                suffix,
                cfg_attr,
                list: SegmentedList {
                    first: String::new(),
                    inner: text
                        .split('\n')
                        .map(|x| (String::from(x), String::new()))
                        .collect(),
                },
            };
            visitor.visit_file(&ast);
            let out = String::from(visitor);
            target(source)
                .map_err(ApplyError::Target)?
                .write_all(out.as_bytes())
                .map_err(ApplyError::Write)?;
            Ok(None)
        }
    }
}

/// Finds the `#[instrument]` attribute on a function.
fn find_instrumented(attrs: &[syn::Attribute]) -> Option<&syn::Attribute> {
    attrs.iter().find(|a| is_instrumented(a).is_some())
}

/// Checks if a `syn::Attribute` is `#[instrument]`.
fn is_instrumented(attr: &syn::Attribute) -> Option<&syn::Attribute> {
    match &attr.meta {
        syn::Meta::List(syn::MetaList { path, tokens, .. }) => {
            // `#[instrument]`
            let instrumented = matches!(path.segments.last(), Some(syn::PathSegment { ident, .. }) if ident == "instrument");
            // `#[cfg_attr(.. , instrument)]`
            let attr_instrumented = matches!(path.segments.last(), Some(syn::PathSegment { ident, .. }) if ident == "cfg_attr") && tokens.clone().into_iter().any(|token| matches!(token, proc_macro2::TokenTree::Ident(ident) if ident == "instrument"));

            (instrumented || attr_instrumented).then_some(attr)
        }
        syn::Meta::Path(syn::Path { segments, .. }) => {
            let x = matches!(segments.last(), Some(syn::PathSegment { ident, .. }) if ident == "instrument");
            x.then_some(attr)
        }
        syn::Meta::NameValue(_) => None,
    }
}

/// The description of attributes on a function signature we care about.
struct Desc {
    /// Does the function have the `#[tracing::instrument]` attribute macro?
    instrumented: bool,
    /// Does the function have the `#[test]` attribute macro?
    test: bool,
}

// A function is considered instrumented if it has the `#[instrument]` attribute or the `#[test]`
// attribute.
/// Returns a tuple where the 1st element is whether `tracing::instrument` is found in the list of
/// attributes and the 2nd is whether `clippy_tracing_attributes::skip` is found in the list of
/// attributes.
fn check_attributes(attrs: &[syn::Attribute]) -> Desc {
    let mut instrumented = false;
    let mut test = false;

    for attr in attrs {
        // Match `#[instrument]` and `#[cfg_attr(.., instrument)]`.
        if is_instrumented(attr).is_some() {
            instrumented = true;
        }

        // Match `#[test]` or `#[kani::proof]`.
        if match &attr.meta {
            syn::Meta::List(syn::MetaList { path, .. }) => {
                matches!(path.segments.last(), Some(syn::PathSegment { ident, .. }) if ident == "proof")
            }
            syn::Meta::Path(syn::Path { segments, .. }) => {
                matches!(segments.last(), Some(syn::PathSegment { ident, .. }) if ident == "test" || ident == "proof")
            }
            syn::Meta::NameValue(_) => false,
        } {
            test = true;
        }
    }
    Desc { instrumented, test }
}
