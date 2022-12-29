// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![warn(clippy::pedantic, clippy::restriction)]
#![allow(
    clippy::blanket_clippy_restriction_lints,
    clippy::implicit_return,
    clippy::pattern_type_mismatch,
    clippy::std_instead_of_alloc,
    clippy::std_instead_of_core,
    clippy::pub_use,
    clippy::non_ascii_literal,
    clippy::single_char_lifetime_names,
    clippy::exhaustive_enums,
    clippy::exhaustive_structs,
    clippy::unseparated_literal_suffix,
    clippy::mod_module_files
)]

//! Procedural macros for the `bit-fields` crate.

use std::convert::TryFrom;

use proc_macro2::{Delimiter, Ident, Span, TokenTree};

/// Utility functions.
mod utils;
use utils::DataTypeToken;

/// Builder struct.
mod builder;
use builder::BitFieldBuilder;

/// Parser struct.
mod parser;

/// Convenience macro for errors in [`bitfield`].
macro_rules! span_error {
    ($span: expr, $msg: expr) => {{
        let x = $msg;
        return (quote::quote_spanned! {
            $span => #x
        })
        .into();
    }};
}

/// Convenience macro for errors in [`bitfield`].
macro_rules! token_error {
    ($token: expr, $msg: expr) => {
        span_error!($token.span(), $msg)
    };
}

/// Convenience macro for errors in [`bitfield`].
macro_rules! callsite_error {
    ($msg:expr) => {
        span_error!(Span::call_site(), $msg)
    };
}

/// Convenience macro for errors in [`bitfield`].
macro_rules! unwrap_or_emit {
    ($res:expr) => {
        match $res {
            Ok(x) => x,
            Err((span, err)) => span_error!(span, err.to_string()),
        }
    };
}

/// Bit struct member
#[derive(Debug)]
pub(crate) enum Member {
    /// Bit field
    BitRange(BitRange),
    /// Bit flag
    BitFlag(BitFlag),
}
/// Bit field.
#[derive(Debug)]
pub(crate) struct BitRange {
    /// Inclusive start of bit field.
    range: std::ops::Range<u8>,
    /// Rustdoc comment.
    rustdoc: String,
    /// Member identifier.
    identifier: Ident,
    /// Skip serialization/deserialization and `From<HashMap>` attribute.
    skip: bool,
}
/// Bit flag.
#[derive(Debug)]
pub(crate) struct BitFlag {
    /// Index of bit flag.
    index: u8,
    /// Rustdoc comment.
    rustdoc: String,
    /// Member identifier.
    identifier: Ident,
    /// Skip serialization/deserialization and `From<HashSet>` attribute.
    skip: bool,
}

/// Procedural macro error type.
type ProcError<T> = (Span, T);

/// Procedural macro to generate bit fields.
///
/// ```ignore
/// use std::mem::size_of;
/// #[rustfmt::skip]
/// bit_fields::bitfield!(GeneratedBitField, u32, {
///     RANGE1: 0..1,
///     SSE: 2,
///     SSE1: 3,
///     RANGE2: 4..6,
///     SSE2: 9,
///     SSE3: 10,
///     RANGE3: 12..15,
///     SSE4: 17
/// });
/// assert_eq!(size_of::<GeneratedBitField>(), size_of::<u32>());
/// let bitfield = GeneratedBitField::from(23548);
/// println!("{}", bitfield);
/// ```
/// Prints:
/// ```test
/// ┌───────┬────────────┬───────┬───────┬────────────┬───────┬───────┬────────────┬───────┐
/// │ Bit/s │     00..01 │    02 │    03 │     04..06 │    09 │    10 │     12..15 │    17 │
/// ├───────┼────────────┼───────┼───────┼────────────┼───────┼───────┼────────────┼───────┤
/// │ Desc  │     RANGE1 │   SSE │  SSE1 │     RANGE2 │  SSE2 │  SSE3 │     RANGE3 │  SSE4 │
/// ├───────┼────────────┼───────┼───────┼────────────┼───────┼───────┼────────────┼───────┤
/// │ Value │          0 │  true │  true │          3 │  true │ false │          5 │ false │
/// └───────┴────────────┴───────┴───────┴────────────┴───────┴───────┴────────────┴───────┘
/// ```
///
/// **Important**: Undefined bits are not preserved on serialization and deserialization.
///
/// # Panics
///
/// When failing to parse values to token streams. This should never occur.
#[proc_macro]
pub fn bitfield(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    /// Errors returned on malformed or missing rustdoc comment.
    const RUSTDOC_ERR: &str = "Expected rustdoc comment";
    /// Description of correct bit field ident.
    const IDENT_ERR: &str = "Expected struct identifier or rustdoc comment";

    /// Separator between struct identifiers and struct data type.
    const IDENT_TYPE_SEPARATOR_ERR: &str = "Expected punctuation comma (',')";

    /// Description of correct bit field type.
    const TYPE_ERR: &str = "Expected type identifier, options: [u8, u16, u32, u64, u128]";

    /// Separator between struct data type and struct members.
    const TYPE_FIELDS_SEPARATOR_ERR: &str = "Expected punctuation comma (',')";

    /// Description of correct bit field array.
    const FIELDS_ERR: &str = "Expected a brace delimited group (`{ ... }`) of identifiers and bit \
                              indexes. The bit indexes must be within the bounds of the given \
                              data type. The identifiers must be unique.";

    let item = proc_macro2::TokenStream::from(input);
    let mut token_stream_iter = item.into_iter();

    // Get struct identifier (e.g. `MyBitField`) and any preceding rustdoc comments.
    let (rustdoc, struct_name) = {
        let mut rustdoc = String::new();
        let struct_name = loop {
            match token_stream_iter.next() {
                // Rustdoc case
                Some(TokenTree::Punct(punct)) if punct.as_char() == '#' => {
                    match token_stream_iter.next() {
                        Some(TokenTree::Group(group))
                            if group.delimiter() == Delimiter::Bracket =>
                        {
                            let group_vec = group.stream().into_iter().collect::<Vec<_>>();
                            #[allow(clippy::cmp_owned)]
                            match group_vec.as_slice() {
                                [TokenTree::Ident(group_ident), TokenTree::Punct(group_punct), TokenTree::Literal(group_lit)]
                                    if group_ident.to_string() == "doc"
                                        && group_punct.as_char() == '=' =>
                                {
                                    // Check for then remove " from start and end of string.
                                    let comment_unenclosed = {
                                        let group_string = group_lit.to_string();
                                        let mut chars = group_string.chars();
                                        if let (Some('"'), Some('"')) =
                                            (chars.next(), chars.next_back())
                                        {
                                            String::from(chars.as_str())
                                        } else {
                                            token_error!(
                                                group_lit,
                                                "Rustdoc comment missing enclosing \" characters."
                                            );
                                        }
                                    };
                                    // Trim space leading spaces.
                                    // E.g. A coment like `/// abcde` will become `" abcde"` and we
                                    // want `abcde`.
                                    let comment_trimmed = comment_unenclosed.trim_start();
                                    // We append to the rustdoc string.
                                    rustdoc.push_str(comment_trimmed);
                                    rustdoc.push(' ');
                                }
                                _ => token_error!(group, RUSTDOC_ERR),
                            }
                        }
                        Some(token) => token_error!(token, RUSTDOC_ERR),
                        None => callsite_error!(RUSTDOC_ERR),
                    }
                }
                // Ident case
                Some(TokenTree::Ident(ident)) => break ident,
                Some(token) => token_error!(token, IDENT_ERR),
                None => callsite_error!(IDENT_ERR),
            }
        };
        (rustdoc, struct_name)
    };

    // Check struct identifier and data type identifier are separated by ','.
    match token_stream_iter.next() {
        Some(TokenTree::Punct(punct)) if punct.as_char() == ',' => (),
        Some(token_tree) => token_error!(token_tree, IDENT_TYPE_SEPARATOR_ERR),
        None => callsite_error!(IDENT_TYPE_SEPARATOR_ERR),
    }
    // Get struct data type identifier token.
    let data_type_ident = match token_stream_iter.next() {
        Some(TokenTree::Ident(ident)) => ident,
        Some(token) => token_error!(token, TYPE_ERR),
        None => callsite_error!(TYPE_ERR),
    };
    // Get struct data type as number of bits and check it is valid when doing this (valid
    // identifiers are `u8`, `u16`, `u32`, `u64` or `u128`).
    let data_type = unwrap_or_emit!(DataTypeToken::try_from(data_type_ident));

    // Check data type identifier and field definitions are separated by ','.
    match token_stream_iter.next() {
        Some(TokenTree::Punct(punct)) if punct.as_char() == ',' => (),
        Some(TokenTree::Punct(punct)) => token_error!(punct, TYPE_FIELDS_SEPARATOR_ERR),
        Some(token_tree) => token_error!(token_tree, TYPE_FIELDS_SEPARATOR_ERR),
        None => callsite_error!(TYPE_FIELDS_SEPARATOR_ERR),
    }

    // Get fields group
    let group = match token_stream_iter.next() {
        Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Brace => group,
        Some(TokenTree::Group(group)) => token_error!(
            group,
            format!(
                "Found group delimiter `{:?}` expected group delimiter `Brace` (`{{ ... }}`)",
                group.delimiter()
            )
        ),
        Some(token_tree) => token_error!(token_tree, FIELDS_ERR),
        None => callsite_error!(FIELDS_ERR),
    };

    // Parses token stream into bit field member iterator.
    let member_tokens = group.stream().into_iter().collect::<Vec<_>>();
    let member_iter = parser::BitFieldMembersParser::from((data_type.size(), member_tokens.iter()));

    // Builds field struct.
    let builder = unwrap_or_emit!(member_iter.into_iter().try_fold(
        BitFieldBuilder::new(rustdoc, struct_name, data_type),
        |builder, member_res| {
            let member = member_res?;
            Ok(builder.add(member))
        }
    ));

    proc_macro::TokenStream::from(builder.compose())
}
