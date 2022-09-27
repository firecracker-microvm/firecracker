// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Do not use this. Use [bit-fields](https://docs.rs/bit-fields).
#![warn(clippy::pedantic, clippy::restriction)]
#![allow(
    clippy::non_ascii_literal,
    clippy::blanket_clippy_restriction_lints,
    clippy::implicit_return,
    clippy::items_after_statements
)]
use std::collections::HashSet;
use std::convert::TryFrom;

use proc_macro2::{Delimiter, TokenTree};
use proc_macro_error::{abort_call_site, Level};

/// Utility functions.
mod utils;
use utils::{DataType, SliceIter};

/// Builder struct.
mod builder;
use builder::BitFieldBuilder;

// TODO Allow writing rustdoc comments on bit field structs
/// Convenience macro for errors in [`bitfield`].
macro_rules! macro_error {
    ($span:expr,$msg:expr) => {{
        proc_macro_error::Diagnostic::spanned($span.span(), Level::Error, $msg.into()).emit();
        return proc_macro::TokenStream::new();
    }};
}

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
#[allow(clippy::too_many_lines)]
#[proc_macro_error::proc_macro_error]
#[proc_macro]
pub fn bitfield(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    /// Description of correct bit field ident.
    const IDENT_ERR: &str = "1st token must be struct identifier";

    /// Separator between struct identifiers and struct data type.
    const IDENT_TYPE_SEPARATOR_ERR: &str = "2nd token must be a punctuation comma (',')";

    /// Description of correct bit field type.
    const TYPE_ERR: &str = "3rd token must be type identifier, options: [u8, u16, u32, u64, u128]";

    /// Separator between struct data type and struct members.
    const TYPE_FIELDS_SEPARATOR_ERR: &str = "4th token must be a punctuation comma (',')";

    /// Description of correct bit field array.
    const FIELDS_ERR: &str = "5th token must be a brace delimited group (`{ ... }`) of \
                              identifiers and bit indexes. The bit indexes must be within the \
                              bounds of the given data type. The identifiers must be unique.";

    let item = proc_macro2::TokenStream::from(input);
    let mut token_stream_iter = item.into_iter();

    // Get struct identifier e.g. `MyBitField`.
    let struct_name = match token_stream_iter.next() {
        Some(TokenTree::Ident(ident)) => ident,
        Some(token) => macro_error!(token, IDENT_ERR),
        #[allow(clippy::panic)]
        None => abort_call_site!("{}", IDENT_ERR),
    };
    // Check struct identifier and data type identifier are separated by ','.
    match token_stream_iter.next() {
        Some(TokenTree::Punct(punct)) if punct.as_char() == ',' => (),
        Some(TokenTree::Punct(punct)) => macro_error!(punct, IDENT_TYPE_SEPARATOR_ERR),
        Some(token_tree) => macro_error!(token_tree, IDENT_TYPE_SEPARATOR_ERR),
        #[allow(clippy::panic)]
        None => abort_call_site!("{}", IDENT_TYPE_SEPARATOR_ERR),
    }
    // Get struct data type identifier token.
    let struct_data_type: proc_macro2::Ident = match token_stream_iter.next() {
        Some(TokenTree::Ident(ident)) => ident,
        Some(token) => macro_error!(token, TYPE_ERR),
        #[allow(clippy::panic)]
        None => abort_call_site!("{}", TYPE_ERR),
    };
    // Get struct data type as number of bits and check it is valid when doing this (valid
    // identifiers are `u8`, `u16`, `u32`, `u64` or `u128`).
    let bits_len = if let Ok(data) = DataType::try_from(struct_data_type.to_string().as_str()) {
        data
    } else {
        macro_error!(struct_data_type, TYPE_ERR)
    };
    // Construct bit field builder.
    let mut bit_field_builder = BitFieldBuilder::new(struct_name, struct_data_type, bits_len);

    // Check data type identifier and field definitions are separated by ','.
    match token_stream_iter.next() {
        Some(TokenTree::Punct(punct)) if punct.as_char() == ',' => (),
        Some(TokenTree::Punct(punct)) => macro_error!(punct, TYPE_FIELDS_SEPARATOR_ERR),
        Some(token_tree) => macro_error!(token_tree, TYPE_FIELDS_SEPARATOR_ERR),
        #[allow(clippy::panic)]
        None => abort_call_site!("{}", TYPE_FIELDS_SEPARATOR_ERR),
    }

    // Get fields group
    let group = match token_stream_iter.next() {
        Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Brace => group,
        Some(TokenTree::Group(group)) => macro_error!(
            group,
            format!(
                "Found group delimiter `{:?}` expected group delimiter `Brace` (`{{ ... }}`)",
                group.delimiter()
            )
        ),
        Some(token_tree) => macro_error!(token_tree, FIELDS_ERR),
        #[allow(clippy::panic)]
        None => abort_call_site!("{}", FIELDS_ERR),
    };

    let fields_stream = group.stream();
    let fields_vec = fields_stream.into_iter().collect::<Vec<_>>();

    // An iterator over slices of the token stream ([0..], [1..], .., [len()-1..]).
    let mut fields_slice_iter = SliceIter::from(fields_vec.as_slice());
    // Hashset of existing flag/field identifiers, we use this to check the same identifier isn't
    // used for multiple members.
    let mut pre_existing = HashSet::new();
    // The rustdoc of the structure.
    let mut rustdoc = String::new();

    /// For field identifier token, checks if it has already been used then returns it as a
    /// `String`.
    macro_rules! check_ident {
        ($x: ident) => {{
            if !pre_existing.insert($x) {
                macro_error!($x, "Identifier already used");
            }
        }};
    }

    /// For bit field indices, checks if they are both within the range of the data type and the
    /// stop is greater than or equal to the start then return them as `u8`s.
    macro_rules! index_field {
        ($start:ident,$stop:ident) => {{
            // Get start, checking if in range of data type.
            let start = match $start.to_string().parse::<u8>() {
                Ok(s) if (0..bits_len.size()).contains(&s) => s,
                Ok(s) => macro_error!(
                    $start,
                    format!(
                        "Start index ({}) outside valid range ({:?}).",
                        s,
                        (0..bits_len.size())
                    )
                ),
                Err(err) => macro_error!(
                    $start,
                    format!("Failed to parse token for start index: {}", err)
                ),
            };
            // Get stop, checking if in range of data type.
            let stop = match $stop.to_string().parse::<u8>() {
                Ok(s) if (start..=bits_len.size()).contains(&s) => s,
                Ok(s) => macro_error!(
                    $stop,
                    format!(
                        "Stop index ({}) outside valid range ({:?}).",
                        s,
                        (start..=bits_len.size())
                    )
                ),
                Err(err) => macro_error!(
                    $stop,
                    format!("Failed to parse token for stop index: {}", err)
                ),
            };
            (start, stop)
        }};
    }
    /// For bit flag index, checks if it is within the range of the data type,
    /// then returns it as a `u8`.
    macro_rules! index_flag {
        ($index:ident) => {{
            // Get index, checking if in range of data type.
            match $index.to_string().parse::<u8>() {
                Ok(s) if (0..bits_len.size()).contains(&s) => s,
                Ok(s) => macro_error!(
                    $index,
                    format!(
                        "Index ({}) outside of valid range ({:?}).",
                        s,
                        (0..bits_len.size())
                    )
                ),
                Err(err) => {
                    macro_error!($index, format!("Failed to parse token for index: {}", err))
                }
            }
        }};
    }
    // Iterate through the token stream, matching slices to:
    // 1. Bit fields.
    // 2. Bit flags.
    // 3. Rustdoc comments.
    // And appending these to the `bit_field_builder`.
    while let Some(field_token_slice) = fields_slice_iter.next() {
        match field_token_slice {
            // Bit field: [ident, punct, literal, punct, punct, literal, punct, ..]
            [TokenTree::Ident(ident), TokenTree::Punct(colon), TokenTree::Literal(start), TokenTree::Punct(d1), TokenTree::Punct(d2), TokenTree::Literal(stop), TokenTree::Punct(comma), ..]
                if colon.as_char() == ':'
                    && d1.as_char() == '.'
                    && d2.as_char() == '.'
                    && comma.as_char() == ',' =>
            {
                check_ident!(ident);
                let (start, stop) = index_field!(start, stop);
                bit_field_builder.add_bit_field(start, &rustdoc, ident, stop);
                rustdoc.clear();
                // Move past this identified slice.
                fields_slice_iter.nth(5);
            }
            // Bit field: [ident, punct, literal, punct, punct, literal, ..]
            [TokenTree::Ident(ident), TokenTree::Punct(colon), TokenTree::Literal(start), TokenTree::Punct(d1), TokenTree::Punct(d2), TokenTree::Literal(stop), ..]
                if colon.as_char() == ':' && d1.as_char() == '.' && d2.as_char() == '.' =>
            {
                check_ident!(ident);
                let (start, stop) = index_field!(start, stop);
                bit_field_builder.add_bit_field(start, &rustdoc, ident, stop);
                rustdoc.clear();
                // Move past this identified slice.
                fields_slice_iter.nth(4);
            }
            // Bit flag: [ ident, punct, literal, punct, .. ]
            [TokenTree::Ident(ident), TokenTree::Punct(colon), TokenTree::Literal(index), TokenTree::Punct(comma), ..]
                if colon.as_char() == ':' && comma.as_char() == ',' =>
            {
                check_ident!(ident);
                let index = index_flag!(index);
                bit_field_builder.add_bit_flag(index, &rustdoc, ident);
                rustdoc.clear();
                // Move past this identified slice.
                fields_slice_iter.nth(2);
            }
            // Bit flag: [ ident, punct, literal, .. ]
            [TokenTree::Ident(ident), TokenTree::Punct(colon), TokenTree::Literal(index), ..]
                if colon.as_char() == ':' =>
            {
                check_ident!(ident);
                let index = index_flag!(index);
                bit_field_builder.add_bit_flag(index, &rustdoc, ident);
                rustdoc.clear();
                // Move past this identified slice.
                fields_slice_iter.nth(1);
            }
            // Rustdoc comment: [ punct, group, .. ]
            [TokenTree::Punct(punct), TokenTree::Group(doc_group), ..]
                if punct.as_char() == '#' && doc_group.delimiter() == Delimiter::Bracket =>
            {
                let rustdoc_vec = doc_group.stream().into_iter().collect::<Vec<_>>();
                // From `#[doc="some comment"]` we are getting `"some comment"`
                let doc_comment = match &*rustdoc_vec {
                    [TokenTree::Ident(group_ident), TokenTree::Punct(group_punct), TokenTree::Literal(group_lit)]
                        if *group_ident == "doc" && group_punct.as_char() == '=' =>
                    {
                        group_lit
                    }
                    _ => macro_error!(doc_group, "Malformed rustdoc comment"),
                };
                // Check and remove " from start and end of string.
                let comment_unenclosed = {
                    let comment_str = doc_comment.to_string();
                    let mut chars = comment_str.chars();
                    if let (Some('"'), Some('"')) = (chars.next(), chars.next_back()) {
                        String::from(chars.as_str())
                    } else {
                        macro_error!(
                            doc_comment,
                            "rustdoc comment missing enclosing \" characters"
                        );
                    }
                };
                // Trim space off front e.g. `/// abcde` becomes `" abcde"` and we want `abcde`.
                let comment_trimmed = comment_unenclosed.trim_start();
                // We append to the rustdoc string until we hit a bit flag or field which will then
                // use it and then clear it.
                rustdoc.push_str(comment_trimmed);
                rustdoc.push(' ');
                // Move past this identified slice.
                fields_slice_iter.next();
            }
            _ => macro_error!(
                group,
                format!(
                    "Badly defined members: {:?}",
                    field_token_slice
                        .iter()
                        .map(std::string::ToString::to_string)
                        .collect::<Vec<_>>()
                )
            ),
        }
    }
    bit_field_builder.end();
    bit_field_builder.compose()
}
