// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::collections::HashMap;
use std::ops::Range;

use proc_macro2::{Delimiter, Ident, Literal, Span, TokenTree};

use crate::{BitFlag, BitRange, Member};

/// Parses a slice of tokens into an iterator of bit field members.
pub(crate) struct BitFieldMembersParser<'a> {
    /// Token slice iterator.
    iter: std::slice::Iter<'a, TokenTree>,
    /// Hashmap of used identifiers, where `None` represents a bit flag and `Some(_)` represents a
    /// bit range.
    existing: HashMap<String, Option<Range<u8>>>,
    /// Rustdoc.
    rustdoc: String,
    /// Number of bits in data type, e.g. `size_of::<data_type>() * 8`.
    size: u8,
    /// Error flag we set when encountering an error.
    error: bool,
    /// Skip attribute flag, indicating the next member should be skipped on serialization and
    /// deserialization.
    skip: bool,
    /// Members which are present in the conversion to/from sets of flags and maps of fields cannot
    /// have overlapping bits as this leads to undefined behavior in as the value of the bit field
    /// would depend on the ordering of keys in a `HashMap` and/or `HashSet` (which is
    /// inconsistent). Thus this case would enable the same data to produce to bit fields of
    /// different values.
    non_skipped_bits: Vec<bool>,
}
impl<'a> From<(u8, std::slice::Iter<'a, TokenTree>)> for BitFieldMembersParser<'a> {
    fn from((size, iter): (u8, std::slice::Iter<'a, TokenTree>)) -> Self {
        Self {
            iter,
            existing: HashMap::new(),
            rustdoc: String::new(),
            size,
            error: false,
            skip: false,
            non_skipped_bits: vec![false; usize::from(size)],
        }
    }
}

/// Error type for [`<BitFieldMembersParser<'_> as std::iter::Iterator>::next`].
#[derive(Debug, thiserror::Error)]
pub(crate) enum BitFieldMembersParserIterError {
    /// Identifier already used.
    #[error("Identifier already used.")]
    DuplicateIdentifier,
    /// Failed to get field index.
    #[error("Failed to get field indices: {0}")]
    IndexField(IndexFieldError),
    /// Failed to get flag index.
    #[error("Failed to get flag index: {0}")]
    IndexFlag(IndexFlagError),
    /// Unknown attribute supplied on member.
    #[error(
        "Unknown attribute supplied on member. Supported attributes are `#[skip]` and \
         `#[doc=\"..\"]`."
    )]
    UnknownAttribute,
    /// Rustdoc comment missing enclosing " characters.
    #[error("Rustdoc comment missing enclosing \" characters.")]
    RustdocUnenclosed,
    /// Badly defined members.
    #[error("Badly defined members: {0:?}.")]
    BadlyDefinedMembers(Vec<String>),
    /// Expected commma
    #[error("Expected commma.")]
    ExpectedComma,
    /// Cannot define member as indexing into bit range, as bit range does not exist.
    #[error(
        "Cannot define member on bit range, as bit range does not exist. Bit ranges need to be \
         defined before members which reference them."
    )]
    IndexingMissingRange,
    /// Cannt define member as indexing into bit flag, as you cannot index a bit flag.
    #[error("Cannt define member as indexing into bit flag, as you cannot index a bit flag.")]
    IndexingBitFlag,
    /// Malformed bit range index.
    #[error("Malformed bit range index.")]
    IndexingMalformed,
    /// Members which are present in the conversion to/from sets of flags and maps of fields cannot
    /// have overlapping bits as this leads to undefined behavior in as the value of the bit field
    /// would depend on the ordering of keys in a `HashMap` and/or `HashSet` (which is
    /// inconsistent). Thus this case would enable the same data to produce to bit fields of
    /// different values.
    #[error(
        "Members which are present in the conversion to/from sets of flags and maps of fields \
         cannot have overlapping bits as this leads to undefined behavior in as the value of the \
         bit field would depend on the ordering of keys in a `HashMap` and/or `HashSet` (which is \
         inconsistent). Thus this case would enable the same data to produce to bit fields of \
         different values."
    )]
    OverlappingNonSkipped,
}

/// Advantces parser iterator expecting `base+1`th token to be `None` or a comma.
fn advance_iter<'a>(
    iter: &mut std::slice::Iter<'a, TokenTree>,
    tail: &[TokenTree],
    base: usize,
) -> Result<(), crate::ProcError<BitFieldMembersParserIterError>> {
    // Move past this identified slice.
    iter.nth(base);
    // Match comma
    #[allow(clippy::pattern_type_mismatch)]
    match tail.first() {
        // If no tailing comma, we also we expect this to be end
        None => Ok(()),
        // If tailing comma
        Some(TokenTree::Punct(comma)) if comma.as_char() == ',' => {
            // Advance over comma
            iter.next();
            Ok(())
        }
        // Else if not end and next token is not comma
        Some(token) => Err((token.span(), BitFieldMembersParserIterError::ExpectedComma)),
    }
}

impl std::iter::Iterator for BitFieldMembersParser<'_> {
    type Item = Result<Member, crate::ProcError<BitFieldMembersParserIterError>>;
    #[allow(clippy::too_many_lines)]
    fn next(&mut self) -> Option<Self::Item> {
        // After the iterator yields `Some(Err(_))` it always yields `None`.
        if self.error {
            return None;
        }
        // This loop is required to collect rustdoc comments
        loop {
            #[allow(clippy::pattern_type_mismatch, clippy::cmp_owned)]
            match self.iter.as_slice() {
                // Bit reference range: [ident, punct, ident, group [ literal, punct, punct, literal
                // ], punct, ..] e.g. "see2: sse[0..2],"
                [TokenTree::Ident(ident), TokenTree::Punct(colon), TokenTree::Ident(parent_bit_range), TokenTree::Group(group), end @ ..]
                    if colon.as_char() == ':' && group.delimiter() == Delimiter::Bracket =>
                {
                    // Move past this identified slice.
                    if let Err(err) = advance_iter(&mut self.iter, end, 3) {
                        self.error = true;
                        return Some(Err(err));
                    }

                    let vec = group.stream().into_iter().collect::<Vec<_>>();
                    // Checks if parent key exists in the map
                    let parent_bit_range_range =
                        match self.existing.get(&parent_bit_range.to_string()) {
                            Some(Some(some)) => some.clone(),
                            Some(None) => {
                                self.error = true;
                                return Some(Err((
                                    group.span(),
                                    BitFieldMembersParserIterError::IndexingBitFlag,
                                )));
                            }
                            None => {
                                self.error = true;
                                return Some(Err((
                                    group.span(),
                                    BitFieldMembersParserIterError::IndexingMissingRange,
                                )));
                            }
                        };

                    return match vec.as_slice() {
                        // Bit flag: [literal]
                        [TokenTree::Literal(index_token)] => {
                            // Check bit index
                            match check_bit_flag(
                                &mut self.existing,
                                ident,
                                index_token,
                                parent_bit_range_range.clone(),
                                parent_bit_range_range.start,
                                self.skip,
                                &mut self.non_skipped_bits,
                            ) {
                                // Get return type
                                Ok(index) => Some(Ok(Member::BitFlag(BitFlag {
                                    index,
                                    rustdoc: self.rustdoc.drain(..).collect(),
                                    identifier: ident.clone(),
                                    // Set `self.skip` to `false` returning the previous value.
                                    skip: std::mem::replace(&mut self.skip, false),
                                }))),
                                Err(err) => {
                                    self.error = true;
                                    Some(Err(err))
                                }
                            }
                        }
                        // Bit range: [literal, punct, punct, literal]
                        [TokenTree::Literal(start_token), TokenTree::Punct(d1), TokenTree::Punct(d2), TokenTree::Literal(stop_token)]
                            if d1.as_char() == '.' && d2.as_char() == '.' =>
                        {
                            // Checks bit range.
                            match check_bit_range(
                                &mut self.existing,
                                ident,
                                start_token,
                                stop_token,
                                parent_bit_range_range.clone(),
                                parent_bit_range_range.start,
                                self.skip,
                                &mut self.non_skipped_bits,
                            ) {
                                // Get return type
                                Ok(range) => Some(Ok(Member::BitRange(BitRange {
                                    range,
                                    rustdoc: self.rustdoc.drain(..).collect(),
                                    identifier: ident.clone(),
                                    // Set `self.skip` to `false` returning the previous value.
                                    skip: std::mem::replace(&mut self.skip, false),
                                }))),
                                Err(err) => {
                                    self.error = true;
                                    Some(Err(err))
                                }
                            }
                        }
                        _ => {
                            self.error = true;
                            return Some(Err((
                                group.span(),
                                BitFieldMembersParserIterError::IndexingMalformed,
                            )));
                        }
                    };
                }
                // Bit range: [ident, punct, literal, punct, punct, literal] e.g. "sse2: 0..2"
                [TokenTree::Ident(ident), TokenTree::Punct(colon), TokenTree::Literal(start_token), TokenTree::Punct(d1), TokenTree::Punct(d2), TokenTree::Literal(stop_token), end @ ..]
                    if colon.as_char() == ':' && d1.as_char() == '.' && d2.as_char() == '.' =>
                {
                    // Move past this identified slice.
                    if let Err(err) = advance_iter(&mut self.iter, end, 5) {
                        self.error = true;
                        return Some(Err(err));
                    }

                    return match add_bit_range(
                        &mut self.existing,
                        ident,
                        start_token,
                        stop_token,
                        self.rustdoc.drain(..).collect(),
                        0..self.size,
                        // Set `self.skip` to `false` returning the previous value.
                        std::mem::replace(&mut self.skip, false),
                        &mut self.non_skipped_bits,
                    ) {
                        Ok(member) => Some(Ok(member)),
                        Err(err) => {
                            self.error = true;
                            Some(Err(err))
                        }
                    };
                }
                // Bit flag: [ ident, punct, literal] e.g. "sse2: 0"
                [TokenTree::Ident(ident), TokenTree::Punct(colon), TokenTree::Literal(index_token), end @ ..]
                    if colon.as_char() == ':' =>
                {
                    // Move past this identified slice.
                    if let Err(err) = advance_iter(&mut self.iter, end, 2) {
                        self.error = true;
                        return Some(Err(err));
                    }

                    return match add_bit_flag(
                        &mut self.existing,
                        ident,
                        index_token,
                        self.rustdoc.drain(..).collect(),
                        0..self.size,
                        // Set `self.skip` to `false` returning the previous value.
                        std::mem::replace(&mut self.skip, false),
                        &mut self.non_skipped_bits,
                    ) {
                        Ok(member) => Some(Ok(member)),
                        Err(err) => {
                            self.error = true;
                            Some(Err(err))
                        }
                    };
                }
                // [ punct, group, .. ] e.g. `#[skip]` or `#[doc=".."]`
                [TokenTree::Punct(punct), TokenTree::Group(group), ..]
                    if punct.as_char() == '#' && group.delimiter() == Delimiter::Bracket =>
                {
                    // Move past this identified slice.
                    self.iter.nth(1);

                    let group_vec = group.stream().into_iter().collect::<Vec<_>>();

                    match group_vec.as_slice() {
                        // Skip attribute e.g. `#[skip]`
                        [TokenTree::Ident(skip_ident)] if skip_ident.to_string() == "skip" => {
                            self.skip = true;
                        }
                        // Rustdoc e.g. `#[doc=".."]`
                        [TokenTree::Ident(group_ident), TokenTree::Punct(group_punct), TokenTree::Literal(group_lit)]
                            if group_ident.to_string() == "doc" && group_punct.as_char() == '=' =>
                        {
                            // Check for then remove " from start and end of string.
                            let comment_unenclosed = {
                                let group_string = group_lit.to_string();
                                let mut chars = group_string.chars();
                                if let (Some('"'), Some('"')) = (chars.next(), chars.next_back()) {
                                    String::from(chars.as_str())
                                } else {
                                    self.error = true;
                                    return Some(Err((
                                        group_lit.span(),
                                        BitFieldMembersParserIterError::RustdocUnenclosed,
                                    )));
                                }
                            };
                            // Trim space leading spaces.
                            // E.g. A coment like `/// abcde` will become `" abcde"` and we want
                            // `abcde`.
                            let comment_trimmed = comment_unenclosed.trim_start();
                            // We append to the rustdoc string. When we hit a bit flag or field, we
                            // use the rustdoc string for this flag or
                            // field, then empty the rustdoc string.
                            self.rustdoc.push_str(comment_trimmed);
                            self.rustdoc.push(' ');
                        }
                        _ => {
                            self.error = true;
                            return Some(Err((
                                group.span(),
                                BitFieldMembersParserIterError::UnknownAttribute,
                            )));
                        }
                    }
                }
                // On an exhausted iterator return none.
                [] => return None,
                // https://doc.rust-lang.org/proc_macro/struct.Span.html#method.join is curretly
                // unstable, but when it is stablized we should collect and join spans of remaining
                // element for this error message.
                _ => {
                    self.error = true;
                    return Some(Err((
                        Span::call_site(),
                        BitFieldMembersParserIterError::BadlyDefinedMembers(
                            self.iter
                                .clone()
                                .map(std::string::ToString::to_string)
                                .collect::<Vec<_>>(),
                        ),
                    )));
                }
            }
        }
    }
}
/// Create bit range member.
#[allow(clippy::too_many_arguments)]
fn add_bit_range(
    existing: &mut HashMap<String, Option<Range<u8>>>,
    ident: &Ident,
    start_token: &Literal,
    stop_token: &Literal,
    rustdoc: String,
    valid_range: Range<u8>,
    skip: bool,
    non_skipped_bits: &mut [bool],
) -> Result<Member, crate::ProcError<BitFieldMembersParserIterError>> {
    // Checks bit range.
    let range = check_bit_range(
        existing,
        ident,
        start_token,
        stop_token,
        valid_range,
        0,
        skip,
        non_skipped_bits,
    )?;
    // Get return type
    let member = Member::BitRange(BitRange {
        range,
        rustdoc,
        identifier: ident.clone(),
        skip,
    });
    Ok(member)
}
/// Create bit flag member.
fn add_bit_flag(
    existing: &mut HashMap<String, Option<Range<u8>>>,
    ident: &Ident,
    index_token: &Literal,
    rustdoc: String,
    valid_range: Range<u8>,
    skip: bool,
    non_skipped_bits: &mut [bool],
) -> Result<Member, crate::ProcError<BitFieldMembersParserIterError>> {
    // Checks bit flag.
    let index = check_bit_flag(
        existing,
        ident,
        index_token,
        valid_range,
        0,
        skip,
        non_skipped_bits,
    )?;
    // Get return type
    let member = Member::BitFlag(BitFlag {
        index,
        rustdoc,
        identifier: ident.clone(),
        skip,
    });
    Ok(member)
}

/// Check if identifer not used and index valid.
fn check_bit_flag(
    existing: &mut HashMap<String, Option<Range<u8>>>,
    ident: &Ident,
    index_token: &Literal,
    valid_range: Range<u8>,
    offset: u8,
    skip: bool,
    non_skipped_bits: &mut [bool],
) -> Result<u8, crate::ProcError<BitFieldMembersParserIterError>> {
    // Check index
    let index = index_flag(index_token, valid_range, offset)
        .map_err(|(span, err)| (span, BitFieldMembersParserIterError::IndexFlag(err)))?;

    // Check indentifier not already used.
    check_ident(existing, ident, None)?;

    // Checks that if this member is non-skipped it does not overlap with another non-skipped
    // member.
    // Also updates `non_skipped_bits[index]` to be true if this member is non-skipped.
    //
    // `non_skipped_bits` is initialized to a length of atleast `valid_range.end`.
    #[allow(clippy::indexing_slicing)]
    let old = std::mem::replace(&mut non_skipped_bits[usize::from(index)], !skip);
    // If the bits where already used in a non-skipped member and this member is non-skipped.
    if old && !skip {
        return Err((
            index_token.span(),
            BitFieldMembersParserIterError::OverlappingNonSkipped,
        ));
    }

    Ok(index)
}

/// Checks if identifier not used and indices valid.
#[allow(clippy::too_many_arguments)]
fn check_bit_range(
    existing: &mut HashMap<String, Option<Range<u8>>>,
    ident: &Ident,
    start_token: &Literal,
    stop_token: &Literal,
    valid_range: Range<u8>,
    offset: u8,
    skip: bool,
    non_skipped_bits: &mut [bool],
) -> Result<Range<u8>, crate::ProcError<BitFieldMembersParserIterError>> {
    // Check indices
    let bit_range_range = index_field(start_token, stop_token, valid_range, offset)
        .map_err(|(span, err)| (span, BitFieldMembersParserIterError::IndexField(err)))?;

    // Check indentifier not already used.
    check_ident(existing, ident, Some(bit_range_range.clone()))?;

    // `non_skipped_bits` is initialized to a length of atleast `valid_range.end`.
    #[allow(clippy::indexing_slicing)]
    for bit in
        &mut non_skipped_bits[usize::from(bit_range_range.start)..usize::from(bit_range_range.end)]
    {
        if *bit && !skip {
            // Join the spans of `start_token` and `start_token` when span joining is stabilized.
            return Err((
                start_token.span(),
                BitFieldMembersParserIterError::OverlappingNonSkipped,
            ));
        }
        *bit = !skip;
    }

    Ok(bit_range_range)
}

/// Check indentifier not already used.
fn check_ident(
    existing: &mut HashMap<String, Option<Range<u8>>>,
    ident: &Ident,
    range: Option<Range<u8>>,
) -> Result<(), (Span, BitFieldMembersParserIterError)> {
    if existing.insert(ident.to_string(), range).is_some() {
        Err((
            ident.span(),
            BitFieldMembersParserIterError::DuplicateIdentifier,
        ))
    } else {
        Ok(())
    }
}

/// Error type for [`index_field`].
#[derive(Debug, thiserror::Error)]
pub(crate) enum IndexFieldError {
    /// Failed to parse token for start index.
    #[error("Failed to parse token for start index: {0}")]
    ParseStart(std::num::ParseIntError),
    /// Start index outside of valid range.
    #[error("Start index ({start}) outside of valid range ({valid_range:?}).")]
    InvalidStart {
        /// Parsed start index.
        start: u8,
        /// Valid range that `start` lies outside of.
        valid_range: Range<u8>,
    },
    /// Failed to parse token for stop index.
    #[error("Failed to parse token for stop index: {0}")]
    ParseStop(std::num::ParseIntError),
    /// Stop index outside of valid range.
    #[error("Stop index ({stop}) outside of valid range ({valid_range:?}).")]
    InvalidStop {
        /// Parsed stop index.
        stop: u8,
        /// Valid range that `stop` lies outside of.
        valid_range: std::ops::RangeInclusive<u8>,
    },
}

/// For bit field indices, checks if they are both within the range of the data type and the stop is
/// greater than or equal to the start then returns them as `u8`s.
#[allow(clippy::integer_arithmetic, clippy::arithmetic_side_effects)]
fn index_field(
    start_token: &Literal,
    stop_token: &Literal,
    valid_range: Range<u8>,
    offset: u8,
) -> Result<Range<u8>, crate::ProcError<IndexFieldError>> {
    // Get start, checking if in range of data type.
    let start = match start_token.to_string().parse::<u8>() {
        Ok(s) if valid_range.contains(&(s + offset)) => Ok(s + offset),
        Ok(s) => Err((
            start_token.span(),
            IndexFieldError::InvalidStart {
                start: s,
                valid_range: valid_range.clone(),
            },
        )),
        Err(err) => Err((start_token.span(), IndexFieldError::ParseStart(err))),
    }?;
    // Get stop, checking if in range of data type.
    let stop = match stop_token.to_string().parse::<u8>() {
        Ok(s) if (start..=valid_range.end).contains(&(s + offset)) => Ok(s + offset),
        Ok(s) => Err((
            stop_token.span(),
            IndexFieldError::InvalidStop {
                stop: s,
                valid_range: start..=valid_range.end,
            },
        )),
        Err(err) => Err((stop_token.span(), IndexFieldError::ParseStop(err))),
    }?;

    Ok(start..stop)
}

/// Error type for [`index_field`].
#[derive(Debug, thiserror::Error)]
pub(crate) enum IndexFlagError {
    /// Failed to parse token for index.
    #[error("Failed to parse token for index: {0}")]
    Parse(std::num::ParseIntError),
    /// Index outside of valid range.
    #[error("Index ({index}) outside valid range ({valid_range:?}).")]
    Invalid {
        /// Parsed index.
        index: u8,
        /// Valid range that `index` lies outside of.
        valid_range: Range<u8>,
    },
}

/// For  abit flag index, checks if it is within the range of the data type, then returns it as a
/// `u8`.
#[allow(clippy::integer_arithmetic, clippy::arithmetic_side_effects)]
fn index_flag(
    index: &Literal,
    valid_range: Range<u8>,
    offset: u8,
) -> Result<u8, crate::ProcError<IndexFlagError>> {
    // Get index, checking if in range of data type.
    match index.to_string().parse::<u8>() {
        Ok(s) if valid_range.contains(&(s + offset)) => Ok(s + offset),
        Ok(s) => Err((
            index.span(),
            IndexFlagError::Invalid {
                index: s,
                valid_range,
            },
        )),
        Err(err) => Err((index.span(), IndexFlagError::Parse(err))),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        non_snake_case,
        clippy::dbg_macro,
        clippy::unwrap_used,
        clippy::as_conversions,
        clippy::shadow_unrelated
    )]

    use proc_macro2::{Group, Ident, Literal, Punct, Spacing, TokenTree};

    use super::*;

    // Construct an ident with a given string.
    fn ident(s: &str) -> Ident {
        Ident::new(s, Span::call_site())
    }
    fn punct(c: char) -> Punct {
        Punct::new(c, Spacing::Alone)
    }
    fn rustdoc(s: &str) -> [TokenTree; 2] {
        [
            TokenTree::Punct(punct('#')),
            TokenTree::Group(Group::new(Delimiter::Bracket, quote::quote! { doc=#s })),
        ]
    }
    fn field(name: &str, start: u8, stop: u8) -> [TokenTree; 6] {
        [
            TokenTree::Ident(ident(name)),
            TokenTree::Punct(punct(':')),
            TokenTree::Literal(Literal::u8_unsuffixed(start)),
            TokenTree::Punct(punct('.')),
            TokenTree::Punct(punct('.')),
            TokenTree::Literal(Literal::u8_unsuffixed(stop)),
        ]
    }
    fn field_comma(name: &str, start: u8, stop: u8) -> [TokenTree; 7] {
        [
            TokenTree::Ident(ident(name)),
            TokenTree::Punct(punct(':')),
            TokenTree::Literal(Literal::u8_unsuffixed(start)),
            TokenTree::Punct(punct('.')),
            TokenTree::Punct(punct('.')),
            TokenTree::Literal(Literal::u8_unsuffixed(stop)),
            TokenTree::Punct(punct(',')),
        ]
    }
    fn flag(name: &str, index: u8) -> [TokenTree; 3] {
        [
            TokenTree::Ident(ident(name)),
            TokenTree::Punct(punct(':')),
            TokenTree::Literal(Literal::u8_unsuffixed(index)),
        ]
    }
    fn flag_comma(name: &str, index: u8) -> [TokenTree; 4] {
        [
            TokenTree::Ident(ident(name)),
            TokenTree::Punct(punct(':')),
            TokenTree::Literal(Literal::u8_unsuffixed(index)),
            TokenTree::Punct(punct(',')),
        ]
    }

    #[test]
    fn bit_field_members_parser_empty() {
        let tokens = &[];
        let mut parser = BitFieldMembersParser::from((8, tokens.iter()));
        assert!(matches!(parser.next(), None));
    }
    #[test]
    fn bit_field_members_parser_field() {
        let tokens = &field("field", 0, 1);
        let mut parser = BitFieldMembersParser::from((8, tokens.iter()));
        assert!(
            matches!(parser.next(),Some(Ok(Member::BitRange(BitRange { range: Range { start: 0, end: 1 }, rustdoc, identifier: ident, skip: false }))) if rustdoc.is_empty() && ident == "field")
        );
        assert!(matches!(parser.next(), None));
    }
    #[test]
    fn bit_field_members_parser_field_comma() {
        let tokens = &field_comma("field", 0, 1);
        let mut parser = BitFieldMembersParser::from((8, tokens.iter()));
        assert!(
            matches!(parser.next(),Some(Ok(Member::BitRange(BitRange { range: Range { start: 0, end: 1 }, rustdoc, identifier: ident, skip: false }))) if rustdoc.is_empty() && ident == "field")
        );
        assert!(matches!(parser.next(), None));
    }
    #[test]
    fn bit_field_members_parser_field_no_comma() {
        let tokens = &[field("field1", 0, 1), field("field2", 1, 2)].concat();
        let mut parser = BitFieldMembersParser::from((8, tokens.iter()));
        assert!(matches!(
            parser.next(),
            Some(Err((_, BitFieldMembersParserIterError::ExpectedComma)))
        ));
        assert!(matches!(parser.next(), None));
    }
    #[test]
    fn bit_field_members_parser_flag_duplicate() {
        let tokens = &[
            field_comma("field", 0, 1).as_slice(),
            field("field", 1, 2).as_slice(),
        ]
        .concat();
        let mut parser = BitFieldMembersParser::from((8, tokens.iter()));
        assert!(
            matches!(parser.next(),Some(Ok(Member::BitRange(BitRange { range: Range { start: 0, end: 1 }, rustdoc, identifier: ident, skip: false }))) if rustdoc.is_empty() && ident == "field")
        );
        assert!(matches!(
            parser.next(),
            Some(Err((
                _,
                BitFieldMembersParserIterError::DuplicateIdentifier
            )))
        ));
        assert!(matches!(parser.next(), None));
    }
    #[test]
    fn bit_field_members_parser_flag_comma_duplicate() {
        let tokens = &[field_comma("field", 0, 1), field_comma("field", 1, 2)].concat();
        let mut parser = BitFieldMembersParser::from((8, tokens.iter()));
        assert!(
            matches!(parser.next(),Some(Ok(Member::BitRange(BitRange { range: Range { start: 0, end: 1 }, rustdoc, identifier: ident, skip: false }))) if rustdoc.is_empty() && ident == "field")
        );
        assert!(matches!(
            parser.next(),
            Some(Err((
                _,
                BitFieldMembersParserIterError::DuplicateIdentifier
            )))
        ));
        dbg!(parser.next());
        assert!(matches!(parser.next(), None));
    }
    #[test]
    fn bit_field_members_parser_field_seperating_comma() {
        let tokens = &[
            field_comma("field1", 0, 1).as_slice(),
            field("field2", 1, 2).as_slice(),
        ]
        .concat();
        let mut parser = BitFieldMembersParser::from((8, tokens.iter()));
        assert!(
            matches!(parser.next(),Some(Ok(Member::BitRange(BitRange { range: Range { start: 0, end: 1 }, rustdoc, identifier: ident, skip: false }))) if rustdoc.is_empty() && ident == "field1")
        );
        assert!(
            matches!(parser.next(),Some(Ok(Member::BitRange(BitRange { range: Range { start: 1, end: 2 }, rustdoc, identifier: ident, skip: false }))) if rustdoc.is_empty() && ident == "field2")
        );
        assert!(matches!(parser.next(), None));
    }
    #[test]
    fn bit_field_members_parser_field_rustdoc() {
        let tokens = &[
            rustdoc("some docs").as_slice(),
            field("field", 0, 1).as_slice(),
        ]
        .concat();
        let mut parser = BitFieldMembersParser::from((8, tokens.iter()));
        assert!(
            matches!(parser.next(),Some(Ok(Member::BitRange(BitRange { range: Range { start: 0, end: 1 }, rustdoc, identifier: ident, skip: false }))) if rustdoc == "some docs " && ident == "field")
        );
        assert!(matches!(parser.next(), None));
    }

    #[test]
    fn bit_field_members_parser_flag() {
        let tokens = &flag("flag", 0);
        let mut parser = BitFieldMembersParser::from((8, tokens.iter()));
        assert!(
            matches!(parser.next(),Some(Ok(Member::BitFlag(BitFlag { index: 0, rustdoc, identifier: ident, skip: false }))) if rustdoc.is_empty() && ident == "flag")
        );
        assert!(matches!(parser.next(), None));
    }
    #[test]
    fn bit_field_members_parser_flag_comma() {
        let tokens = &flag_comma("flag", 0);
        let mut parser = BitFieldMembersParser::from((8, tokens.iter()));
        assert!(
            matches!(parser.next(),Some(Ok(Member::BitFlag(BitFlag { index: 0, rustdoc, identifier: ident, skip: false }))) if rustdoc.is_empty() && ident == "flag")
        );
        assert!(matches!(parser.next(), None));
    }
    #[test]
    fn bit_field_members_parser_flag_no_comma() {
        let tokens = &[flag("flag1", 0), flag("flag2", 1)].concat();
        let mut parser = BitFieldMembersParser::from((8, tokens.iter()));
        assert!(matches!(
            parser.next(),
            Some(Err((_, BitFieldMembersParserIterError::ExpectedComma)))
        ));
        assert!(matches!(parser.next(), None));
    }
    #[test]
    fn bit_field_members_parser_flag_seperating_comma() {
        let tokens = &[
            flag_comma("flag1", 0).as_slice(),
            flag("flag2", 1).as_slice(),
        ]
        .concat();
        let mut parser = BitFieldMembersParser::from((8, tokens.iter()));
        assert!(
            matches!(parser.next(),Some(Ok(Member::BitFlag(BitFlag { index: 0, rustdoc, identifier: ident, skip: false }))) if rustdoc.is_empty() && ident == "flag1")
        );
        assert!(
            matches!(parser.next(),Some(Ok(Member::BitFlag(BitFlag { index: 1, rustdoc, identifier: ident, skip: false }))) if rustdoc.is_empty() && ident == "flag2")
        );
        assert!(matches!(parser.next(), None));
    }
    #[test]
    fn bit_field_members_parser_flag_rustdoc() {
        let tokens = &[rustdoc("some docs").as_slice(), flag("flag", 0).as_slice()].concat();
        let mut parser = BitFieldMembersParser::from((8, tokens.iter()));
        assert!(
            matches!(parser.next(),Some(Ok(Member::BitFlag(BitFlag { index: 0, rustdoc, identifier: ident, skip: false }))) if rustdoc == "some docs " && ident == "flag")
        );
        assert!(matches!(parser.next(), None));
    }

    #[test]
    fn bit_field_members_parser_mixed() {
        let tokens = &[
            rustdoc("some docs").as_slice(),
            flag_comma("flag1", 0).as_slice(),
            rustdoc("some more docs").as_slice(),
            field_comma("field1", 1, 2).as_slice(),
            flag_comma("flag2", 3).as_slice(),
            rustdoc("some extra docs").as_slice(),
            field_comma("field2", 4, 5).as_slice(),
        ]
        .concat();
        let mut parser = BitFieldMembersParser::from((8, tokens.iter()));
        assert!(
            matches!(parser.next(),Some(Ok(Member::BitFlag(BitFlag { index: 0, rustdoc, identifier: ident, skip: false }))) if rustdoc == "some docs " && ident == "flag1")
        );
        assert!(
            matches!(parser.next(),Some(Ok(Member::BitRange(BitRange { range: Range { start: 1, end: 2, }, rustdoc, identifier: ident, skip: false }))) if rustdoc == "some more docs " && ident == "field1")
        );
        assert!(
            matches!(parser.next(),Some(Ok(Member::BitFlag(BitFlag { index: 3, rustdoc, identifier: ident, skip: false }))) if rustdoc.is_empty() && ident == "flag2")
        );
        assert!(
            matches!(parser.next(),Some(Ok(Member::BitRange(BitRange { range: Range { start: 4, end: 5, }, rustdoc, identifier: ident, skip: false }))) if rustdoc == "some extra docs " && ident == "field2")
        );
        assert!(matches!(parser.next(), None));
    }

    #[test]
    fn index_field_suffixed() {
        let res = index_field(&Literal::u8_suffixed(0), &Literal::u8_suffixed(4), 0..8, 0);
        dbg!(&res);
        assert!(matches!(res, Err((_, IndexFieldError::ParseStart(_)))));

        let res = index_field(
            &Literal::u8_unsuffixed(0),
            &Literal::u8_suffixed(4),
            0..8,
            0,
        );
        dbg!(&res);
        assert!(matches!(res, Err((_, IndexFieldError::ParseStop(_)))));
    }
    #[test]
    fn index_field_unsuffixed() {
        let res = index_field(
            &Literal::u8_unsuffixed(0),
            &Literal::u8_unsuffixed(4),
            0..8,
            0,
        );
        dbg!(&res);
        assert!(matches!(res, Ok(Range { start: 0, end: 4 })));
    }

    #[test]
    fn index_field_start_outside() {
        let res = index_field(
            &Literal::u8_unsuffixed(8),
            &Literal::u8_unsuffixed(4),
            0..8,
            0,
        );
        dbg!(&res);
        assert!(
            matches!(res,Err((_,IndexFieldError::InvalidStart { start: 8, valid_range })) if (valid_range == (0..8)))
        );
    }
    #[test]
    fn index_field_stop_outside() {
        let res = index_field(
            &Literal::u8_unsuffixed(0),
            &Literal::u8_unsuffixed(9),
            0..8,
            0,
        );
        dbg!(&res);
        assert!(
            matches!(res,Err((_,IndexFieldError::InvalidStop { stop: 9, valid_range })) if (valid_range == (0..=8)) )
        );
    }
    #[test]
    fn index_field_stop_before() {
        let res = index_field(
            &Literal::u8_unsuffixed(4),
            &Literal::u8_unsuffixed(3),
            0..8,
            0,
        );
        dbg!(&res);
        assert!(
            matches!(res,Err((_,IndexFieldError::InvalidStop{ stop: 3, valid_range } )) if (valid_range == (4..=8)))
        );
    }
    #[test]
    fn index_flag_suffixed() {
        let res = index_flag(&Literal::u8_suffixed(4), 0..8, 0);
        dbg!(&res);
        assert!(matches!(res, Err((_, IndexFlagError::Parse(_)))));
    }
    #[test]
    fn index_flag_unsuffixed() {
        let res = index_flag(&Literal::u8_unsuffixed(4), 0..8, 0);
        dbg!(&res);
        assert!(matches!(res, Ok(4)));
    }
    #[test]
    fn index_flag_outside() {
        let res = index_flag(&Literal::u8_unsuffixed(8), 0..8, 0);
        dbg!(&res);
        assert!(
            matches!(res,Err((_,IndexFlagError::Invalid { index: 8, valid_range })) if (valid_range == (0..8)))
        );
    }
}
