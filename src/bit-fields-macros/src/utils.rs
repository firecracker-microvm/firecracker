// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use std::default::Default;
use std::fmt;
use std::str::FromStr;

use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;

/// Type used to ensure safety by avoiding some arithmetic operations.
#[derive(Debug, Clone, Copy)]
pub struct DataTypeToken {
    /// [`DataType`]
    ty: DataType,
    /// [`proc_macro2::Span`]
    span: Span,
}

impl DataTypeToken {
    // When const trait implementations are stabilized this should be
    // `impl const From<DataType> for u8`.
    /// Returns the size in bits of the data type.
    pub const fn size(self) -> u8 {
        self.ty.size()
    }
    /// Returns base data type.
    pub fn base(self) -> TokenStream {
        self.ty.base()
    }
}

/// Error type for [`<DataTypeToken as TryFrom<Ident>>::try_from`].
type DataTypeTokenTryFromError = crate::ProcError<DataTypeTryFromError>;

impl TryFrom<Ident> for DataTypeToken {
    type Error = DataTypeTokenTryFromError;
    fn try_from(ident: Ident) -> Result<Self, Self::Error> {
        match DataType::from_str(&ident.to_string()) {
            Ok(ty) => Ok(Self {
                ty,
                span: ident.span(),
            }),
            Err(err) => Err((ident.span(), err)),
        }
    }
}

impl quote::ToTokens for DataTypeToken {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        tokens.extend(std::iter::once(proc_macro2::TokenTree::Ident(Ident::new(
            &self.ty.to_string(),
            self.span,
        ))));
    }
}

impl Default for DataTypeToken {
    fn default() -> Self {
        Self {
            ty: DataType::default(),
            span: Span::call_site(),
        }
    }
}

/// Type used to ensure safety by avoiding some arithmetic operations.
///
/// Without this type we would parse and store the size of the bit field as a `u8`. The following
/// operations would then use the generic `u8` implementations which the compiler cannot guarantee
/// are safe. By using this enum to restrict the type we can avoid these operations. This is a
/// small point, but helps a little.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataType {
    /// `u8`
    U8,
    /// `u16`
    U16,
    /// `u32`
    U32,
    /// `u64`
    U64,
    /// `u128`
    U128,
}

impl DataType {
    // When const trait implementations are stabilized this should be
    // `impl const From<DataType> for u8`.
    /// Returns the size in bits of the data type.
    pub const fn size(self) -> u8 {
        match self {
            Self::U8 => 8,
            Self::U16 => 16,
            Self::U32 => 32,
            Self::U64 => 64,
            Self::U128 => 128,
        }
    }
    /// Returns base data type.
    pub fn base(self) -> TokenStream {
        match self {
            Self::U8 => quote! { u8 },
            Self::U16 => quote! { u16 },
            Self::U32 => quote! { u32 },
            Self::U64 => quote! { u64 },
            Self::U128 => quote! { u128 },
        }
    }
}

impl Default for DataType {
    fn default() -> Self {
        Self::U8
    }
}

impl fmt::Display for DataType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::U8 => write!(f, "u8"),
            Self::U16 => write!(f, "u16"),
            Self::U32 => write!(f, "u32"),
            Self::U64 => write!(f, "u64"),
            Self::U128 => write!(f, "u128"),
        }
    }
}

impl FromStr for DataType {
    type Err = DataTypeTryFromError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "u8" => Ok(Self::U8),
            "u16" => Ok(Self::U16),
            "u32" => Ok(Self::U32),
            "u64" => Ok(Self::U64),
            "u128" => Ok(Self::U128),
            _ => Err(DataTypeTryFromError),
        }
    }
}

/// Error type for `impl TryFrom<&str> for DataType`
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "Bad backing data type given. Only accepted types are `u8`, `u16`, `u32`, `u64` and `u128`."
)]
pub struct DataTypeTryFromError;

/// Utility used to assembly the display string
#[derive(Debug, Default)]
pub struct MultiLineString(pub Vec<String>);

impl MultiLineString {
    /// Pushes `MultiLineString` on to `self`, if the given `other` is deeper than `self` it will
    /// expand down to accommodate.
    pub fn push(&mut self, other: &Self) {
        // Split `other` into slice to join to `self` and slice to extend `self`.
        let (join, extend) = other.0.split_at(self.0.len());

        // Lines where both `self` and `other` have strings, join them
        let joined = self.0.iter().zip(join).map(|(x, y)| format!("{x}{y}"));

        // Lines `other` extends below `self` add them
        let chained = joined.chain(extend.iter().cloned());

        // Collect into new string
        self.0 = chained.collect();
    }
    /// Pushes a `&str` onto `self`.
    pub fn push_str(&mut self, s: &str) {
        self.push(&MultiLineString::from(s));
    }
}

// Un-fallable `FromStr`.
impl From<&str> for MultiLineString {
    fn from(s: &str) -> Self {
        Self(s.split('\n').map(String::from).collect())
    }
}

impl fmt::Display for MultiLineString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for line in &self.0 {
            writeln!(f, "{line}")?;
        }
        Ok(())
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

    use proc_macro2::{Ident, Span};

    use super::*;

    #[test]
    fn data_type_token_debug() {
        assert_eq!(
            format!(
                "{:?}",
                DataTypeToken {
                    ty: DataType::U8,
                    span: Span::call_site()
                }
            ),
            "DataTypeToken { ty: U8, span: Span }"
        );
        assert_eq!(
            format!(
                "{:?}",
                DataTypeToken {
                    ty: DataType::U16,
                    span: Span::call_site()
                }
            ),
            "DataTypeToken { ty: U16, span: Span }"
        );
        assert_eq!(
            format!(
                "{:?}",
                DataTypeToken {
                    ty: DataType::U32,
                    span: Span::call_site()
                }
            ),
            "DataTypeToken { ty: U32, span: Span }"
        );
        assert_eq!(
            format!(
                "{:?}",
                DataTypeToken {
                    ty: DataType::U64,
                    span: Span::call_site()
                }
            ),
            "DataTypeToken { ty: U64, span: Span }"
        );
        assert_eq!(
            format!(
                "{:?}",
                DataTypeToken {
                    ty: DataType::U128,
                    span: Span::call_site()
                }
            ),
            "DataTypeToken { ty: U128, span: Span }"
        );
    }
    #[test]
    fn data_type_token_try_from_ident() {
        let a = DataTypeToken::try_from(Ident::new("u8", Span::call_site()));
        assert!(matches!(a,Ok(x) if x.ty == DataType::U8));

        let a = DataTypeToken::try_from(Ident::new("u16", Span::call_site()));
        assert!(matches!(a,Ok(x) if x.ty == DataType::U16));

        let a = DataTypeToken::try_from(Ident::new("u32", Span::call_site()));
        assert!(matches!(a,Ok(x) if x.ty == DataType::U32));

        let a = DataTypeToken::try_from(Ident::new("u64", Span::call_site()));
        assert!(matches!(a,Ok(x) if x.ty == DataType::U64));

        let a = DataTypeToken::try_from(Ident::new("u128", Span::call_site()));
        assert!(matches!(a,Ok(x) if x.ty == DataType::U128));

        let a = DataTypeToken::try_from(Ident::new("u256", Span::call_site()));
        assert!(matches!(a, Err((_, DataTypeTryFromError))));
    }

    #[test]
    fn data_type_debug() {
        assert_eq!(format!("{:?}", DataType::U8), "U8");
        assert_eq!(format!("{:?}", DataType::U16), "U16");
        assert_eq!(format!("{:?}", DataType::U32), "U32");
        assert_eq!(format!("{:?}", DataType::U64), "U64");
        assert_eq!(format!("{:?}", DataType::U128), "U128");
    }
    #[test]
    fn data_type_display() {
        assert_eq!(DataType::U8.to_string(), "u8");
        assert_eq!(DataType::U16.to_string(), "u16");
        assert_eq!(DataType::U32.to_string(), "u32");
        assert_eq!(DataType::U64.to_string(), "u64");
        assert_eq!(DataType::U128.to_string(), "u128");
    }
    #[test]
    fn data_type_from_str() {
        assert_eq!(DataType::from_str("u8"), Ok(DataType::U8));
        assert_eq!(DataType::from_str("u16"), Ok(DataType::U16));
        assert_eq!(DataType::from_str("u32"), Ok(DataType::U32));
        assert_eq!(DataType::from_str("u64"), Ok(DataType::U64));
        assert_eq!(DataType::from_str("u128"), Ok(DataType::U128));
        assert_eq!(DataType::from_str("u256"), Err(DataTypeTryFromError));
    }

    #[test]
    fn data_type_try_from_error_debug() {
        assert_eq!(format!("{DataTypeTryFromError:?}"), "DataTypeTryFromError");
    }
    #[test]
    fn data_type_try_from_error_display() {
        assert_eq!(
            DataTypeTryFromError.to_string(),
            "Bad backing data type given. Only accepted types are `u8`, `u16`, `u32`, `u64` and \
             `u128`."
        );
    }

    #[test]
    fn multi_line_string_debug() {
        assert_eq!(
            format!("{:?}", MultiLineString::default()),
            "MultiLineString([])"
        );
    }
    #[test]
    fn multi_line_string_match() {
        let mut mls = MultiLineString(Vec::new());
        mls.push_str("1 4\n2 5\n3 6");
        mls.push_str(" 7 10\n 8 11\n 9 12");
        assert_eq!(mls.to_string(), "1 4 7 10\n2 5 8 11\n3 6 9 12\n");
    }
    #[test]
    fn multi_line_string_mismatch() {
        let mut mls = MultiLineString(Vec::new());
        mls.push_str("1 2 3\n4 5 6");
        mls.push_str(" 7 10\n 8 11\n9 12");
        assert_eq!(mls.to_string(), "1 2 3 7 10\n4 5 6 8 11\n9 12\n");
    }
}
