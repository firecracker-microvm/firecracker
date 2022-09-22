// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::fmt::Write;

use quote::quote;

use crate::utils::{DataType, MultiLineString};

/// Builder for bit fields.
#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub struct BitFieldBuilder {
    /// String used to define `From<HashSet<String>>`.
    #[cfg(feature = "flag_set")]
    flag_matching_from_hashset: proc_macro2::TokenStream,
    /// String used to define `From<HashSet<String>>`.
    #[cfg(feature = "flag_set")]
    flag_setting_hashset: proc_macro2::TokenStream,
    /// String used to define `From<HashMap<String,$data_type>>`.
    #[cfg(feature = "field_map")]
    field_matching_from_hashmap: proc_macro2::TokenStream,
    /// String used to define `From<HashMap<String,$data_type>>`.
    #[cfg(feature = "field_map")]
    field_setting_hashmap: proc_macro2::TokenStream,
    /// String used to define `superset()`.
    #[cfg(feature = "set_theory")]
    fields_superset_fn: proc_macro2::TokenStream,
    /// String used to define `subset()`.
    #[cfg(feature = "set_theory")]
    fields_subset_fn: proc_macro2::TokenStream,
    /// String used to define `disjoint()`.
    #[cfg(feature = "set_theory")]
    fields_disjoint_fn: proc_macro2::TokenStream,
    /// String used to define `intersection()`.
    #[cfg(feature = "set_theory")]
    fields_intersection_fn: proc_macro2::TokenStream,
    /// String used to define `union()`.
    #[cfg(feature = "set_theory")]
    fields_union_fn: proc_macro2::TokenStream,
    /// String used to define the table used in the rustdoc for the bit field.
    struct_doc_table_layout: String,
    /// String used to define members of the bit field.
    struct_member_fields: proc_macro2::TokenStream,
    /// String used to define `new()` for the bit field.
    struct_member_fields_initialization: proc_macro2::TokenStream,
    /// String used to form the display the bit field, the lines represent:
    /// 1. Top border
    /// 2. Bit numbers
    /// 3. Border
    /// 4. Field idents
    /// 5. Border
    /// 6. Field values
    /// 7. Bottom border
    /// Fmt values (since write doesn't work with in place ones)
    display_string: MultiLineString,
    /// String used to pass arguments for `std::fmt::Display` implementation.
    display_fmt_string: proc_macro2::TokenStream,
    /// Struct data type (e.g. `u8`)
    data_type: DataType,
    /// Struct data type token (e.g. `u8`)
    struct_data_type: proc_macro2::Ident,
    /// Struct identifier
    struct_name: proc_macro2::Ident,
}

impl BitFieldBuilder {
    /// Constructs new `BitFieldBuilder`.
    pub fn new(
        struct_name: proc_macro2::Ident,
        struct_data_type: proc_macro2::Ident,
        data_type: DataType,
    ) -> Self {
        Self {
            #[cfg(feature = "flag_set")]
            flag_matching_from_hashset: proc_macro2::TokenStream::new(),
            #[cfg(feature = "flag_set")]
            flag_setting_hashset: proc_macro2::TokenStream::new(),
            #[cfg(feature = "field_map")]
            field_matching_from_hashmap: proc_macro2::TokenStream::new(),
            #[cfg(feature = "field_map")]
            field_setting_hashmap: proc_macro2::TokenStream::new(),
            #[cfg(feature = "set_theory")]
            fields_superset_fn: quote! { true },
            #[cfg(feature = "set_theory")]
            fields_subset_fn: quote! { true },
            #[cfg(feature = "set_theory")]
            fields_disjoint_fn: quote! { false },
            #[cfg(feature = "set_theory")]
            fields_intersection_fn: proc_macro2::TokenStream::new(),
            #[cfg(feature = "set_theory")]
            fields_union_fn: proc_macro2::TokenStream::new(),
            struct_doc_table_layout: String::from(
                "///     <tr><th>Bit/s</th><th>Identifier</th><th>Description</th></tr>\n",
            ),
            struct_member_fields: proc_macro2::TokenStream::new(),
            struct_member_fields_initialization: proc_macro2::TokenStream::new(),
            #[rustfmt::skip]
            display_string: MultiLineString::from("\
                ┌───────\n\
                │ \x1b[1mBit/s\x1b[0m \n\
                ├───────\n\
                │ \x1b[1mDesc\x1b[0m  \n\
                ├───────\n\
                │ \x1b[1mValue\x1b[0m \n\
                └───────",
            ),
            display_fmt_string: proc_macro2::TokenStream::new(),
            data_type,
            struct_data_type,
            struct_name,
        }
    }

    /// Adds a bit field to the structure.
    #[allow(clippy::integer_arithmetic)]
    pub fn add_bit_field(&mut self, start: u8, rustdoc: &str, ident: &proc_macro2::Ident, end: u8) {
        let identifier = ident.to_string();
        let data_type = &self.struct_data_type;

        // Display
        // ------------------------
        // Use first 10 characters of identifier.
        let cropped = identifier.chars().take(10).collect::<String>();
        #[rustfmt::skip]
        self.display_string.push_str(&format!("\
            ┬─────────────\n\
            │\x20     {:02}..{:02} \n\
            ┼─────────────\n\
            │\x20 {:>10} \n\
            ┼─────────────\n\
            │\x20{{:>11}} \n\
            ┴─────────────\
            ",
            start,
            end,
            cropped,
        ));
        self.display_fmt_string.extend(quote! {
            self.#ident.to_string(),
        });
        // Struct member
        // ------------------------
        self.struct_member_fields.extend(quote! {
            #[doc=#rustdoc]
            pub #ident: bit_fields::BitRange<#data_type,#start,#end>,
        });
        // field_map
        // ------------------------
        #[cfg(feature = "field_map")]
        {
            self.field_matching_from_hashmap.extend(quote! {
                #identifier => {
                    base.#ident.checked_assign(value)?;
                }
            });
            self.field_setting_hashmap.extend(quote! {
                map.insert(String::from(#identifier),#data_type::from(&bit_field.#ident));
            });
        }
        // Struct rustdoc table
        // ------------------------
        // We use `writeln!` here over `proc_macro2::TokenStream::extend()` given
        // <https://docs.rs/quote/latest/quote/macro.quote.html#interpolating-text-inside-of-doc-comments>
        writeln!(
            &mut self.struct_doc_table_layout,
            "///     <tr><td>{:02}..{:02}</td><td>{}</td><td>{}</td></tr>",
            start,
            // Due to the earlier check on `end <= start` we can guarantee
            // `end > start >= 0`, thus `end >= 1` thus `end - 1 >=0` thus this
            // will never panic.
            end,
            identifier,
            rustdoc
        )
        .expect("Failed to write");
        // Struct `new()`
        // ------------------------
        self.struct_member_fields_initialization.extend(quote! {
            #ident: bit_fields::BitRange::new(),
        });
    }
    /// Adds a bit flag to the structure.
    #[allow(clippy::too_many_lines)]
    pub fn add_bit_flag(&mut self, index: u8, rustdoc: &str, ident: &proc_macro2::Ident) {
        let identifier = ident.to_string();
        let data_type = &self.struct_data_type;

        // Display
        // ------------------------
        // Use first 4 characters of the identifier.
        let cropped = identifier.chars().take(4).collect::<String>();
        #[rustfmt::skip]
        self.display_string.push_str(&format!("\
            ┬───────\n\
            │\x20   {:02} \n\
            ┼───────\n\
            │\x20{:>5} \n\
            ┼───────\n\
            │\x20{{:>5}} \n\
            ┴───────\
            ",
            index,cropped
        ));
        self.display_fmt_string.extend(quote! {
            self.#ident.to_string(),
        });
        // Struct member
        // ------------------------
        self.struct_member_fields.extend(quote! {
            #[doc=#rustdoc]
            pub #ident: bit_fields::Bit<#data_type,#index>,
        });
        // Struct rustdoc table
        // ------------------------
        // We use `writeln!` here over `proc_macro2::TokenStream::extend()` given
        // <https://docs.rs/quote/latest/quote/macro.quote.html#interpolating-text-inside-of-doc-comments>
        writeln!(
            &mut self.struct_doc_table_layout,
            "///     <tr><td>{:02}</td><td>{}</td><td>{}</td></tr>",
            index, identifier, rustdoc
        )
        .expect("Failed to write");
        // Struct `new()`
        // ------------------------
        self.struct_member_fields_initialization.extend(quote! {
            #ident: bit_fields::Bit::new(),
        });
        // flag_set
        // ------------------------
        #[cfg(feature = "flag_set")]
        {
            self.flag_matching_from_hashset.extend(quote! {
                #identifier => {
                    base.#ident.on();
                },
            });
            self.flag_setting_hashset.extend(quote! {
                if bit_field.#ident == true {
                    set.insert(String::from(#identifier));
                }
            });
        }
        // set_theory
        // ------------------------
        #[cfg(feature = "set_theory")]
        {
            // Superset
            self.fields_superset_fn.extend(quote! {
                && if other.#ident == true {
                    bool::from(&self.#ident)
                } else {
                    true
                }
            });
            // Subset
            self.fields_subset_fn.extend(quote! {
                && if self.#ident == true {
                    bool::from(&other.#ident)
                } else {
                    true
                }
            });
            // Disjoint
            self.fields_disjoint_fn.extend(quote! {
                || !(self.#ident == other.#ident)
            });
            // Intersection
            self.fields_intersection_fn.extend(quote! {
                if self.#ident == true && other.#ident == true {
                    base.#ident.on();
                }
            });
            // Union
            self.fields_union_fn.extend(quote! {
                if self.#ident == true || other.#ident == true {
                    base.#ident.on();
                }
            });
        }
    }

    /// Ends the bit field, completing the display string.
    pub fn end(&mut self) {
        #[rustfmt::skip]
            self.display_string.push_str("\
                ┐\n\
                │\n\
                ┤\n\
                │\n\
                ┤\n\
                │\n\
                ┘\n\
            ");
    }

    /// Composes `self` into `proc_macro::TokenStream`.
    #[allow(clippy::expect_used, clippy::too_many_lines)]
    pub fn compose(self) -> proc_macro::TokenStream {
        // Convert to token streams
        #[cfg(feature = "flag_set")]
        let (flag_setting_hashset, flag_matching_from_hashset) =
            (self.flag_setting_hashset, self.flag_matching_from_hashset);
        #[cfg(feature = "field_map")]
        let (field_matching_from_hashmap, field_setting_hashmap) =
            (self.field_matching_from_hashmap, self.field_setting_hashmap);
        #[cfg(feature = "set_theory")]
        let (
            fields_superset_fn,
            fields_subset_fn,
            fields_disjoint_fn,
            fields_intersection_fn,
            fields_union_fn,
        ) = (
            self.fields_superset_fn,
            self.fields_subset_fn,
            self.fields_disjoint_fn,
            self.fields_intersection_fn,
            self.fields_union_fn,
        );
        #[cfg(feature = "display")]
        let display_fmt_string = self.display_fmt_string;
        let struct_doc_table_layout: proc_macro2::TokenStream = self
            .struct_doc_table_layout
            .parse()
            .expect("Failed to parse");
        let (struct_member_fields, struct_member_fields_initialization) = (
            self.struct_member_fields,
            self.struct_member_fields_initialization,
        );

        let struct_name = self.struct_name;
        let struct_data_type = self.struct_data_type;

        #[cfg(feature = "serde")]
        let visitor = quote::format_ident!("{}Visitor", struct_name);

        #[cfg(feature = "serde")]
        let serde = quote! {
            impl serde::Serialize for #struct_name {
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where
                    S: serde::Serializer,
                {
                    use serde::ser::{Serialize, SerializeMap, SerializeSeq, SerializeTuple, Serializer};
                    let (set, map): (std::collections::HashSet<String>, std::collections::HashMap<String, #struct_data_type>) = self.into();
                    let mut tup = serializer.serialize_tuple(2)?;
                    tup.serialize_element(&set)?;
                    tup.serialize_element(&map)?;
                    tup.end()
                }
            }
            struct #visitor;
            impl<'de> serde::de::Visitor<'de> for #visitor {
                type Value = #struct_name;
                fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    write!(
                        formatter,
                        "a set of feature flags followed by a map of fields"
                    )
                }
                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: serde::de::SeqAccess<'de>,
                {
                    use std::convert::TryFrom;
                    if let Some(set) = seq.next_element::<std::collections::HashSet<String>>()? {
                        if let Some(map) = seq.next_element::<std::collections::HashMap<String, #struct_data_type>>()? {
                            Ok(#struct_name::try_from((set, map)).expect("Failed to deserialize #struct_name"))
                        } else {
                            Err(serde::de::Error::custom("no 2nd value in seq"))
                        }
                    } else {
                        Err(serde::de::Error::custom("no 1st value in seq"))
                    }
                }
            }
            impl<'de> serde::Deserialize<'de> for #struct_name {
                fn deserialize<D>(deserializer: D) -> Result<#struct_name, D::Error>
                where
                    D: serde::Deserializer<'de>,
                {
                    deserializer.deserialize_tuple(2,#visitor)
                }
            }
        };
        #[cfg(not(feature = "serde"))]
        let serde = proc_macro2::TokenStream::new();

        #[cfg(feature = "set_theory")]
        let set_theory = quote!(
            /// Returns `true` if `self` is a [`superset`](https://en.wikipedia.org/wiki/Subset) of `other`.
            pub fn superset(&self, other: &Self) -> bool {
                #fields_superset_fn
            }
            /// Returns `true` if `self` is a [`subset`](https://en.wikipedia.org/wiki/Subset) of `other`.
            pub fn subset(&self, other: &Self) -> bool {
                #fields_subset_fn
            }
            /// Returns `true` if `self` and `other` are [`disjoint sets`](https://en.wikipedia.org/wiki/Disjoint_sets).
            pub fn disjoint(&self, other: &Self) -> bool {
                #fields_disjoint_fn
            }
            /// Returns the [`intersection`](https://en.wikipedia.org/wiki/Intersection_(set_theory)) of `self` and `other`.
            pub fn intersection(&self, other: &Self) -> Self {
                let mut base = Self::from(0);
                #fields_intersection_fn
                base
            }
            /// Returns the [`union`](https://en.wikipedia.org/wiki/Union_(set_theory)) of `self` and `other`.
            pub fn union(&self, other: &Self) -> Self {
                let mut base = Self::from(0);
                #fields_union_fn
                base
            }
        );
        #[cfg(not(feature = "set_theory"))]
        let set_theory = proc_macro2::TokenStream::new();

        #[cfg(feature = "bit_index")]
        let bit_indices = (0..self.data_type.size())
            .map(|i| {
                // We do this to put `30` instead of `30u8` in the following quote segment.
                let temp: proc_macro2::TokenStream =
                    i.to_string().parse().expect("Failed to parse `bit_index`.");
                quote! {
                    impl bit_fields::BitIndex<#struct_data_type,#temp> for #struct_name {
                        fn bit(&self) -> &bit_fields::Bit<#struct_data_type,#temp> {
                            &self.bits.#temp
                        }
                    }
                    impl bit_fields::BitIndexMut<#struct_data_type,#temp> for #struct_name {
                        fn bit_mut(&mut self) -> &mut bit_fields::Bit<#struct_data_type,#temp> {
                            &mut self.bits.#temp
                        }
                    }
                }
            })
            .collect::<proc_macro2::TokenStream>();

        #[cfg(feature = "bit_index")]
        let (index_fn, bit_index) = {
            (
                quote! {
                    /// Returns a reference to the `N`th bit.
                    pub fn bit<const N: u8>(&self) -> &bit_fields::Bit<#struct_data_type,N>
                    where
                        Self: bit_fields::BitIndex<#struct_data_type,N>,
                    {
                        <Self as bit_fields::BitIndex<#struct_data_type,N>>::bit(self)
                    }
                    /// Returns a mutable reference to the `N`th bit.
                    pub fn bit_mut<const N: u8>(&mut self) -> &mut bit_fields::Bit<#struct_data_type,N>
                    where
                        Self: bit_fields::BitIndexMut<#struct_data_type,N>,
                    {
                        <Self as bit_fields::BitIndexMut<#struct_data_type,N>>::bit_mut(self)
                    }
                },
                bit_indices,
            )
        };
        #[cfg(not(feature = "bit_index"))]
        let (index_fn, bit_index) = {
            (
                proc_macro2::TokenStream::new(),
                proc_macro2::TokenStream::new(),
            )
        };

        // `flag_set` offers:
        // - Constructing a bit field from a set of feature flags
        // - Constructing a set of feature flags from a reference to the bit field
        #[cfg(feature = "flag_set")]
        let flag_set = quote! {
            impl<T:std::fmt::Display> std::convert::TryFrom<std::collections::HashSet<T>> for #struct_name {
                type Error = bit_fields::TryFromFlagSetError;
                fn try_from(set: std::collections::HashSet<T>) -> Result<Self,Self::Error> {
                    let mut base = Self::from(0);
                    for key in set.into_iter() {
                        match key.to_string().as_str() {
                            #flag_matching_from_hashset
                            _ => return Err(bit_fields::TryFromFlagSetError)
                        }
                    }
                    Ok(base)
                }
            }
            impl std::convert::From<&#struct_name> for std::collections::HashSet<String> {
                fn from(bit_field: &#struct_name) -> Self {
                    let mut set = Self::new();
                    #flag_setting_hashset
                    set
                }
            }
        };
        #[cfg(not(feature = "flag_set"))]
        let flag_set = proc_macro2::TokenStream::new();

        // `field_map` offers:
        // - Constructing a bit field from a map of fields
        // - Constructing a map of fields from a reference to the bit field
        #[cfg(feature = "field_map")]
        let field_map = quote! {
            impl<T:std::fmt::Display> std::convert::TryFrom<std::collections::HashMap<T,#struct_data_type>> for #struct_name {
                type Error = bit_fields::TryFromFieldMapError;
                fn try_from(set: std::collections::HashMap<T,#struct_data_type>) -> Result<Self,Self::Error> {
                    let mut base = Self::from(0);
                    for (key,value) in set.into_iter() {
                        match key.to_string().as_str() {
                            #field_matching_from_hashmap
                            _ => return Err(bit_fields::TryFromFieldMapError::UnknownField)
                        }
                    }
                    Ok(base)
                }
            }
            impl std::convert::From<&#struct_name> for std::collections::HashMap<String,#struct_data_type> {
                fn from(bit_field: &#struct_name) -> Self {
                    let mut map = Self::new();
                    #field_setting_hashmap
                    map
                }
            }
        };
        #[cfg(not(feature = "field_map"))]
        let field_map = proc_macro2::TokenStream::new();

        #[cfg(all(feature = "flag_set", feature = "field_map"))]
        let set_map_conversions = quote! {
            impl<T:std::fmt::Display> std::convert::TryFrom<(std::collections::HashSet<T>,std::collections::HashMap<T,#struct_data_type>)> for #struct_name {
                type Error = bit_fields::TryFromFlagSetAndFieldMapError;
                fn try_from((set,map):(std::collections::HashSet<T>,std::collections::HashMap<T,#struct_data_type>)) -> Result<Self,Self::Error> {
                    let mut base = Self::from(0);
                    for key in set.into_iter() {
                        match key.to_string().as_str() {
                            #flag_matching_from_hashset
                            _ => return Err(bit_fields::TryFromFlagSetAndFieldMapError::FlagSet(bit_fields::TryFromFlagSetError))
                        }
                    }
                    for (key,value) in map.into_iter() {
                        match key.to_string().as_str() {
                            #field_matching_from_hashmap
                            _ => return Err(bit_fields::TryFromFlagSetAndFieldMapError::FieldMap(bit_fields::TryFromFieldMapError::UnknownField))
                        }
                    }
                    Ok(base)
                }
            }
            impl std::convert::From<&#struct_name> for (std::collections::HashSet<String>,std::collections::HashMap<String,#struct_data_type>) {
                fn from(bit_field: &#struct_name) -> Self {
                    let mut set = std::collections::HashSet::<String>::new();
                    #flag_setting_hashset

                    let mut map = std::collections::HashMap::<String,#struct_data_type>::new();
                    #field_setting_hashmap

                    (set,map)
                }
            }
        };
        #[cfg(not(all(feature = "flag_set", feature = "field_map")))]
        let set_map_conversions = proc_macro2::TokenStream::new();

        #[cfg(feature = "display")]
        let display_impl = {
            let display_full_string = String::from(self.display_string);
            quote! {
                impl std::fmt::Display for #struct_name {
                    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                        write!(f,#display_full_string,#display_fmt_string)
                    }
                }
            }
        };
        #[cfg(not(feature = "display"))]
        let display_impl = proc_macro2::TokenStream::new();

        #[cfg(feature = "cmp_flags")]
        let cmp_flags = quote! {
            /// Returns [`std::cmp::Ordering`] based on bit flags.
            /// - `Some(Ordering::Equal)` - Bit flags match between `self` and `other`.
            /// - `Some(Ordering::Greater)` - Bit flags of `self` are a strict superset of bit flags of `other`.
            /// - `Some(Ordering::Less)` - Bit flags of `self` are a strict subset of bit flags of `other`.
            /// - `None` - None of the above conditions are met.
            pub fn cmp_flags(&self,other: &Self) -> Option<std::cmp::Ordering> {
                if self == other {
                    Some(std::cmp::Ordering::Equal)
                }
                else if self.superset(other) {
                    Some(std::cmp::Ordering::Greater)
                }
                else {
                    Some(std::cmp::Ordering::Less)
                }
            }
        };
        #[cfg(not(feature = "cmp_flags"))]
        let cmp_flags = proc_macro2::TokenStream::new();

        let struct_name_str = struct_name.to_string();
        let header = format!(
            "A {} bit structure containing a number of bit flags and bit fields.",
            self.data_type.size()
        );

        #[cfg(feature = "bit_index")]
        let (struct_bits, struct_new_bits) = {
            let struct_bits = (0..self.data_type.size())
                .map(|i| quote! { bit_fields::Bit<#struct_data_type,#i>, })
                .collect::<proc_macro2::TokenStream>();

            let struct_new_bits = (0..self.data_type.size())
                .map(|_| quote! { bit_fields::Bit::new(), })
                .collect::<proc_macro2::TokenStream>();

            (
                quote! { pub bits: (#struct_bits), },
                quote! { bits: (#struct_new_bits), },
            )
        };
        #[cfg(not(feature = "bit_index"))]
        let (struct_bits, struct_new_bits) = (
            proc_macro2::TokenStream::new(),
            proc_macro2::TokenStream::new(),
        );

        let layout = quote! {
            #[doc=#header]
            ///
            /// ## Layout
            ///
            /// <table>
            #struct_doc_table_layout
            /// </table>
            #[derive(Clone)]
            #[repr(C)]
            pub struct #struct_name {
                pub data: #struct_data_type,
                #struct_bits
                #struct_member_fields
            }
            impl std::marker::Copy for #struct_name { }
            #serde
            impl std::cmp::PartialEq<#struct_data_type> for #struct_name {
                fn eq(&self,other:&#struct_data_type) -> bool {
                    self.data == *other
                }
            }
            impl std::cmp::PartialEq for #struct_name {
                fn eq(&self,other: &Self) -> bool {
                    self.data == other.data
                }
            }
            impl std::cmp::Eq for #struct_name { }
            /// We cannot derive [`std::fmt::Debug`] as `self.bits` may have too many elements.
            impl std::fmt::Debug for #struct_name {
                fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.debug_tuple(#struct_name_str)
                        .field(&self.data)
                        .finish()
                }
            }
            #display_impl
            /// We cannot derive [`std::default::Default`] as `self.bits` may have too many elements.
            impl std::default::Default for #struct_name {
                fn default() -> Self {
                    Self::from(0)
                }
            }
            impl std::fmt::Binary for #struct_name {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    std::fmt::Binary::fmt(&self.data, f)
                }
            }
            #flag_set
            #field_map
            #set_map_conversions
            /// Constructs `self` from the data type.
            impl std::convert::From<#struct_data_type> for #struct_name {
                fn from(data: #struct_data_type) -> Self {
                    Self {
                        data,
                        #struct_new_bits
                        #struct_member_fields_initialization
                    }
                }
            }
            /// Constructs the data type from `self`.
            impl std::convert::From<#struct_name> for #struct_data_type {
                fn from(bit_field: #struct_name) -> Self {
                    bit_field.data
                }
            }
            impl std::ops::BitOr for #struct_name {
                type Output = Self;
                fn bitor(self,rhs: Self) -> Self::Output {
                    Self::from(self.data | rhs.data)
                }
            }
            impl std::ops::BitAnd for #struct_name {
                type Output = Self;
                fn bitand(self,rhs: Self) -> Self::Output {
                    Self::from(self.data & rhs.data)
                }
            }
            impl std::ops::Not for #struct_name {
                type Output = Self;
                fn not(self) -> Self::Output {
                    Self::from(!self.data)
                }
            }
            impl #struct_name {
                const fn new(data: #struct_data_type) -> Self {
                    Self {
                        data,
                        #struct_new_bits
                        #struct_member_fields_initialization
                    }
                }
                #cmp_flags
                #set_theory
                #index_fn
            }
            #bit_index
        };

        proc_macro::TokenStream::from(layout)
    }
}
