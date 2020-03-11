// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::{ATTRIBUTE_NAME, END_VERSION, START_VERSION};
use common::{Exists, FieldType};
use quote::{format_ident, quote};
use std::cmp::max;
use std::collections::hash_map::HashMap;

// Returns a string literal attribute as an Ident.
pub(crate) fn get_ident_attr(
    attrs: &HashMap<String, syn::Lit>,
    attr_name: &str,
) -> Option<syn::Ident> {
    attrs.get(attr_name).map(|default_fn| match default_fn {
        syn::Lit::Str(lit_str) => {
            return format_ident!("{}", lit_str.value());
        }
        _ => panic!("default_fn must be the function name as a String."),
    })
}

pub(crate) fn get_start_version(attrs: &HashMap<String, syn::Lit>) -> Option<u16> {
    if let Some(start_version) = attrs.get(START_VERSION) {
        return Some(match start_version {
            syn::Lit::Int(lit_int) => lit_int.base10_parse().unwrap(),
            _ => panic!("Field start/end version number must be an integer"),
        });
    }
    None
}

pub(crate) fn get_end_version(attrs: &HashMap<String, syn::Lit>) -> Option<u16> {
    if let Some(start_version) = attrs.get(END_VERSION) {
        return Some(match start_version {
            syn::Lit::Int(lit_int) => lit_int.base10_parse().unwrap(),
            _ => panic!("Field start/end version number must be an integer"),
        });
    }
    None
}

// Returns an attribute hash_map constructed by processing a vector of syn::Attribute.
pub(crate) fn parse_field_attributes(attributes: &[syn::Attribute]) -> HashMap<String, syn::Lit> {
    let mut attrs = HashMap::new();

    for nested_attr in attributes
        .iter()
        .flat_map(|attr| -> Result<Vec<syn::NestedMeta>, ()> {
            if !attr.path.is_ident(ATTRIBUTE_NAME) {
                return Ok(Vec::new());
            }

            if let Ok(syn::Meta::List(meta)) = attr.parse_meta() {
                return Ok(meta.nested.into_iter().collect());
            }

            Ok(Vec::new())
        })
        .flatten()
    {
        if let syn::NestedMeta::Meta(nested_meta) = nested_attr {
            if let syn::Meta::NameValue(attr_name_value) = nested_meta {
                attrs.insert(
                    attr_name_value.path.get_ident().unwrap().to_string(),
                    attr_name_value.lit,
                );
            }
        }
    }

    attrs
}

pub fn is_array(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Array(_) => true,
        _ => false,
    }
}

// Compute current struct version by finding the latest field change version.
pub(crate) fn compute_version<T>(fields: &[T]) -> u16
where
    T: Exists,
{
    let mut version = 0;
    for field in fields {
        version = max(version, max(field.start_version(), field.end_version()));
    }
    version
}

// Just checking if there are any array fields present.
// If so, return a token stream with the vec2array macro.
pub(crate) fn generate_deserializer_header<T>(fields: &[T]) -> proc_macro2::TokenStream
where
    T: FieldType,
{
    if fields.iter().any(|field| is_array(&field.ty())) {
        return quote! {
            use std::convert::TryInto;

            // This macro will generate a function that copies a vec to an array.
            // We serialize arrays as vecs.
            macro_rules! vec_to_arr_func {
                ($name:ident, $type:ty, $size:expr) => {
                    pub fn $name(data: std::vec::Vec<$type>) -> [$type; $size] {
                        let mut arr = [<$type as Default>::default(); $size];
                        arr.copy_from_slice(&data[0..$size]);
                        arr
                    }
                };
            }
        };
    }

    quote! {}
}
