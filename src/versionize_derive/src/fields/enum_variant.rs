// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::super::DEFAULT_FN;
use common::Exists;
use helpers::{get_end_version, get_ident_attr, get_start_version, parse_field_attributes};
use quote::{format_ident, quote};
use std::collections::hash_map::HashMap;

#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct EnumVariant {
    ident: syn::Ident,
    ty: Vec<syn::Type>,
    start_version: u16,
    // Bincode uses u32 instead of usize also.
    variant_index: u32,
    end_version: u16,
    attrs: HashMap<String, syn::Lit>,
}

impl Exists for EnumVariant {
    fn start_version(&self) -> u16 {
        self.start_version
    }

    fn end_version(&self) -> u16 {
        self.end_version
    }
}

impl EnumVariant {
    pub fn new(base_version: u16, ast_variant: &syn::Variant, variant_index: u32) -> Self {
        let attrs = parse_field_attributes(&ast_variant.attrs);
        let ty;

        match &ast_variant.fields {
            syn::Fields::Unnamed(fields) => {
                ty = fields
                    .unnamed
                    .iter()
                    .map(|field| field.ty.clone())
                    .collect();
            }
            _ => ty = Vec::new(),
        }

        EnumVariant {
            ident: ast_variant.ident.clone(),
            ty,
            variant_index,
            // Set base version.
            start_version: get_start_version(&attrs).unwrap_or(base_version),
            end_version: get_end_version(&attrs).unwrap_or_default(),
            attrs,
        }
    }

    // Emits code that serializes an enum variant.
    pub fn generate_serializer(&self, target_version: u16) -> proc_macro2::TokenStream {
        let field_ident = &self.ident;
        let variant_index = self.variant_index;

        if !self.exists_at(target_version) {
            if let Some(default_fn_ident) = get_ident_attr(&self.attrs, DEFAULT_FN) {
                return quote! {
                    Self::#field_ident(_) => {
                        // Call user defined fn to provide a variant that exists in target version.
                        let new_variant = self.#default_fn_ident(version)?;
                        // The new_variant will serialize it's index and data.
                        new_variant.serialize(writer, version_map, app_version)?;
                    },
                };
            } else {
                panic!("Variant {} does not exist in version {}, please implement a default_fn function that provides a default value for this variant.", field_ident.to_string(), target_version);
            }
        }

        let mut serialize_data = proc_macro2::TokenStream::new();
        let mut data_tuple = proc_macro2::TokenStream::new();

        for (index, _) in self.ty.iter().enumerate() {
            let data_ident = format_ident!("data_{}", index);
            data_tuple.extend(quote!(#data_ident,));
            serialize_data.extend(quote! {
                #data_ident.serialize(writer, version_map, app_version)?;
            });
        }

        if self.ty.is_empty() {
            quote! {
                Self::#field_ident => {
                    let index: u32 = #variant_index;
                    index.serialize(writer, version_map, app_version)?;
                },
            }
        } else {
            quote! {
                Self::#field_ident(#data_tuple) => {
                    let index: u32 = #variant_index;
                    index.serialize(writer, version_map, app_version)?;
                    #serialize_data
                },
            }
        }
    }

    pub fn generate_deserializer(&self) -> proc_macro2::TokenStream {
        let variant_index = self.variant_index;
        let ident = &self.ident;

        // Enum variant with no data.
        if self.ty.is_empty() {
            return quote! {
                #variant_index => {
                    return Ok(Self::#ident);
                },
            };
        }

        let mut deserialize_data = proc_macro2::TokenStream::new();
        let mut data_tuple = proc_macro2::TokenStream::new();
        for (index, data_type) in self.ty.iter().enumerate() {
            let data_ident = format_ident!("data_{}", index);
            data_tuple.extend(quote!(#data_ident,));
            deserialize_data.extend(
                quote! {
                    let #data_ident = <#data_type as Versionize>::deserialize(&mut reader, version_map, app_version)?;
                }
            );
        }

        return quote! {
            #variant_index => {
                #deserialize_data
                return Ok(Self::#ident(#data_tuple));
            },
        };
    }
}
