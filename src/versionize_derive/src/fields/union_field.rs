// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use common::{Exists, FieldType};
use helpers::{get_end_version, get_start_version, is_array, parse_field_attributes};
use quote::{format_ident, quote};
use std::collections::hash_map::HashMap;

#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct UnionField {
    ty: syn::Type,
    name: String,
    start_version: u16,
    end_version: u16,
    attrs: HashMap<String, syn::Lit>,
}

impl Exists for UnionField {
    fn start_version(&self) -> u16 {
        self.start_version
    }

    fn end_version(&self) -> u16 {
        self.end_version
    }
}

impl FieldType for UnionField {
    fn ty(&self) -> syn::Type {
        self.ty.clone()
    }
}

impl UnionField {
    pub fn new(
        base_version: u16,
        ast_field: syn::punctuated::Pair<&syn::Field, &syn::token::Comma>,
    ) -> Self {
        let attrs = parse_field_attributes(&ast_field.value().attrs);

        UnionField {
            ty: ast_field.value().ty.clone(),
            name: ast_field.value().ident.as_ref().unwrap().to_string(),
            start_version: get_start_version(&attrs).unwrap_or(base_version),
            end_version: get_end_version(&attrs).unwrap_or_default(),
            attrs: HashMap::new(),
        }
    }

    fn name(&self) -> String {
        self.name.clone()
    }

    pub fn generate_serializer(&self, _target_version: u16) -> proc_macro2::TokenStream {
        let field_ident = format_ident!("{}", self.name());

        // If the field is an array then serialize as a Vec<T>.
        if is_array(&self.ty()) {
            return quote! {
                unsafe {
                    for element in &copy_of_self.#field_ident {
                        element.serialize(writer, version_map, app_version)?;
                    }
                }
            };
        }

        quote! {
            unsafe {
                Versionize::serialize(&copy_of_self.#field_ident, writer, version_map, app_version)?
            }
        }
    }

    pub fn generate_deserializer(&self, _source_version: u16) -> proc_macro2::TokenStream {
        let field_ident = format_ident!("{}", self.name);
        let ty = &self.ty;

        match ty {
            // Array deserialization is more verbose than serialization as we have to
            // extract the array type and length from the AST.
            // TODO!: Find a more efficient way to deserialize this array: currently we
            // deserialize a Vec<T> and then copy the elements to the target array.
            syn::Type::Array(array) => {
                let array_type_token;

                match *array.elem.clone() {
                    syn::Type::Path(token) => {
                        array_type_token = token;
                    }
                    _ => panic!("Unsupported array type."),
                }

                match &array.len {
                    syn::Expr::Lit(expr_lit) => match &expr_lit.lit {
                        syn::Lit::Int(lit_int) => {
                            let array_len: usize = lit_int.base10_parse().unwrap();
                            self.generate_array_deserializer(array_type_token, array_len)
                        }
                        _ => panic!("Unsupported array len literal."),
                    },
                    syn::Expr::Path(expr_path) => {
                        self.generate_array_deserializer(array_type_token, &expr_path.path)
                    }
                    _ => panic!("Unsupported array len expression."),
                }
            }
            syn::Type::Path(_) => quote! {
                unsafe { object.#field_ident = <#ty as Versionize>::deserialize(&mut reader, version_map, app_version)?; }
            },
            syn::Type::Reference(_) => quote! {
                unsafe { object.#field_ident = <#ty as Versionize>::deserialize(&mut reader, version_map, app_version)?; }
            },
            _ => panic!("Unsupported field type {:?}", self.ty),
        }
    }

    fn generate_array_deserializer<T: quote::ToTokens>(
        &self,
        array_type_token: syn::TypePath,
        array_len: T,
    ) -> proc_macro2::TokenStream {
        let field_ident = format_ident!("{}", self.name);

        quote! {
            unsafe {
                object.#field_ident = {
                    let mut array = [#array_type_token::default() ; #array_len];
                    for i in 0..#array_len {
                        array[i] = <#array_type_token as Versionize>::deserialize(&mut reader, version_map, app_version)?;
                    }
                    array
                }
            }
        }
    }
}
