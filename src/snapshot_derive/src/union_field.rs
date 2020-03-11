// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use common::*;
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
        let name = ast_field.value().ident.as_ref().unwrap().to_string();
        let mut field = UnionField {
            ty: ast_field.value().ty.clone(),
            name,
            start_version: base_version,
            end_version: 0,
            attrs: HashMap::new(),
        };

        parse_field_attributes(&mut field.attrs, &ast_field.value().attrs);

        field.start_version = get_start_version(&field.attrs).unwrap_or(base_version);
        field.end_version = get_end_version(&field.attrs).unwrap_or_default();

        field
    }

    fn name(&self) -> String {
        self.name.clone()
    }

    // Emits code that serializes a union field.
    pub fn generate_serializer(&self, _target_version: u16) -> proc_macro2::TokenStream {
        let field_ident = format_ident!("{}", self.name());
        if is_array(&self.ty()) {
            return quote! {
                unsafe {
                    Versionize::serialize(&copy_of_self.#field_ident.to_vec(), writer, version_map, app_version)?
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
            syn::Type::Array(array) => {
                let array_type_token;
                let array_len: usize;

                match *array.elem.clone() {
                    syn::Type::Path(token) => {
                        array_type_token = token;
                    }
                    _ => panic!("Unsupported array type."),
                }

                match &array.len {
                    syn::Expr::Lit(expr_lit) => match &expr_lit.lit {
                        syn::Lit::Int(lit_int) => array_len = lit_int.base10_parse().unwrap(),
                        _ => panic!("Unsupported array len literal."),
                    },
                    _ => panic!("Unsupported array len expression."),
                }

                quote! {
                    unsafe {
                        object.#field_ident = {
                            let v: Vec<#array_type_token> = <Vec<#array_type_token> as Versionize>::deserialize(&mut reader, version_map, app_version)?;
                            vec_to_arr_func!(transform_vec, #array_type_token, #array_len);
                            transform_vec(&v)
                        }
                    }
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
}
