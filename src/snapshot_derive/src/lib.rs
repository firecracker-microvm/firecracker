// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// The `quote!` macro requires deep recursion.
extern crate proc_macro;
extern crate proc_macro2;
extern crate quote;
extern crate syn;

mod common;
mod descriptor;
mod enum_field;
mod struct_field;
mod union_field;

use descriptor::*;
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

pub(crate) const DEFAULT_FN: &str = "default_fn";
pub(crate) const SEMANTIC_SER_FN: &str = "semantic_ser_fn";
pub(crate) const SEMANTIC_DE_FN: &str = "semantic_de_fn";
pub(crate) const START_VERSION: &str = "start_version";
pub(crate) const END_VERSION: &str = "end_version";


#[proc_macro_derive(Versionize, attributes(snapshot))]
pub fn generate_versionizer(input: TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let ident = input.ident.clone();
    let generics = input.generics.clone();

    let descriptor: Box<dyn Descriptor> = match &input.data {
        syn::Data::Struct(data_struct) => {
            Box::new(StructDescriptor::new(&data_struct, ident.clone()))
        }
        syn::Data::Enum(data_enum) => Box::new(EnumDescriptor::new(&data_enum, ident.clone())),
        syn::Data::Union(data_union) => Box::new(UnionDescriptor::new(&data_union, ident.clone())),
    };

    let name = descriptor.ty().to_string();
    let version = descriptor.version();
    let serializer = descriptor.generate_serializer();
    let deserializer = descriptor.generate_deserializer();

    (quote! {
        impl Versionize for #ident #generics {
            #[inline]
            fn serialize<W: std::io::Write>(&self, writer: &mut W, version_map: &VersionMap, app_version: u16) -> Result<()> {
                #serializer
                Ok(())
            }

            #[inline]
            fn deserialize<R: std::io::Read>(mut reader: &mut R, version_map: &VersionMap, app_version: u16) -> Result<Self> {
                #deserializer
            }

            #[inline]
            // Returns struct name as string.
            fn name() -> String {
                #name.to_owned()
            }

            #[inline]
            // Returns struct current version.
            fn version() -> u16 {
                #version
            }
        }
    }).into()
}
