// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]

//! Exports the Versionize derive proc macro that generates the Versionize implementation
//! for structs, enums and unions by using structure annotations.

extern crate proc_macro;
extern crate proc_macro2;
extern crate quote;
extern crate syn;

mod common;
mod descriptors;
mod fields;
mod helpers;

use common::Descriptor;
use descriptors::{
    enum_desc::EnumDescriptor, struct_desc::StructDescriptor, union_desc::UnionDescriptor,
};
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

pub(crate) const ATTRIBUTE_NAME: &str = "version";

/// Struct annotation constants.
pub(crate) const DEFAULT_FN: &str = "default_fn";
pub(crate) const SEMANTIC_SER_FN: &str = "ser_fn";
pub(crate) const SEMANTIC_DE_FN: &str = "de_fn";
pub(crate) const START_VERSION: &str = "start";
pub(crate) const END_VERSION: &str = "end";

/// Implements the derive proc macro.
#[proc_macro_derive(Versionize, attributes(version))]
pub fn impl_versionize(input: TokenStream) -> proc_macro::TokenStream {
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

    let version = descriptor.version();
    let versioned_serializer = descriptor.generate_serializer();
    let deserializer = descriptor.generate_deserializer();
    let serializer = quote! {
        // Get the struct version for the input app_version.
        let version = version_map.get_type_version(app_version, Self::type_id());
        // We will use this copy to perform semantic serialization.
        let mut copy_of_self = self.clone();
        match version {
            #versioned_serializer
            _ => panic!("Unknown {:?} version {}.", &Self::type_id(), version)
        }
    };
    (quote! {
        impl Versionize for #ident #generics {
            fn serialize<W: std::io::Write>(&self, writer: &mut W, version_map: &VersionMap, app_version: u16) -> VersionizeResult<()> {
                #serializer
                Ok(())
            }

            fn deserialize<R: std::io::Read>(mut reader: &mut R, version_map: &VersionMap, app_version: u16) -> VersionizeResult<Self> {
                #deserializer
            }

            // Returns struct current version.
            fn version() -> u16 {
                #version
            }
        }
    }).into()
}
