// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use common::{Descriptor, GenericDescriptor};
use fields::struct_field::*;
use helpers::compute_version;
use quote::{format_ident, quote};

pub(crate) type StructDescriptor = GenericDescriptor<StructField>;

impl Descriptor for StructDescriptor {
    fn generate_serializer(&self) -> proc_macro2::TokenStream {
        let mut versioned_serializers = proc_macro2::TokenStream::new();

        for i in 1..=self.version {
            let mut versioned_serializer = proc_macro2::TokenStream::new();
            let mut semantic_serializer = proc_macro2::TokenStream::new();

            // Generate field and semantic serializers for all fields.
            // Not all fields have semantic serializers defined and some fields
            // might be missing in version `i`. In these cases the generate_serializer() and
            // generate_semantic_serializer() will return an empty token stream.
            for field in &self.fields {
                versioned_serializer.extend(field.generate_serializer(i));
                semantic_serializer.extend(field.generate_semantic_serializer(i));
            }

            // Generate the match arm for version `i`.
            versioned_serializers.extend(quote! {
                #i => {
                    #semantic_serializer
                    #versioned_serializer
                }
            });
        }

        versioned_serializers
    }

    fn generate_deserializer(&self) -> proc_macro2::TokenStream {
        let mut versioned_deserializers = proc_macro2::TokenStream::new();
        let struct_ident = format_ident!("{}", self.ty);

        for i in 1..=self.version {
            let mut versioned_deserializer = proc_macro2::TokenStream::new();
            let mut semantic_deserializer = proc_macro2::TokenStream::new();

            // Generate field and semantic deserializers for all fields.
            // Not all fields have semantic deserializers defined and some fields
            // might be missing in version `i`. In these cases the generate_deserializer() and
            // generate_semantic_deserializer() will return an empty token stream.
            for field in &self.fields {
                versioned_deserializer.extend(field.generate_deserializer(i));
                semantic_deserializer.extend(field.generate_semantic_deserializer(i));
            }

            // Generate the match arm for version `i`.
            //
            // The semantic deserialization functions will be called after the object is constructed
            // using the previously generated field deserializers.
            versioned_deserializers.extend(quote! {
                #i => {
                    let mut object = #struct_ident {
                        #versioned_deserializer
                    };
                    #semantic_deserializer
                    Ok(object)
                }
            });
        }

        // Generate code to map the app version to struct version and wrap the
        // deserializers with the `version` match.
        quote! {
            let version = version_map.get_type_version(app_version, Self::type_id());
            match version {
                #versioned_deserializers
                _ => panic!("Unknown {:?} version {}.", Self::type_id(), version)
            }
        }
    }

    fn version(&self) -> u16 {
        self.version
    }

    fn ty(&self) -> String {
        self.ty.to_string()
    }
}

impl StructDescriptor {
    pub fn new(input: &syn::DataStruct, ident: syn::Ident) -> Self {
        let mut descriptor = StructDescriptor {
            ty: ident,
            version: 1, // struct start at version 1.
            fields: vec![],
        };

        // Fills self.fields.
        descriptor.parse_struct_fields(&input.fields);
        descriptor.version = compute_version(&descriptor.fields);
        descriptor
    }

    fn parse_struct_fields(&mut self, fields: &syn::Fields) {
        match fields {
            syn::Fields::Named(ref named_fields) => {
                let pairs = named_fields.named.pairs();
                for field in pairs.into_iter() {
                    self.fields.push(StructField::new(self.version, field));
                }
            }
            _ => panic!("Only named fields are supported."),
        }
    }
}
