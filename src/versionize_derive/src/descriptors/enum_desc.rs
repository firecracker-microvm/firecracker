// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use common::{Descriptor, GenericDescriptor};
use fields::enum_variant::*;
use helpers::compute_version;
use quote::quote;

pub(crate) type EnumDescriptor = GenericDescriptor<EnumVariant>;

impl Descriptor for EnumDescriptor {
    fn generate_serializer(&self) -> proc_macro2::TokenStream {
        let mut versioned_serializers = proc_macro2::TokenStream::new();

        for i in 1..=self.version {
            let mut versioned_serializer = proc_macro2::TokenStream::new();

            for field in &self.fields {
                versioned_serializer.extend(field.generate_serializer(i));
            }

            // Generate the match arm for version `i` serializer.
            versioned_serializers.extend(quote! {
                #i => {
                    match self {
                        #versioned_serializer
                    }
                }
            });
        }

        versioned_serializers
    }

    // Versioned/semantic deserialization is not implemented for enums.
    fn generate_deserializer(&self) -> proc_macro2::TokenStream {
        let mut versioned_deserializers = proc_macro2::TokenStream::new();

        for field in &self.fields {
            versioned_deserializers.extend(field.generate_deserializer());
        }

        quote! {
            let variant_index = <u32 as Versionize>::deserialize(&mut reader, version_map, app_version)?;
            match variant_index {
                #versioned_deserializers
                x => return Err(Error::Deserialize(format!("Unknown variant_index {}", x)))
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

impl EnumDescriptor {
    pub fn new(input: &syn::DataEnum, ident: syn::Ident) -> Self {
        let mut descriptor = EnumDescriptor {
            ty: ident,
            version: 1,
            fields: vec![],
        };

        descriptor.parse_enum_variants(&input.variants);
        descriptor.version = compute_version(&descriptor.fields);
        descriptor
    }

    fn parse_enum_variants(
        &mut self,
        variants: &syn::punctuated::Punctuated<syn::Variant, syn::token::Comma>,
    ) {
        for (index, variant) in variants.iter().enumerate() {
            self.fields
                .push(EnumVariant::new(self.version, variant, index as u32));
        }
    }
}
