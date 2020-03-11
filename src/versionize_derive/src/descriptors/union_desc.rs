// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use common::{Descriptor, Exists, FieldType, GenericDescriptor};
use fields::union_field::*;
use helpers::{compute_version, generate_deserializer_header};
use quote::quote;

pub(crate) type UnionDescriptor = GenericDescriptor<UnionField>;

impl Descriptor for UnionDescriptor {
    fn generate_serializer(&self) -> proc_macro2::TokenStream {
        let mut versioned_serializers = proc_macro2::TokenStream::new();

        for i in 1..=self.version {
            let union_serializer = self.generate_union_serializer(i);

            versioned_serializers.extend(quote! {
                #i => {
                    #union_serializer
                }
            });
        }

        versioned_serializers
    }

    fn generate_deserializer(&self) -> proc_macro2::TokenStream {
        let mut versioned_deserializers = proc_macro2::TokenStream::new();

        for i in 1..=self.version {
            let union_serializer = self.generate_union_deserializer(i);

            versioned_deserializers.extend(quote! {
                #i => {
                    let mut object = Self::default();
                    #union_serializer;
                    Ok(object)
                }
            });
        }

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

impl UnionDescriptor {
    pub fn new(input: &syn::DataUnion, ident: syn::Ident) -> Self {
        let mut descriptor = UnionDescriptor {
            ty: ident,
            version: 1, // struct start at version 1.
            fields: vec![],
        };

        descriptor.parse_union_fields(&input.fields);
        descriptor.version = compute_version(&descriptor.fields);
        descriptor
    }

    fn parse_union_fields(&mut self, fields: &syn::FieldsNamed) {
        let pairs = fields.named.pairs();
        for field in pairs.into_iter() {
            self.fields.push(UnionField::new(self.version, field));
        }
    }

    fn generate_field_finder(
        &self,
        sizes: proc_macro2::TokenStream,
        matcher: proc_macro2::TokenStream,
    ) -> proc_macro2::TokenStream {
        quote! {
            // Create a vector of field sizes.
            let size_vector = vec![#sizes];
            let largest_field_index: usize = size_vector
                .iter()
                .enumerate()
                .max_by(|(_, lsize), (_, rsize)| lsize.partial_cmp(rsize).unwrap_or(std::cmp::Ordering::Equal))
                .map(|(index, _)| index)
                .expect("Cannot find largest union field index");

            // Serialize the largest field.
            match largest_field_index {
                #matcher
                _ => panic!("Cannot find largest union field index")
            }
        }
    }

    // Generate code that serializes the largest field of an union at a specified version.
    // NOTE: For the moment, there is no safe way to find the largest field is at compile,
    // so we will need to also generate code that selects a specific field at runtime.
    // If this overhead is too much, one can revert to manually implementing the Versionize
    // trait.
    fn generate_union_serializer(&self, target_version: u16) -> proc_macro2::TokenStream {
        let mut sizes = proc_macro2::TokenStream::new();
        let mut matcher = proc_macro2::TokenStream::new();

        // Select fields that exist in the target version.
        let serializable_fields: Vec<&UnionField> = self
            .fields
            .iter()
            .filter(|field| field.exists_at(target_version))
            .collect();

        for (index, field) in serializable_fields.iter().enumerate() {
            let field_type = field.ty();
            let field_serializer = field.generate_serializer(target_version);

            // Generate the vec initializer content.
            sizes.extend(quote! {
                std::mem::size_of::<#field_type> as usize,
            });

            // Generate match arms for select fields by index.
            matcher.extend(quote! {
                #index => #field_serializer,
            });
        }

        self.generate_field_finder(sizes, matcher)
    }

    // Generate code that deserializes the largest field of an union at a specified version.
    // NOTE: See generate_union_serializer().
    fn generate_union_deserializer(&self, source_version: u16) -> proc_macro2::TokenStream {
        let mut sizes = proc_macro2::TokenStream::new();
        let mut matcher = proc_macro2::TokenStream::new();
        let header = generate_deserializer_header(&self.fields);

        let deserializable_fields: Vec<&UnionField> = self
            .fields
            .iter()
            .filter(|field| field.exists_at(source_version))
            .collect();

        for (index, field) in deserializable_fields.iter().enumerate() {
            let field_type = field.ty();
            let field_deserializer = field.generate_deserializer(source_version);

            sizes.extend(quote! {
                std::mem::size_of::<#field_type> as usize,
            });

            matcher.extend(quote! {
                #index => #field_deserializer,
            });
        }

        let finder = self.generate_field_finder(sizes, matcher);
        quote! {
            #header
            #finder
        }
    }
}
