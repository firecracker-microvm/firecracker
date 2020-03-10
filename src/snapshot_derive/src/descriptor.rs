use common::{compute_version, generate_deserializer_header, Exists, FieldType};
use enum_field::*;
use quote::{format_ident, quote};
use struct_field::*;
use union_field::*;

// An interface for generating serialzer and deserializers based on
// field descriptions.
pub trait Descriptor {
    fn generate_serializer(&self) -> proc_macro2::TokenStream;
    fn generate_deserializer(&self) -> proc_macro2::TokenStream;
    fn version(&self) -> u16;
    fn ty(&self) -> String;
}

// Describes a structure and it's fields.
pub(crate) struct StructDescriptor {
    pub ty: syn::Ident,
    pub version: u16,
    fields: Vec<StructField>,
}

// Describes an enum and it's fields.
pub(crate) struct EnumDescriptor {
    pub ty: syn::Ident,
    pub version: u16,
    fields: Vec<EnumVariant>,
}

// Describes an union and it's fields.
pub(crate) struct UnionDescriptor {
    pub ty: syn::Ident,
    pub version: u16,
    fields: Vec<UnionField>,
}

impl Descriptor for StructDescriptor {
    // Returns a token stream containing the serializer body.
    fn generate_serializer(&self) -> proc_macro2::TokenStream {
        let mut versioned_serializers = proc_macro2::TokenStream::new();

        for i in 1..=self.version {
            let mut versioned_serializer = proc_macro2::TokenStream::new();
            let mut semantic_serializer = proc_macro2::TokenStream::new();

            // Emit code for both field serializer and semantic serializer.
            for field in &self.fields {
                versioned_serializer.extend(field.generate_serializer(i));
                semantic_serializer.extend(field.generate_semantic_serializer(i));
            }

            // Serialization follows this flow: semantic -> field -> encode.
            versioned_serializers.extend(quote! {
                #i => {
                    #semantic_serializer
                    #versioned_serializer
                }
            });
        }

        let result = quote! {
            // Get the struct version for the input app_version.
            let version = version_map.get_type_version(app_version, &Self::name());
            // We will use this copy to perform semantic serialization.
            let mut copy_of_self = self.clone();
            match version {
                #versioned_serializers
                _ => panic!("Unknown {} version {}.", &Self::name(), version)
            }
        };
        result
    }

    // Returns a token stream containing the serializer body.
    fn generate_deserializer(&self) -> proc_macro2::TokenStream {
        let mut versioned_deserializers = proc_macro2::TokenStream::new();
        let struct_ident = format_ident!("{}", self.ty);
        let header = generate_deserializer_header(&self.fields);

        for i in 1..=self.version {
            let mut versioned_deserializer = proc_macro2::TokenStream::new();
            let mut semantic_deserializer = proc_macro2::TokenStream::new();

            for field in &self.fields {
                versioned_deserializer.extend(field.generate_deserializer(i));
                semantic_deserializer.extend(field.generate_semantic_deserializer(i));
            }

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

        quote! {
            #header
            let version = version_map.get_type_version(app_version, &Self::name());
            match version {
                #versioned_deserializers
                _ => panic!("Unknown {} version {}.", Self::name(), version)
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

    // Parses the struct field by field.
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

impl Descriptor for EnumDescriptor {
    fn generate_serializer(&self) -> proc_macro2::TokenStream {
        let mut versioned_serializers = proc_macro2::TokenStream::new();

        for i in 1..=self.version {
            let mut versioned_serializer = proc_macro2::TokenStream::new();

            // Emit code for both field serializer and semantic serializer.
            for field in &self.fields {
                versioned_serializer.extend(field.generate_serializer(i));
            }

            versioned_serializers.extend(quote! {
                #i => {
                    match self {
                        #versioned_serializer
                    }
                }
            });
        }

        let result = quote! {
            // Get the struct version for the input app_version.
            let version = version_map.get_type_version(app_version, &Self::name());
            // We will use this copy to perform semantic serialization.
            let mut copy_of_self = self.clone();
            match version {
                #versioned_serializers
                _ => panic!("Unknown {} version {}.", &Self::name(), version)
            }
        };

        result
    }

    // Returns a token stream containing the deserializer body.
    // Versioned/semantic deserialization is not implemented for enums.
    fn generate_deserializer(&self) -> proc_macro2::TokenStream {
        let ident = format_ident!("{}", self.ty);

        quote! {
            let variant: #ident = bincode::deserialize_from(&mut reader).map_err(|ref err| Error::Deserialize(format!("{}", err)))?;
            Ok(variant)
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
        for variant in variants.iter() {
            self.fields.push(EnumVariant::new(self.version, variant));
        }
    }
}

impl Descriptor for UnionDescriptor {
    fn generate_serializer(&self) -> proc_macro2::TokenStream {
        let mut versioned_serializers = proc_macro2::TokenStream::new();

        for i in 1..=self.version {
            let mut versioned_serializer = proc_macro2::TokenStream::new();
            for field in &self.fields {
                versioned_serializer.extend(field.generate_serializer(i));
            }

            let union_serializer = self.generate_union_serializer(i);

            // We aim here to serialize the largest field in the structure only.
            versioned_serializers.extend(quote! {
                #i => {
                    #union_serializer
                }
            });
        }

        let result = quote! {
            // Get the struct version for the input app_version.
            let version = version_map.get_type_version(app_version, &Self::name());
            // We will use this copy to perform semantic serialization.
            let mut copy_of_self = self.clone();
            match version {
                #versioned_serializers
                _ => panic!("Unknown {} version {}.", &Self::name(), version)
            }
        };

        result
    }

    // Returns a token stream containing the deserializer body.
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
            let version = version_map.get_type_version(app_version, &Self::name());
            match version {
                #versioned_deserializers
                _ => panic!("Unknown {} version {}.", Self::name(), version)
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

    fn generate_union_serializer(&self, target_version: u16) -> proc_macro2::TokenStream {
        let mut sizes = proc_macro2::TokenStream::new();
        let mut matcher = proc_macro2::TokenStream::new();

        let mut index: usize = 0;
        for field in &self.fields {
            if field.exists_at(target_version) {
                let field_type = field.ty();
                let field_serializer = field.generate_serializer(target_version);

                // Now generate code that compares each size of the fields and selects the largest one.
                sizes.extend(quote! {
                    std::mem::size_of::<#field_type> as usize,
                });

                matcher.extend(quote! {
                    #index => #field_serializer,
                });
                index += 1;
            }
        }

        quote! {
            // Create a vector of field sizes.
            let size_vector = vec![#sizes];
            let mut max: usize = 0;
            let mut largest_field_index: usize = 0;
            // Find largest_field_index.
            for i in 0..size_vector.len() {
                if (size_vector[i] > max) {
                    max = size_vector[i];
                    largest_field_index = i;
                }
            }

            // Serialize the largest field.
            match largest_field_index {
                #matcher
                _ => panic!("Cannot find largest union field index")
            }
        }
    }

    fn generate_union_deserializer(&self, source_version: u16) -> proc_macro2::TokenStream {
        let mut sizes = proc_macro2::TokenStream::new();
        let mut matcher = proc_macro2::TokenStream::new();
        let header = generate_deserializer_header(&self.fields);

        let mut index: usize = 0;

        let deserializable_fields: Vec<&UnionField> = self
            .fields
            .iter()
            .filter(|field| field.exists_at(source_version))
            .collect();

        for field in &deserializable_fields {
            let field_type = field.ty();
            let field_deserializer = field.generate_deserializer(source_version);

            // Now generate code that compares each size of the fields and selects the largest one.
            sizes.extend(quote! {
                std::mem::size_of::<#field_type> as usize,
            });

            matcher.extend(quote! {
                #index => #field_deserializer,
            });
            index += 1;
        }

        quote! {
            #header
            let size_vector = vec![#sizes];
            let mut max: usize = 0;
            let mut largest_field_index: usize = 0;
            for i in 0..size_vector.len() {
                if (size_vector[i] > max) {
                    max = size_vector[i];
                    largest_field_index = i;
                }
            }

            match largest_field_index {
                #matcher
                _ => panic!("Cannot find largest union field index")
            }
        }
    }
}
