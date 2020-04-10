// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// An interface for generating serialzer and deserializers based on
/// field descriptions.
pub trait Descriptor {
    /// Returns the serializer code block as a token stream.
    fn generate_serializer(&self) -> proc_macro2::TokenStream;
    /// Returns the deserializer code block as a token stream.
    fn generate_deserializer(&self) -> proc_macro2::TokenStream;
    /// Returns the curent version.
    fn version(&self) -> u16;
    /// Returns the type name as string.
    fn ty(&self) -> String;
}

/// Describes a structure and it's fields.
pub(crate) struct GenericDescriptor<T> {
    // The structure type identifier.
    pub ty: syn::Ident,
    pub version: u16,
    pub fields: Vec<T>,
}

// A trait that defines an interface to check if a certain field
// exists at a specified version.
pub(crate) trait Exists {
    fn exists_at(&self, version: u16) -> bool {
        // All fields have a start version.
        // Some field do not have an end version specified.
        version >= self.start_version()
            && (0 == self.end_version() || (self.end_version() > 0 && version < self.end_version()))
    }

    fn start_version(&self) -> u16;
    fn end_version(&self) -> u16;
}

// A trait that defines an interface for exposing a field type.
pub(crate) trait FieldType {
    fn ty(&self) -> syn::Type;
}

#[cfg(test)]
mod tests {
    use super::Exists;

    #[test]
    fn test_exists_at() {
        impl Exists for u32 {
            fn start_version(&self) -> u16 {
                3
            }

            fn end_version(&self) -> u16 {
                5
            }
        }

        let test = 1234;
        assert!(!test.exists_at(2));
        assert!(test.exists_at(3));
        assert!(test.exists_at(4));
        assert!(!test.exists_at(5));
        assert!(!test.exists_at(6));
    }
}
