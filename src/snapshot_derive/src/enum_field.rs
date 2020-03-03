use common::{get_ident_attr, parse_field_attributes};
use quote::quote;
use std::collections::hash_map::HashMap;

#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct EnumVariant {
    ident: syn::Ident,
    discriminant: u16, // Only u16 discriminants allowed.
    start_version: u16,
    end_version: u16,
    attrs: HashMap<String, syn::Lit>,
}

impl EnumVariant {
    pub fn new(base_version: u16, ast_variant: &syn::Variant) -> Self {
        let mut variant = EnumVariant {
            ident: ast_variant.ident.clone(),
            discriminant: 0,
            // Set base version.
            start_version: base_version,
            end_version: 0,
            attrs: HashMap::new(),
        };

        // Get variant discriminant as u16.
        if let Some(discriminant) = &ast_variant.discriminant {
            // We only support ExprLit
            match &discriminant.1 {
                syn::Expr::Lit(lit_expr) => match &lit_expr.lit {
                    syn::Lit::Int(lit_int) => {
                        variant.discriminant = lit_int.base10_parse().unwrap()
                    }
                    _ => panic!("A u16 discriminant is required for versioning Enums."),
                },
                _ => panic!("A u16 discriminant is required for versioning Enums."),
            }
        } else {
            panic!("A u16 discriminant is required for versioning Enums.")
        }

        parse_field_attributes(&mut variant.attrs, &ast_variant.attrs);

        // TODO: This code is duplicated in StructField, UnionField and EnumFields.
        if let Some(start_version) = variant.get_attr("start_version") {
            match start_version {
                syn::Lit::Int(lit_int) => variant.start_version = lit_int.base10_parse().unwrap(),
                _ => panic!("Field start/end version number must be an integer"),
            }
        }

        if let Some(end_version) = variant.get_attr("end_version") {
            match end_version {
                syn::Lit::Int(lit_int) => variant.end_version = lit_int.base10_parse().unwrap(),
                _ => panic!("Field start/end version number must be an integer"),
            }
        }

        variant
    }

    fn get_default(&self) -> Option<syn::Ident> {
        get_ident_attr(&self.attrs, "default_fn")
    }

    fn get_attr(&self, attr: &str) -> Option<&syn::Lit> {
        self.attrs.get(attr)
    }

    pub fn get_start_version(&self) -> u16 {
        self.start_version
    }

    pub fn get_end_version(&self) -> u16 {
        self.end_version
    }

    // Emits code that serializes an enum variant.
    pub fn generate_serializer(&self, target_version: u16) -> proc_macro2::TokenStream {
        let field_ident = &self.ident;

        if target_version < self.start_version
            || (self.end_version > 0 && target_version > self.end_version)
        {
            if let Some(default_fn_ident) = self.get_default() {
                return quote! {
                    Self::#field_ident => {
                        let variant = self.#default_fn_ident(version);
                        bincode::serialize_into(writer, &variant).map_err(|ref err| Error::Serialize(format!("{}", err)))?;
                    },
                };
            } else {
                panic!("Variant {} does not exist in version {}, please implement a default_fn function that provides a default value for this variant.", field_ident.to_string(), target_version);
            }
        }

        quote! {
            Self::#field_ident => {
                bincode::serialize_into(writer, &self).map_err(|ref err| Error::Serialize(format!("{}", err)))?;
            },
        }
    }
}
