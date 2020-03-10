use common::{get_end_version, get_ident_attr, get_start_version, parse_field_attributes, Exists};
use quote::quote;
use super::{DEFAULT_FN};
use std::collections::hash_map::HashMap;

#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct EnumVariant {
    ident: syn::Ident,
    discriminant: u16, // Only u16 discriminants allowed.
    start_version: u16,
    end_version: u16,
    attrs: HashMap<String, syn::Lit>,
}

impl Exists for EnumVariant {
    fn start_version(&self) -> u16 {
        self.start_version
    }

    fn end_version(&self) -> u16 {
        self.end_version
    }
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
        variant.start_version = get_start_version(&variant.attrs).unwrap_or(base_version);
        variant.end_version = get_end_version(&variant.attrs).unwrap_or_default();
        variant
    }

    // Emits code that serializes an enum variant.
    pub fn generate_serializer(&self, target_version: u16) -> proc_macro2::TokenStream {
        let field_ident = &self.ident;

        if !self.exists_at(target_version) {
            if let Some(default_fn_ident) = get_ident_attr(&self.attrs, DEFAULT_FN) {
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
