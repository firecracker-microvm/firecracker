use common::*;
use quote::{format_ident, quote};
use super::{DEFAULT_FN, SEMANTIC_SER_FN, SEMANTIC_DE_FN};
use std::collections::hash_map::HashMap;

#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct StructField {
    ty: syn::Type,
    name: String,
    start_version: u16,
    end_version: u16,
    attrs: HashMap<String, syn::Lit>,
}

impl Exists for StructField {
    fn start_version(&self) -> u16 {
        self.start_version
    }

    fn end_version(&self) -> u16 {
        self.end_version
    }
}

impl FieldType for StructField {
    fn ty(&self) -> syn::Type {
        self.ty.clone()
    }
}

impl StructField {
    // Parses the abstract syntax tree and create a versioned Field definition.
    pub fn new(
        base_version: u16,
        ast_field: syn::punctuated::Pair<&syn::Field, &syn::token::Comma>,
    ) -> Self {
        let name = ast_field.value().ident.as_ref().unwrap().to_string();
        let mut field = StructField {
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

    pub fn generate_semantic_serializer(&self, target_version: u16) -> proc_macro2::TokenStream {
        // Generate semantic serializer for this field only if it does not exist in target_version.
        if !self.exists_at(target_version) {
            if let Some(semantic_ser_fn) = get_ident_attr(&self.attrs, SEMANTIC_SER_FN) {
                return quote! {
                    copy_of_self.#semantic_ser_fn(version)?;
                };
            }
        }
        quote! {}
    }

    // !! Semantic deserialization not supported for enums.
    pub fn generate_semantic_deserializer(&self, source_version: u16) -> proc_macro2::TokenStream {
        // Generate semantic deserializer for this field only if it does not exist in source_version.
        if !self.exists_at(source_version) {
            if let Some(semantic_de_fn) = get_ident_attr(&self.attrs, SEMANTIC_DE_FN) {
                // Object is an instance of the structure.
                return quote! {
                    object.#semantic_de_fn(version)?;
                };
            }
        }
        quote! {}
    }

    // Emits code that serializes this field.
    pub fn generate_serializer(&self, target_version: u16) -> proc_macro2::TokenStream {
        let field_ident = format_ident!("{}", self.name);

        // Generate serializer for this field only if it exists in target_version.
        if !self.exists_at(target_version) {
            return proc_macro2::TokenStream::new();
        }

        match &self.ty {
            syn::Type::Array(_) => quote! {
                Versionize::serialize(&copy_of_self.#field_ident.to_vec(), writer, version_map, app_version)?;
            },
            syn::Type::Path(_) => quote! {
                Versionize::serialize(&copy_of_self.#field_ident, writer, version_map, app_version)?;
            },
            syn::Type::Reference(_) => quote! {
                Versionize::serialize(&copy_of_self.#field_ident, writer, version_map, app_version)?;
            },
            _ => panic!("Unsupported field type {:?}", self.ty),
        }
    }

    // Emits code that deserializes this field.
    pub fn generate_deserializer(&self, source_version: u16) -> proc_macro2::TokenStream {
        let field_ident = format_ident!("{}", self.name);

        // If the field does not exist in source version, use default annotation or Default trait.
        if !self.exists_at(source_version) {
            if let Some(default_fn) = get_ident_attr(&self.attrs, DEFAULT_FN) {
                return quote! {
                    // The default_fn is called with source version of the struct:
                    // - `version` is set to version_map.get_type_version(app_version, &Self::name());
                    // - `app_version` is source application version.
                    #field_ident: Self::#default_fn(version),
                };
            } else {
                return quote! { #field_ident: Default::default(), };
            }
        }

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
                    #field_ident: {
                        let v: Vec<#array_type_token> = <Vec<#array_type_token> as Versionize>::deserialize(&mut reader, version_map, app_version)?;
                        vec_to_arr_func!(transform_vec, #array_type_token, #array_len);
                        transform_vec(&v)
                    },
                }
            }
            syn::Type::Path(_) => quote! {
                #field_ident: <#ty as Versionize>::deserialize(&mut reader, version_map, app_version)?,
            },
            syn::Type::Reference(_) => quote! {
                #field_ident: <#ty as Versionize>::deserialize(&mut reader, version_map, app_version)?,
            },
            _ => panic!("Unsupported field type {:?}", self.ty),
        }
    }
}
