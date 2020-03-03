use common::*;
use quote::{format_ident, quote};
use std::collections::hash_map::HashMap;

#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct UnionField {
    ty: syn::Type,
    name: String,
    start_version: u16,
    end_version: u16,
    attrs: HashMap<String, syn::Lit>,
}

impl UnionField {
    pub fn new(
        base_version: u16,
        ast_field: syn::punctuated::Pair<&syn::Field, &syn::token::Comma>,
    ) -> Self {
        let name = ast_field.value().ident.as_ref().unwrap().to_string();
        let mut field = UnionField {
            ty: ast_field.value().ty.clone(),
            name,
            start_version: base_version,
            end_version: 0,
            attrs: HashMap::new(),
        };

        parse_field_attributes(&mut field.attrs, &ast_field.value().attrs);

        // Adjust version based on attributes.
        if let Some(start_version) = field.get_attr("start_version") {
            match start_version {
                syn::Lit::Int(lit_int) => field.start_version = lit_int.base10_parse().unwrap(),
                _ => panic!("Field start/end version number must be an integer"),
            }
        }

        if let Some(end_version) = field.get_attr("end_version") {
            match end_version {
                syn::Lit::Int(lit_int) => field.end_version = lit_int.base10_parse().unwrap(),
                _ => panic!("Field start/end version number must be an integer"),
            }
        }

        field
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

    pub fn get_type(&self) -> syn::Type {
        self.ty.clone()
    }

    fn get_name(&self) -> String {
        self.name.clone()
    }

    pub fn is_array(&self) -> bool {
        match self.ty {
            syn::Type::Array(_) => true,
            _ => false,
        }
    }

    // Emits code that serializes a union field.
    pub fn generate_serializer(&self, _target_version: u16) -> proc_macro2::TokenStream {
        let field_ident = format_ident!("{}", self.get_name());
        if self.is_array() {
            return quote! {
                unsafe {
                    Versionize::serialize(&copy_of_self.#field_ident.to_vec(), writer, version_map, app_version)?
                }
            };
        }

        quote! {
            unsafe {
                Versionize::serialize(&copy_of_self.#field_ident, writer, version_map, app_version)?
            }
        }
    }

    pub fn generate_deserializer(&self, _source_version: u16) -> proc_macro2::TokenStream {
        let field_ident = format_ident!("{}", self.name);
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
                    unsafe {
                        object.#field_ident = {
                            let v: Vec<#array_type_token> = <Vec<#array_type_token> as Versionize>::deserialize(&mut reader, version_map, app_version)?;
                            vec_to_arr_func!(transform_vec, #array_type_token, #array_len);
                            transform_vec(&v)
                        }
                    }
                }
            }
            syn::Type::Path(_) => quote! {
                unsafe { object.#field_ident = <#ty as Versionize>::deserialize(&mut reader, version_map, app_version)?; }
            },
            syn::Type::Reference(_) => quote! {
                unsafe { object.#field_ident = <#ty as Versionize>::deserialize(&mut reader, version_map, app_version)?; }
            },
            _ => panic!("Unsupported field type {:?}", self.ty),
        }
    }

}
