use quote::{format_ident, quote};
use super::{START_VERSION, END_VERSION};
use std::cmp::max;
use std::collections::hash_map::HashMap;

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

// Returns a string literal attribute as an Ident.
pub(crate) fn get_ident_attr(
    attrs: &HashMap<String, syn::Lit>,
    attr_name: &str,
) -> Option<syn::Ident> {
    attrs.get(attr_name).map(|default_fn| match default_fn {
        syn::Lit::Str(lit_str) => {
            return format_ident!("{}", lit_str.value());
        }
        _ => panic!("default_fn must be the function name as a String."),
    })
}

pub(crate) fn get_start_version(attrs: &HashMap<String, syn::Lit>) -> Option<u16> {
    if let Some(start_version) = attrs.get(START_VERSION) {
        return Some(match start_version {
            syn::Lit::Int(lit_int) => lit_int.base10_parse().unwrap(),
            _ => panic!("Field start/end version number must be an integer"),
        });
    }
    None
}

pub(crate) fn get_end_version(attrs: &HashMap<String, syn::Lit>) -> Option<u16> {
    if let Some(start_version) = attrs.get(END_VERSION) {
        return Some(match start_version {
            syn::Lit::Int(lit_int) => lit_int.base10_parse().unwrap(),
            _ => panic!("Field start/end version number must be an integer"),
        });
    }
    None
}

// Parses field annotations.
pub(crate) fn parse_field_attributes(
    attrs: &mut HashMap<String, syn::Lit>,
    attributes: &Vec<syn::Attribute>,
) {
    for nested_attr in attributes
        .iter()
        .flat_map(|attr| -> Result<Vec<syn::NestedMeta>, ()> {
            if !attr.path.is_ident("snapshot") {
                return Ok(Vec::new());
            }

            if let Ok(syn::Meta::List(meta)) = attr.parse_meta() {
                return Ok(meta.nested.into_iter().collect());
            }

            Ok(Vec::new())
        })
        .flatten()
    {
        if let syn::NestedMeta::Meta(nested_meta) = nested_attr {
            if let syn::Meta::NameValue(attr_name_value) = nested_meta {
                attrs.insert(
                    attr_name_value.path.segments[0].ident.to_string(),
                    attr_name_value.lit,
                );
            }
        }
    }
}

pub fn is_array(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Array(_) => true,
        _ => false,
    }
}

// Compute current struct version.
pub(crate) fn compute_version<T>(fields: &Vec<T>) -> u16
where
    T: Exists,
{
    let mut version = 0;
    for field in fields {
        version = max(version, max(field.start_version(), field.end_version()));
    }
    version
}

pub(crate) fn generate_deserializer_header<T>(fields: &Vec<T>) -> proc_macro2::TokenStream
where
    T: FieldType,
{
    // Just checking if there are any array fields present.
    // If so, include the vec2array macro.
    if let Some(_) = fields.iter().find(|&field| is_array(&field.ty())) {
        return quote! {
            use std::convert::TryInto;

            // This macro will generate a function that copies a vec to an array.
            // We serialize arrays as vecs.
            macro_rules! vec_to_arr_func {
                ($name:ident, $type:ty, $size:expr) => {
                    pub fn $name(data: &std::vec::Vec<$type>) -> [$type; $size] {
                        let mut arr = [<$type as Default>::default(); $size];
                        arr.copy_from_slice(&data[0..$size]);
                        arr
                    }
                };
            }
        };
    }

    quote! {}
}
