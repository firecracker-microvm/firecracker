use quote::format_ident;
use std::collections::hash_map::HashMap;

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

// Parses field annotations.
pub(crate) fn parse_field_attributes(
    attrs: &mut HashMap<String, syn::Lit>,
    attributes: &Vec<syn::Attribute>,
) {
    for attribute in attributes {
        // Check if this is a snapshot attribute.
        match attribute.parse_meta().unwrap().clone() {
            syn::Meta::List(meta_list) => {
                // Check if this is a "snapshot" attribute.
                if meta_list.path.segments[0].ident.to_string() == "snapshot" {
                    // Fetch the specific attribute name
                    for nested_attribute in meta_list.nested {
                        match nested_attribute {
                            syn::NestedMeta::Meta(nested_meta) => {
                                match nested_meta {
                                    syn::Meta::NameValue(attr_name_value) => {
                                        // panic!("{:?}", attr_name_value);
                                        // if attr_name_value.eq_token.to_string() == "=" {
                                        attrs.insert(
                                            attr_name_value.path.segments[0].ident.to_string(),
                                            attr_name_value.lit,
                                        );
                                        // }
                                    }
                                    _ => {}
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            _ => {}
        }
    }
}
