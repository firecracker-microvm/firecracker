// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![warn(clippy::pedantic)]

extern crate proc_macro;
use quote::quote;
use syn::parse_quote;

/// Adds `log::trace!` events at the start and end of an attributed function.
///
/// # Panics
///
/// When applied to anything other than a function.
#[proc_macro_attribute]
pub fn instrument(
    _attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let input = syn::parse_macro_input!(item as syn::Item);

    let syn::Item::Fn(mut item_fn) = input else {
        panic!("Instrument macro can only be on functions.")
    };

    let clippy_attr: syn::Attribute = parse_quote! {
        #[allow(clippy::items_after_statements)]
    };
    item_fn.attrs.push(clippy_attr);

    let item_fn_ident = item_fn.sig.ident.to_string();
    let new_stmt: syn::Stmt =
        parse_quote! { let __ = log_instrument::__Instrument::new(#item_fn_ident); };
    item_fn.block.stmts.insert(0, new_stmt);

    let out = quote! { #item_fn };
    proc_macro::TokenStream::from(out)
}
