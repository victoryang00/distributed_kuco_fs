extern crate proc_macro;
extern crate proc_macro2;
#[macro_use]
extern crate syn;
#[macro_use]
extern crate quote;

use proc_macro::TokenStream;

mod datablock_array;
mod datablock_derive;

use syn::LitInt;
use datablock_array::*;
use datablock_derive::*;

#[proc_macro]
pub fn unsafe_impl_array(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as LitInt);
    process_array_decl(&input).unwrap_or_else(|x| { syn::Error::to_compile_error(&x) }).into()
}

#[proc_macro_derive(DataBlock, attributes(datablock))]
pub fn derive_datablock(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as syn::DeriveInput);
    process_derive_datablock(&input).unwrap_or_else(|x| { syn::Error::to_compile_error(&x)}).into()
}
