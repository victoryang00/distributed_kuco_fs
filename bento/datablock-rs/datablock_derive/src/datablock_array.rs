use syn::{LitInt, Result};
use std::str::FromStr;
use proc_macro2::TokenStream;

fn generate_array_impl(n: usize) -> String {
    format!("unsafe impl<T : DataBlock> DataBlock for [T; {}] {{}}", n)
}

pub fn process_array_decl(input: &LitInt) -> Result<TokenStream> {
    let n : usize = input.base10_parse::<usize>()?;
    let mut result = String::new();
    for i in 1..n+1 {
        result.push_str(&generate_array_impl(i));
    }
    TokenStream::from_str(&result).map_err(|e| { e.into() })
}