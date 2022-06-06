use syn::{Result, DeriveInput, Data};
use proc_macro2::TokenStream;
use syn::punctuated::Iter;

fn collect_type_from_field_iter(ty_list: &mut Vec<syn::Type>, iter: Iter<syn::Field>) {
    iter.map(|f| { ty_list.push(f.ty.clone()) }).collect()
}

fn collect_type_from_fields(ty_list: &mut Vec<syn::Type>, fields: &syn::Fields) {
    match fields {
        syn::Fields::Named(fs) => collect_type_from_field_iter(ty_list, fs.named.iter()),
        syn::Fields::Unnamed(fs) => collect_type_from_field_iter(ty_list, fs.unnamed.iter()),
        _ => (),
    }
}

pub fn process_derive_datablock(input: &DeriveInput) -> Result<TokenStream> {
    let mut type_deps = Vec::new();
    match &input.data {
        Data::Struct(syn::DataStruct { fields, .. }) =>
            collect_type_from_fields(&mut type_deps, fields),
        Data::Enum(syn::DataEnum { variants, .. }) =>
            variants.iter().map(|v| { collect_type_from_fields(&mut type_deps, &v.fields) }).collect(),
        Data::Union(syn::DataUnion { fields, ..}) =>
            collect_type_from_field_iter(&mut type_deps, fields.named.iter()),
    }
    let struct_name = &input.ident;
    let (impl_generics, ty_generics, _generics_where) = input.generics.split_for_impl();
    let mut where_clause = quote! {};
    if type_deps.len() > 0 {
        let t = type_deps.iter();
        let b = type_deps.iter().map(|_t| {quote! {DataBlock}});
        where_clause = quote! {
            where 
                #(
                    #t : #b,
                )*
        };
    }
    let impl_block = quote! {
        unsafe impl#impl_generics DataBlock for #struct_name#ty_generics #where_clause {}
    };
    Ok(impl_block)
}