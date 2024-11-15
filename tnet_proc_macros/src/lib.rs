use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields};

#[proc_macro_derive(Packet)]
pub fn packet_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;

    let expanded = quote! {
        impl Packet for #name {
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }

            fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
                self
            }

            fn encode(&self) -> Vec<u8> {
                bincode::serialize(self).expect(&format!("Failed to encode packet: {}", std::any::type_name::<Self>()))
            }

            fn decode<T: DeserializeOwned>(data: &[u8]) -> T {
                bincode::deserialize(data).expect(&format!("Failed to decode packet: {}", std::any::type_name::<T>()))
            }
        }
    };

    TokenStream::from(expanded)
}

#[proc_macro_derive(Session, attributes(session_id))]
pub fn derive_session(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;

    // Look for field named "session_id"
    let id_field = if let Data::Struct(data) = &input.data {
        if let Fields::Named(fields) = &data.fields {
            fields.named.iter().find(|field| {
                if let Some(ident) = &field.ident {
                    ident == "session_id"
                } else {
                    false
                }
            })
        } else {
            None
        }
    } else {
        None
    };

    let get_id_impl = if let Some(_field) = id_field {
        quote! {
            fn get_id(&self) -> String {
                self.session_id.clone()
            }
        }
    } else {
        quote! {
            fn get_id(&self) -> String {
                format!("{:?}", self)
            }
        }
    };

    let expanded = quote! {
        impl Session for #name {
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }

            fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
                self
            }

            #get_id_impl
        }
    };

    TokenStream::from(expanded)
}
