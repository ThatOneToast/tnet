use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DataEnum, DeriveInput, Fields, parse_macro_input};

/// Automatically implements string conversion traits for an enum.
///
/// This derive macro implements the following traits for your enum:
///
/// - `std::fmt::Display`: Enables `.to_string()` on enum values
/// - `std::str::FromStr`: Enables string parsing via `.parse()`
/// - `From<&str>`: Enables conversion from string slices 
/// - `From<String>`: Enables conversion from owned strings
///
/// # How It Works
///
/// ## String Representation
///
/// Each enum variant is converted to and from a string using its exact variant name:
///
/// ```
/// # use tnet_macros::PacketHeader;
/// #[derive(Debug, Clone, PacketHeader)]
/// pub enum ExampleHeader {
///     Hello,
///     World,
/// }
///
/// // Convert to string
/// let header = ExampleHeader::Hello;
/// assert_eq!(header.to_string(), "Hello");
///
/// // Convert from string
/// let parsed: ExampleHeader = "World".parse().unwrap();
/// assert_eq!(parsed, ExampleHeader::World);
///
/// // From trait
/// let from_str = ExampleHeader::from("Hello");
/// let from_string = ExampleHeader::from(String::from("World"));
/// ```
///
/// ## Error Handling
///
/// When using `parse()`, a `Result` is returned:
/// - `Ok(EnumValue)` for successful parsing
/// - `Err(String)` with an error message for invalid strings
///
/// When using `From::from()` on invalid strings, it will panic with an error message.
///
/// # Limitations
///
/// - This derive macro only works on enums with unit variants (no fields)
/// - The string representation is case-sensitive
/// - Variant names must be valid Rust identifiers
///
/// # Example
///
/// ```
/// use tnet_macros::PacketHeader;
/// use std::str::FromStr;
///
/// #[derive(Debug, Clone, PacketHeader)]
/// pub enum PacketHeader {
///     OK,
///     ERROR,
///     KeepAlive,
/// }
///
/// fn main() {
///     // Display
///     let header = PacketHeader::OK;
///     println!("Header: {}", header); // Prints: Header: OK
///
///     // FromStr
///     let parsed = PacketHeader::from_str("ERROR").unwrap();
///     assert_eq!(parsed, PacketHeader::ERROR);
///
///     // From<&str>
///     let from_str = PacketHeader::from("KeepAlive");
///     assert_eq!(from_str, PacketHeader::KeepAlive);
///
///     // From<String>
///     let from_string = PacketHeader::from(String::from("OK"));
///     assert_eq!(from_string, PacketHeader::OK);
///
///     // Error handling with parse
///     let result = PacketHeader::from_str("Unknown");
///     assert!(result.is_err());
///     assert_eq!(result.unwrap_err(), "Unknown variant: Unknown");
/// }
/// ```
#[proc_macro_derive(PacketHeader)]
pub fn packet_header_derive(input: TokenStream) -> TokenStream {
    // Parse the input tokens into a syntax tree
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    // Extract enum variants
    let variants = match &input.data {
        Data::Enum(DataEnum { variants, .. }) => variants,
        _ => panic!("PacketHeader can only be derived for enums"),
    };

    // Generate match arms for to_string
    let to_string_arms = variants.iter().map(|variant| {
        let variant_name = &variant.ident;
        // Ensure variant has no fields
        match &variant.fields {
            Fields::Unit => {}
            _ => panic!("PacketHeader only supports unit variants"),
        }
        let variant_str = variant_name.to_string();
        quote! {
            #name::#variant_name => #variant_str.to_string()
        }
    });

    // Generate match arms for from_str
    let from_str_arms = variants.iter().map(|variant| {
        let variant_name = &variant.ident;
        let variant_str = variant_name.to_string();
        quote! {
            #variant_str => Ok(#name::#variant_name)
        }
    });

    // Generate the implementation
    let expanded = quote! {
        impl std::fmt::Display for #name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let s = match self {
                    #(#to_string_arms),*
                };
                write!(f, "{}", s)
            }
        }

        impl std::str::FromStr for #name {
            type Err = String;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    #(#from_str_arms),*,
                    _ => Err(format!("Unknown variant: {}", s))
                }
            }
        }

        impl From<&str> for #name {
            fn from(s: &str) -> Self {
                s.parse().unwrap_or_else(|e| panic!("{}", e))
            }
        }

        impl From<String> for #name {
            fn from(s: String) -> Self {
                s.as_str().into()
            }
        }
    };

    // Return the generated implementation
    expanded.into()
}
