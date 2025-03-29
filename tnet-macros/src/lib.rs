#![allow(unused_imports)]
#![allow(unused)]

use once_cell::sync::Lazy;
use std::sync::Mutex;

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{
    Attribute, Data, DataEnum, DeriveInput, Fields, FieldsNamed, Ident, ItemFn, ItemStruct, Lit,
    LitStr, Meta, Token, Visibility,
    parse::{Parse, ParseStream, Result},
    parse_macro_input,
    punctuated::Punctuated,
};

#[proc_macro]
pub fn register_scan_dir(_input: TokenStream) -> TokenStream {
    // Get the current directory
    let current_dir = std::env::current_dir().unwrap_or_default();
    let src_dir = current_dir.join("src");

    // Output the cargo directive to set TNET_SCAN_DIRS
    let output = format!(
        r#"
    println!("cargo:rustc-env=TNET_SCAN_DIRS={{}}", {});
    "#,
        src_dir.display().to_string().escape_debug()
    );

    output.parse().unwrap()
}

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
/// fn test() {
///     // Display
///     let header = ParseEnumString::OK;
///     println!("Header: {}", header); // Prints: Header: OK
///
///     // FromStr
///     let parsed = ParseEnumString::from_str("ERROR").unwrap();
///     assert_eq!(parsed, ParseEnumString::ERROR);
///
///     // From<&str>
///     let from_str = ParseEnumString::from("KeepAlive");
///     assert_eq!(from_str, ParseEnumString::KeepAlive);
///
///     // From<String>
///     let from_string = ParseEnumString::from(String::from("OK"));
///     assert_eq!(from_string, ParseEnumString::OK);
///
///     // Error handling with parse
///     let result = ParseEnumString::from_str("Unknown");
///     assert!(result.is_err());
///     assert_eq!(result.unwrap_err(), "Unknown variant: Unknown");
/// }
/// ```
#[proc_macro_derive(ParseEnumString)]
pub fn parse_enum_string(input: TokenStream) -> TokenStream {
    // Parse the input tokens into a syntax tree
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    // Extract enum variants
    let variants = match &input.data {
        Data::Enum(DataEnum { variants, .. }) => variants,
        _ => panic!("ParseEnumString can only be derived for enums"),
    };

    // Generate match arms for to_string
    let to_string_arms = variants.iter().map(|variant| {
        let variant_name = &variant.ident;
        // Ensure variant has no fields
        match &variant.fields {
            Fields::Unit => {}
            _ => panic!("ParseEnumString only supports unit variants"),
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

/// Registers a function as a packet handler for a specific packet type.
///
/// This attribute macro allows you to define handler functions for specific packet types
/// without manually registering them. The macro automatically registers the function
/// with the global handler registry during application initialization.
///
/// # Arguments
///
/// * A string literal representing the packet type (packet header) this function handles
///
/// # Handler Function Requirements
///
/// The function must have the following signature:
///
/// ```
/// async fn handler_name(
///     sources: HandlerSources<YourSessionType, YourResourceType>,
///     packet: YourPacketType
/// ) {
///     // Handler implementation
/// }
/// ```
///
/// Where:
/// * `HandlerSources` contains the socket, connection pools, and resources
/// * `YourSessionType` implements the `Session` trait
/// * `YourResourceType` implements the `Resource` trait
/// * `YourPacketType` implements the `Packet` trait
///
/// # How It Works
///
/// When the application starts up, all functions with this attribute will be registered in
/// the global handler registry. When a packet with the specified header is received, the
/// `AsyncListener` will look up the appropriate handler in the registry and dispatch the
/// packet to it.
///
/// If no handler is found for a packet type, the default handler passed to `AsyncListener::new()`
/// will be used.
///
/// # Type Safety
///
/// The macro ensures type safety by preserving the generic type parameters of your handler.
/// This means you can have different handlers for the same packet header but with different
/// session, resource, or packet types - they will be properly distinguished at runtime.
///
/// # Example
///
/// ```rust
/// use tnet::prelude::*;
///
/// // Define packet, session, and resource types
/// struct MyPacket { /* ... */ }
/// struct MySession { /* ... */ }
/// struct MyResource { /* ... */ }
///
/// #[tlisten_for("LOGIN")]
/// async fn handle_login(
///     sources: HandlerSources<MySession, MyResource>,
///     packet: MyPacket
/// ) {
///     let mut socket = sources.socket;
///     println!("Handling login packet");
///
///     // Process login logic
///     // ...
///
///     // Send response
///     socket.send(MyPacket::ok()).await.unwrap();
/// }
///
/// #[tlisten_for("CHAT")]
/// async fn handle_chat(
///     sources: HandlerSources<MySession, MyResource>,
///     packet: MyPacket
/// ) {
///     let mut socket = sources.socket;
///     let pools = sources.pools;
///
///     // Process chat message
///     // ...
///
///     // Broadcast to other users
///     pools.broadcast_to("chat_room", packet.clone()).await.unwrap();
/// }
/// ```
///
/// # Multiple Handlers for the Same Packet Type
///
/// You can register multiple handlers for the same packet type. The first one registered
/// will be used:
///
/// ```rust
/// // This handler will be used for regular users
/// #[tlisten_for("ADMIN_COMMAND")]
/// async fn handle_admin_command_for_regular_users(
///     sources: HandlerSources<RegularUserSession, MyResource>,
///     packet: MyPacket
/// ) {
///     // Deny access for regular users
///     sources.socket.send(MyPacket::error(Error::AccessDenied)).await.unwrap();
/// }
///
/// // This handler will be used for admin users
/// #[tlisten_for("ADMIN_COMMAND")]
/// async fn handle_admin_command_for_admins(
///     sources: HandlerSources<AdminUserSession, MyResource>,
///     packet: MyPacket
/// ) {
///     // Process admin command
///     // ...
/// }
/// ```
///
/// # Combining with Packet Header Enums
///
/// For better type safety, you can use this macro with the `PacketHeader` derive macro:
///
/// ```rust
/// #[derive(Debug, Clone, PacketHeader)]
/// enum MyHeaders {
///     Login,
///     Chat,
///     Logout,
/// }
///
/// #[tlisten_for("Login")]
/// async fn handle_login(sources: HandlerSources<MySession, MyResource>, packet: MyPacket) {
///     // Login handling logic
/// }
///
/// #[tlisten_for("Chat")]
/// async fn handle_chat(sources: HandlerSources<MySession, MyResource>, packet: MyPacket) {
///     // Chat handling logic
/// }
///
/// // In your packet implementation:
/// impl Packet for MyPacket {
///     fn header(&self) -> String {
///         self.header.to_string() // This will match what's in the tlisten_for attribute
///     }
///     // ... other implementations
/// }
/// ```
///
/// # Limitations
///
/// - The handler function must be `async`
/// - The handler function must be accessible where it's used (public or in the same module)
/// - The handler must accept exactly two parameters: `HandlerSources` and a packet type
/// - The packet header string is case-sensitive and must match exactly what's returned by `Packet::header()`
#[proc_macro_attribute]
pub fn tlisten_for(attr: TokenStream, item: TokenStream) -> TokenStream {
    let packet_type = parse_macro_input!(attr as LitStr).value();
    let input_fn = parse_macro_input!(item as ItemFn);
    let fn_name = &input_fn.sig.ident;

    // Generate a unique registration function name
    let register_fn_name = format_ident!("__tnet_register_{}", fn_name);

    // Extract the function's path for clarity in logs
    let fn_path = format!("{}::{}", module_path!(), fn_name);

    let expanded = quote! {
        // Keep the original function
        #input_fn

        // Create a unique module to avoid name conflicts
        #[doc(hidden)]
        #[allow(non_snake_case)]
        mod #register_fn_name {
            use super::*;
            use std::sync::OnceLock;

            // Using OnceLock for initialization
            static REGISTER: OnceLock<()> = OnceLock::new();

            #[ctor::ctor]
            fn register() {
                let _ = REGISTER.get_or_init(|| {
                    // Only register once
                    tnet::handler_registry::register_handler(
                        #packet_type,
                        |sources, packet| Box::pin(super::#fn_name(sources, packet))
                    );

                    // Optional: Log registration for debugging
                    #[cfg(debug_assertions)]
                    println!("Registered handler for {} at {}", #packet_type, #fn_path);

                    ()
                });
            }
        }
    };

    TokenStream::from(expanded)
}

struct TPacketArgs {
    name: Option<String>,
}

impl Parse for TPacketArgs {
    fn parse(input: ParseStream) -> Result<Self> {
        // If input is empty, return default
        if input.is_empty() {
            return Ok(TPacketArgs { name: None });
        }

        // Parse a literal string if that's all that's provided
        if input.peek(LitStr) {
            let lit: LitStr = input.parse()?;
            return Ok(TPacketArgs {
                name: Some(lit.value()),
            });
        }

        // Try to parse name = "value" format
        let lookahead = input.lookahead1();
        if lookahead.peek(Ident) {
            let ident: Ident = input.parse()?;
            if ident == "name" {
                let _: Token![=] = input.parse()?;
                let lit: LitStr = input.parse()?;
                return Ok(TPacketArgs {
                    name: Some(lit.value()),
                });
            }
            return Err(syn::Error::new(ident.span(), "Expected `name`"));
        }

        Err(lookahead.error())
    }
}

#[proc_macro_attribute]
pub fn tpacket(args: TokenStream, item: TokenStream) -> TokenStream {
    // Parse the struct
    let item_clone = item.clone();
    let input = parse_macro_input!(item_clone as ItemStruct);
    let struct_name = &input.ident;

    // Parse attribute arguments
    let args = parse_macro_input!(args as TPacketArgs);

    // Determine the field name
    let field_name = if let Some(name) = args.name {
        name
    } else {
        to_snake_case(&struct_name.to_string())
    };

    // Create an uppercase name for the constant
    let marker_name = format_ident!(
        "TNET_PACKET_MARKER_{}",
        struct_name.to_string().to_uppercase()
    );

    // Create a string value for the registration
    let marker_value = format!("{}={}", field_name, struct_name);

    // Create a unique function name for registration
    let register_fn_name = format_ident!(
        "__tnet_register_{}",
        to_snake_case(&struct_name.to_string())
    );

    let field_name_str = field_name.clone();
    let struct_name_str = struct_name.to_string();

    // Create the registration code
    let registration = quote! {
        #[doc(hidden)]
        #[allow(dead_code)]
        pub static #marker_name: &'static str = #marker_value;

        // Run at compile time to create marker files
        #[doc(hidden)]
        #[ctor::ctor]
        fn #register_fn_name() {
            // This function will be called when the program starts
            // Get the full module path at runtime
            let module_path = module_path!();

            // Create the full type path by combining module path with struct name
            let full_path = format!("{}::{}", module_path, #struct_name_str);

            // Create a marker file in the temporary directory
            let temp_dir = ::std::env::temp_dir().join("tnet_registry");
            let _ = ::std::fs::create_dir_all(&temp_dir);
            let temp_file = temp_dir.join(format!("{}.packet", #field_name_str));

            // Store both the full path to the type and the custom field name
            let data = format!("{}|{}", full_path, #field_name_str);
            let _ = ::std::fs::write(&temp_file, &data);

            // Also write to target directory for persistence
            let target_dir = ::std::path::Path::new("target/.tpacket_markers");
            let _ = ::std::fs::create_dir_all(target_dir);
            let target_file = target_dir.join(format!("{}.marker", #field_name_str));
            let _ = ::std::fs::write(&target_file, &data);
        }
    };

    // Always add the necessary derives
    let derive_tokens = quote! {
        #[derive(Debug, Clone, ::serde::Serialize, ::serde::Deserialize)]
    };

    // Combine everything and return
    let expanded = quote! {
        #derive_tokens
        #input
        #registration
    };

    TokenStream::from(expanded)
}

fn to_snake_case(s: &str) -> String {
    let mut result = String::new();
    let mut chars = s.chars().peekable();

    // Handle first character
    if let Some(c) = chars.next() {
        result.extend(c.to_lowercase());
    }

    // Process remaining characters
    for c in chars {
        if c.is_uppercase() {
            result.push('_');
            result.extend(c.to_lowercase());
        } else {
            result.push(c);
        }
    }

    result
}
