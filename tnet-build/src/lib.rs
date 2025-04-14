use std::fmt::Write;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub struct PacketScannerConfig {
    /// Source directories to scan
    pub src_dirs: Vec<PathBuf>,
    /// Output directory for generated code
    pub out_dir: PathBuf,
    /// Name of output file
    pub out_file: String,
    /// Whether to trigger a rebuild on source changes
    pub rerun_if_changed: bool,
}

impl Default for PacketScannerConfig {
    fn default() -> Self {
        Self {
            src_dirs: vec!["src".into()],
            out_dir: match std::env::var("OUT_DIR") {
                Ok(dir) => PathBuf::from(dir),
                Err(_) => PathBuf::from("target/generated"),
            },
            out_file: "tnet_packet.rs".to_string(),
            rerun_if_changed: true,
        }
    }
}

pub struct PacketScanner {
    config: PacketScannerConfig,
}
impl PacketScanner {
    pub fn new(config: PacketScannerConfig) -> Self {
        Self { config }
    }

    /// Scan directories for tpacket attributes and generate a TnetPacket implementation
    pub fn run(&self) -> io::Result<PathBuf> {
        if self.config.rerun_if_changed {
            for dir in &self.config.src_dirs {
                println!("cargo:rerun-if-changed={}", dir.display());
            }
            println!("cargo:rerun-if-changed=build.rs");
        }

        let temp_dir = std::env::temp_dir().join("tnet_registry");
        let trigger_file = temp_dir.join("tnet_rebuild_trigger");
        println!("cargo:rerun-if-changed={}", trigger_file.display());

        let mut rust_files = Vec::new();
        for dir in &self.config.src_dirs {
            self.collect_rust_files(dir, &mut rust_files)?;
        }

        self.clean_marker_files()?;

        let packet_types = self.find_packet_types(&rust_files)?;

        let cache_path = std::path::Path::new("target").join(".tnet_packet_cache.json");
        if let Ok(cache_json) = serde_json::to_string(&packet_types) {
            let _ = std::fs::create_dir_all("target");
            let _ = std::fs::write(&cache_path, cache_json);
        }

        let output_content = self.generate_tnet_packet_code(&packet_types);

        let out_dir = match std::env::var("OUT_DIR") {
            Ok(dir) => PathBuf::from(dir),
            Err(_) => self.config.out_dir.clone(),
        };

        fs::create_dir_all(&out_dir)?;

        let output_path = out_dir.join("tnet_packet.rs");
        println!(
            "cargo:warning=Writing TnetPacket to {}",
            output_path.display()
        );

        fs::write(&output_path, &output_content)?;

        println!(
            "cargo:rustc-env=TNET_PACKET_GENERATED_PATH={}",
            output_path.display()
        );

        Ok(output_path)
    }

    fn clean_marker_files(&self) -> io::Result<()> {
        // Clean temp directory markers
        let temp_dir = std::env::temp_dir().join("tnet_registry");
        if temp_dir.exists() {
            println!(
                "cargo:warning=Cleaning marker files in {}",
                temp_dir.display()
            );
            if let Ok(entries) = fs::read_dir(&temp_dir) {
                for entry in entries.flatten() {
                    if entry.path().extension().is_some_and(|ext| ext == "packet") {
                        let _ = fs::remove_file(entry.path());
                    }
                }
            }
        }

        // Clean target directory markers
        let target_dir = std::path::Path::new("target/.tpacket_markers");
        if target_dir.exists() {
            println!(
                "cargo:warning=Cleaning marker files in {}",
                target_dir.display()
            );
            if let Ok(entries) = fs::read_dir(target_dir) {
                for entry in entries.flatten() {
                    if entry.path().extension().is_some_and(|ext| ext == "marker") {
                        let _ = fs::remove_file(entry.path());
                    }
                }
            }
        }

        Ok(())
    }

    /// Find all Rust files in the given directory
    #[allow(clippy::only_used_in_recursion)]
    fn collect_rust_files(&self, dir: &Path, result: &mut Vec<PathBuf>) -> io::Result<()> {
        if dir.is_dir() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    self.collect_rust_files(&path, result)?;
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    result.push(path);
                }
            }
        }
        Ok(())
    }

    fn find_packet_types(&self, files: &[PathBuf]) -> io::Result<Vec<(String, String)>> {
        let mut packet_types = Vec::new();

        println!(
            "cargo:warning=Scanning {} files for packet types",
            files.len()
        );

        // Scan all Rust files and extract #[tpacket] structs
        for file in files {
            if let Ok(content) = fs::read_to_string(file) {
                if content.contains("#[tpacket") {
                    println!(
                        "cargo:warning=Found tpacket attribute in file: {}",
                        file.display()
                    );

                    // Extract struct names and custom names following #[tpacket]
                    let lines = content.lines().collect::<Vec<_>>();
                    for (i, line) in lines.iter().enumerate() {
                        if line.contains("#[tpacket") {
                            // Extract custom name from the attribute if present
                            let mut custom_name = None;
                            if line.contains("name =") {
                                if let Some(name_start) = line.find("name = \"") {
                                    if let Some(name_end) = line[name_start + 7..].find('\"') {
                                        custom_name = Some(
                                            line[name_start + 7..name_start + 7 + name_end]
                                                .to_string(),
                                        );
                                    }
                                }
                            }

                            // Look for struct definition in subsequent lines
                            if i + 1 < lines.len() {
                                let next_line = lines[i + 1];
                                if next_line.contains("struct ") {
                                    let parts: Vec<&str> = next_line.split("struct ").collect();
                                    if parts.len() > 1 {
                                        let struct_name_parts =
                                            parts[1].split_whitespace().collect::<Vec<_>>();
                                        if !struct_name_parts.is_empty() {
                                            let struct_name =
                                                struct_name_parts[0].trim_end_matches('{').trim();

                                            // Use custom name if provided, otherwise convert struct name to snake case
                                            let field_name = match custom_name {
                                                Some(name) => name,
                                                None => to_snake_case(struct_name),
                                            };

                                            // Try to construct the full type path based on file location
                                            let file_path = file.to_string_lossy();
                                            let module_path =
                                                if let Some(src_idx) = file_path.find("src/") {
                                                    let module_part = &file_path[src_idx + 4..];
                                                    let module_part = module_part
                                                        .trim_end_matches(".rs")
                                                        .replace('/', "::");
                                                    format!("crate::{}", module_part)
                                                } else {
                                                    "crate".to_string()
                                                };

                                            // If it's a mod.rs file, adjust the path
                                            let adjusted_path = if module_path.ends_with("::mod") {
                                                module_path.trim_end_matches("::mod").to_string()
                                            } else {
                                                module_path
                                            };

                                            let full_type =
                                                format!("{}::{}", adjusted_path, struct_name);

                                            // Add to packet types
                                            packet_types
                                                .push((field_name.clone(), full_type.clone()));

                                            // Also create a new marker file for this #[tpacket] struct
                                            self.create_marker_file(&field_name, &full_type)?;

                                            println!(
                                                "cargo:warning=Found packet: {} at {}",
                                                field_name, full_type
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Log the result
        println!(
            "cargo:warning=Total packet types found: {}",
            packet_types.len()
        );

        Ok(packet_types)
    }

    fn create_marker_file(&self, field_name: &str, full_type: &str) -> io::Result<()> {
        // Create temporary directory marker
        let temp_dir = std::env::temp_dir().join("tnet_registry");
        if !temp_dir.exists() {
            fs::create_dir_all(&temp_dir)?;
        }
        let temp_file = temp_dir.join(format!("{}.packet", field_name));

        // Store both the full path to the type and the field name
        let data = format!("{}|{}", full_type, field_name);
        fs::write(&temp_file, &data)?;

        // Also write to target directory for persistence
        let target_dir = PathBuf::from("target/.tpacket_markers");
        if !target_dir.exists() {
            fs::create_dir_all(&target_dir)?;
        }
        let target_file = target_dir.join(format!("{}.marker", field_name));
        fs::write(&target_file, &data)?;

        Ok(())
    }

    fn generate_tnet_packet_code(&self, packet_types: &[(String, String)]) -> String {
        let mut struct_fields = String::new();
        let mut default_fields = String::new();

        for (field_name, type_path) in packet_types {
            let field_ident = sanitize_identifier(field_name);

            writeln!(
                &mut struct_fields,
                r#"    /// Optional field for {} packets
                    #[serde(skip_serializing_if = "Option::is_none")]
                    pub {}: Option<{}>,
                    "#,
                field_name, field_ident, type_path
            )
            .unwrap();

            writeln!(&mut default_fields, "            {}: None,", field_ident).unwrap();
        }

        format!(
            r#"// This file is auto-generated. Do not edit manually.

                        /// Dynamic packet type that can contain registered packet types.
                        ///
                        /// This struct is automatically generated based on types marked with `#[tpacket]`.
                        #[derive(Debug, Clone, ::serde::Serialize, ::serde::Deserialize)]
                        pub struct TnetPacket {{
                            /// The packet header (e.g., "LOGIN", "CHAT", "ERROR")
                            pub header: String,

                            /// Standard packet body with common fields
                            pub body: ::tnet::packet::PacketBody,

                            {}
                        }}

                        impl ::std::default::Default for TnetPacket {{
                            fn default() -> Self {{
                                Self {{
                                    header: "OK".to_string(),
                                    body: ::tnet::packet::PacketBody::default(),
                                    {}
                                }}
                            }}
                        }}

                        impl TnetPacket {{
                            /// Creates a new TnetPacket with the specified header.
                            pub fn new(header: impl Into<String>) -> Self {{
                                Self {{
                                    header: header.into(),
                                    body: ::tnet::packet::PacketBody::default(),
                                    {}
                                }}
                            }}

                            /// Sends this packet to the specified socket.
                            ///
                            /// # Arguments
                            ///
                            /// * `socket` - The socket to send the packet to
                            ///
                            /// # Returns
                            ///
                            /// * `Result<(), ::tnet::errors::Error>` - Success or failure of the send operation
                            ///
                            /// # Errors
                            ///
                            /// Returns an error if sending the packet fails
                            pub async fn send_to<S: ::tnet::session::Session>(&self, socket: &mut ::tnet::asynch::socket::TSocket<S>) -> Result<(), ::tnet::errors::Error> {{
                                socket.send(self.clone()).await
                            }}

                            /// Sends this packet to multiple sockets.
                            ///
                            /// # Arguments
                            ///
                            /// * `sockets` - A slice of sockets to send the packet to
                            ///
                            /// # Returns
                            ///
                            /// * `Result<(), ::tnet::errors::Error>` - Success or failure of the send operation
                            ///
                            /// # Errors
                            ///
                            /// Returns an error if sending the packet fails for any socket
                            pub async fn send_batch<S: ::tnet::session::Session>(&self, sockets: &mut [&mut ::tnet::asynch::socket::TSocket<S>]) -> Result<(), ::tnet::errors::Error> {{
                                let mut errors = Vec::new();

                                for socket in sockets.iter_mut() {{
                                    if let Err(e) = socket.send(self.clone()).await {{
                                        errors.push(e);
                                    }}
                                }}

                                if errors.is_empty() {{
                                    Ok(())
                                }} else {{
                                    Err(::tnet::errors::Error::Broadcast(format!("Batch send errors: {{:?}}", errors)))
                                }}
                            }}
                        }}

                        impl ::tnet::packet::Packet for TnetPacket {{
                            fn header(&self) -> String {{
                                self.header.clone()
                            }}

                            fn body(&self) -> ::tnet::packet::PacketBody {{
                                self.body.clone()
                            }}

                            fn body_mut(&mut self) -> &mut ::tnet::packet::PacketBody {{
                                &mut self.body
                            }}

                            fn ok() -> Self {{
                                Self::new("OK")
                            }}

                            fn error(error: ::tnet::errors::Error) -> Self {{
                                let mut packet = Self::new("ERROR");
                                packet.body = ::tnet::packet::PacketBody::with_error_string(&error.to_string());
                                packet
                            }}

                            fn keep_alive() -> Self {{
                                Self::new("KEEPALIVE")
                            }}
                        }}

                        "#,
            struct_fields, default_fields, default_fields
        )
    }
}

/// Sanitize a field name to be a valid identifier
fn sanitize_identifier(name: &str) -> String {
    // List of Rust keywords that can't be used as identifiers
    let keywords = [
        "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn",
        "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref",
        "return", "self", "Self", "static", "struct", "super", "trait", "true", "type", "unsafe",
        "use", "where", "while", "async", "await", "dyn", "abstract", "become", "box", "do",
        "final", "macro", "override", "priv", "typeof", "unsized", "virtual", "yield", "try",
        "union",
    ];

    // Check if this is a Rust keyword
    for &keyword in &keywords {
        if name == keyword {
            return format!("{}_value", name);
        }
    }
    name.to_string()
}

/// Run a simple TNet packet scanner with default configuration.
///
/// This macro creates and runs a packet scanner with default settings:
/// - Scans the "src" directory
/// - Outputs to the Cargo OUT_DIR
/// - Triggers rebuilds when source files change
///
/// # Example
///
/// ```
/// ```
#[macro_export]
macro_rules! scan_packets {
    () => {
        let config = $crate::PacketScannerConfig::default();
        let scanner = $crate::PacketScanner::new(config);

        match scanner.run() {
            Ok(path) => {
                println!("cargo:warning=Generated TnetPacket at {}", path.display());
                println!(
                    "cargo:rustc-env=TNET_PACKET_GENERATED_PATH={}",
                    path.display()
                );
            }
            Err(e) => {
                println!("cargo:warning=Failed to generate TnetPacket: {}", e);

                // Create a minimal fallback file that only has header and body
                let out_dir = std::env::var("OUT_DIR").unwrap();
                let fallback_path = std::path::Path::new(&out_dir).join("tnet_packet.rs");

                let fallback_content = r#"// Fallback minimal TnetPacket implementation
                use tnet::packet::{Packet, PacketBody};
                use tnet::errors::Error;

                #[derive(Debug, Clone, ::serde::Serialize, ::serde::Deserialize)]
                pub struct TnetPacket {
                    pub header: String,
                    pub body: PacketBody,
                    // No packet-specific fields in fallback
                }

                impl ::std::default::Default for TnetPacket {
                    fn default() -> Self {
                        Self {
                            header: "OK".to_string(),
                            body: PacketBody::default(),
                        }
                    }
                }

                impl TnetPacket {
                    pub fn new(header: impl Into<String>) -> Self {
                        Self {
                            header: header.into(),
                            body: PacketBody::default(),
                        }
                    }
                }

                impl Packet for TnetPacket {
                    fn header(&self) -> String {
                        self.header.clone()
                    }

                    fn body(&self) -> PacketBody {
                        self.body.clone()
                    }

                    fn body_mut(&mut self) -> &mut PacketBody {
                        &mut self.body
                    }

                    fn ok() -> Self {
                        Self::new("OK")
                    }

                    fn error(error: Error) -> Self {
                        let mut packet = Self::new("ERROR");
                        packet.body = PacketBody::with_error_string(&error.to_string());
                        packet
                    }

                    fn keep_alive() -> Self {
                        Self::new("KEEPALIVE")
                    }
                }
                "#;

                if let Err(write_err) = std::fs::write(&fallback_path, fallback_content) {
                    println!(
                        "cargo:warning=Failed to write fallback TnetPacket: {}",
                        write_err
                    );
                } else {
                    println!(
                        "cargo:warning=Created fallback TnetPacket at {}",
                        fallback_path.display()
                    );
                    println!(
                        "cargo:rustc-env=TNET_PACKET_GENERATED_PATH={}",
                        fallback_path.display()
                    );
                }
            }
        }
    };
}

/// Run a TNet packet scanner with custom source directories.
///
/// # Arguments
///
/// * `$( $dir:expr ),*` - One or more directory paths to scan
///
#[macro_export]
macro_rules! scan_packets_from {
    ( $( $dir:expr ),* ) => {
        {
            use std::path::PathBuf;

            let mut dirs = Vec::new();
            $(
                dirs.push(PathBuf::from($dir));
            )*

            let config = $crate::PacketScannerConfig {
                src_dirs: dirs,
                ..Default::default()
            };

            let scanner = $crate::PacketScanner::new(config);

            match scanner.run() {
                Ok(path) => {
                    println!("cargo:warning=Generated TnetPacket at {}", path.display());
                    println!("cargo:rustc-env=TNET_PACKET_GENERATED_PATH={}", path.display());
                }
                Err(e) => {
                    println!("cargo:warning=Failed to generate TnetPacket: {}", e);
                }
            }
        }
    }
}

/// Create a complete build script for TNet packet processing.
///
/// This macro creates a full `main()` function that sets up the build environment
/// and runs the packet scanner.
///
/// # Arguments
///
/// * `$( $dir:expr ),*` - Optional directory paths to scan (defaults to "src")
///
/// # Example
///
/// ```
/// // Basic usage
/// tnet_build::build_script!();
///
/// // With custom directories
/// tnet_build::build_script!("src", "modules/packets");
/// ```
#[macro_export]
macro_rules! build_script {
    () => {
        fn main() {
            $crate::scan_packets!();
        }
    };

    ( $( $dir:expr ),* ) => {
        fn main() {
            $crate::scan_packets_from!($( $dir ),*);
        }
    }
}

/// Create a fully customized TNet packet scanner.
///
/// This macro allows for complete customization of the scanner configuration.
///
/// # Arguments
///
/// * `dirs` - A comma-separated list of directories to scan
/// * `out_dir` - Optional output directory (defaults to OUT_DIR environment variable)
/// * `out_file` - Optional output filename (defaults to "tnet_packet.rs")
/// * `rebuild` - Optional boolean to control rebuild triggers (defaults to true)
///
#[macro_export]
macro_rules! configure_scanner {
    (
        dirs: [ $( $dir:expr ),* $(,)? ]
        $(, out_dir: $out_dir:expr )?
        $(, out_file: $out_file:expr )?
        $(, rebuild: $rebuild:expr )?
        $(,)?
    ) => {
        {
            use std::path::PathBuf;

            let mut dirs = Vec::new();
            $(
                dirs.push(PathBuf::from($dir));
            )*

            let out_dir = PathBuf::from(
                $( $out_dir.to_string() )?
                #[allow(unused_variables)]
                $()?
                std::env::var("OUT_DIR").unwrap_or_else(|_| "target/generated".to_string())
            );

            let config = $crate::PacketScannerConfig {
                src_dirs: dirs,
                out_dir,
                out_file: $( $out_file.to_string() )? #[allow(unused_variables)] $()? String::from("tnet_packet.rs"),
                rerun_if_changed: $( $rebuild )? #[allow(unused_variables)] $()? true,
            };

            let scanner = $crate::PacketScanner::new(config);

            match scanner.run() {
                Ok(path) => {
                    println!("cargo:warning=Generated TnetPacket at {}", path.display());
                    println!("cargo:rustc-env=TNET_PACKET_GENERATED_PATH={}", path.display());
                }
                Err(e) => {
                    println!("cargo:warning=Failed to generate TnetPacket: {}", e);
                }
            }
        }
    };
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
