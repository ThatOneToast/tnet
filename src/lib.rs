pub mod packet;
pub mod prelude;
pub mod session;
pub mod standard;

#[macro_export]
macro_rules! warn {
    ($title:expr, $fmt:literal, $($arg:tt)*) => {{
        use colored::*;
        eprintln!("{} {} - {}",
            "⚠".yellow().bold(),
            $title.yellow().bold(),
            format!($fmt, $($arg)*).yellow()
        );
    }};
    ($fmt:literal, $($arg:tt)*) => {{
        use colored::*;
        eprintln!("{} {} - {}",
            "⚠".yellow().bold(),
            "WARNING".yellow().bold(),
            format!($fmt, $($arg)*).yellow()
        );
    }};
    ($msg:expr) => {{
        use colored::*;
        eprintln!("{} {} - {}",
            "⚠".yellow().bold(),
            "WARNING".yellow().bold(),
            $msg.yellow()
        );
    }};
}
