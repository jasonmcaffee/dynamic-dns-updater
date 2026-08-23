use chrono::{SecondsFormat, Utc};

/// Writes an informational event in the stable format captured by Service Manager.
pub fn info(message: impl AsRef<str>) {
    println!("{} INFO  {}", timestamp(), message.as_ref());
}

/// Writes a warning event in the stable format captured by Service Manager.
pub fn warn(message: impl AsRef<str>) {
    eprintln!("{} WARN  {}", timestamp(), message.as_ref());
}

/// Writes an error event in the stable format captured by Service Manager.
pub fn error(message: impl AsRef<str>) {
    eprintln!("{} ERROR {}", timestamp(), message.as_ref());
}

/// Produces an RFC3339 UTC timestamp for every operational log line.
fn timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}
