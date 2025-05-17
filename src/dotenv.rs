use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead};
use std::path::Path;

/// Parses the content of a .env file and returns a HashMap of key-value pairs.
///
/// # Arguments
///
/// * `content` - A string slice that holds the content of the .env file.
///
/// # Returns
///
/// A `Result` containing a `HashMap<String, String>` with the parsed environment variables
/// or a `String` describing the error if parsing fails (e.g., I/O error).
///
/// # Behavior
///
/// - Ignores empty lines.
/// - Ignores lines starting with `#` (comments).
/// - Parses lines of the format `KEY=VALUE`.
/// - Keys and values are trimmed of leading/trailing whitespace.
/// - If a line contains an `=` but no key before it (e.g., `=VALUE`), it's ignored.
/// - If a line does not contain an `=`, it's ignored.
/// - Values can contain spaces.
pub fn parse_dotenv_content(content: &str) -> HashMap<String, String> {
    let mut env_map = HashMap::new();

    for line in content.lines() {
        let trimmed_line = line.trim();

        // Ignore empty lines and comments
        if trimmed_line.is_empty() || trimmed_line.starts_with('#') {
            continue;
        }

        // Find the first '=' separator
        if let Some(separator_index) = trimmed_line.find('=') {
            let (key_part, value_part) = trimmed_line.split_at(separator_index);
            let key = key_part.trim();

            // Ensure key is not empty
            if key.is_empty() {
                continue;
            }

            // The value part starts with '=', so we skip it.
            let value = value_part[1..].to_string().trim().to_string();

            env_map.insert(key.to_string(), value);
        }
        // Lines without '=' are ignored as per simple parsing requirements
    }

    env_map
}

/// Reads a .env file from the given path and parses its content.
///
/// # Arguments
///
/// * `path` - A reference to a `Path` object representing the .env file.
///
/// # Returns
///
/// A `Result` containing a `HashMap<String, String>` with the parsed environment variables
/// or an `io::Error` if the file cannot be read.
pub fn load_dotenv<P: AsRef<Path>>(path: P) -> io::Result<HashMap<String, String>> {
    let file = fs::File::open(path)?;
    let reader = io::BufReader::new(file);
    let mut content = String::new();

    for line_result in reader.lines() {
        let line = line_result?;
        content.push_str(&line);
        content.push('\n');
    }

    Ok(parse_dotenv_content(&content))
}
