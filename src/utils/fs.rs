//! File system utilities

use anyhow::Result;
use std::path::{Path, PathBuf};

/// Find files matching a pattern in a directory
pub fn find_files(dir: &Path, pattern: &str) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let pattern_regex = regex::Regex::new(pattern)?;

    for entry in walkdir::WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();

        if path.is_file() {
            if let Some(file_name) = path.file_name() {
                if pattern_regex.is_match(file_name.to_string_lossy().as_ref()) {
                    files.push(path.to_path_buf());
                }
            }
        }
    }

    Ok(files)
}

/// Read file contents with size limit
pub fn read_file_limited(path: &Path, max_size: usize) -> Result<String> {
    use std::fs::File;
    use std::io::Read;

    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    let file_size = metadata.len() as usize;

    if file_size > max_size {
        anyhow::bail!("File too large: {} bytes (max: {})", file_size, max_size);
    }

    let mut content = String::with_capacity(file_size);
    file.read_to_string(&mut content)?;

    Ok(content)
}

/// Get the file extension
pub fn get_extension(path: &Path) -> Option<&str> {
    path.extension()?.to_str()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_extension() {
        assert_eq!(get_extension(Path::new("test.rs")), Some("rs"));
        assert_eq!(get_extension(Path::new("test.tar.gz")), Some("gz"));
        assert_eq!(get_extension(Path::new("noext")), None);
    }
}
