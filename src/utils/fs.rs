//! File system utilities

#![allow(dead_code)] // Reserved for v0.6.0 features

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
    use tempfile::TempDir;

    #[test]
    fn test_get_extension() {
        assert_eq!(get_extension(Path::new("test.rs")), Some("rs"));
        assert_eq!(get_extension(Path::new("test.tar.gz")), Some("gz"));
        assert_eq!(get_extension(Path::new("noext")), None);
    }

    #[test]
    fn test_find_files_by_pattern() {
        let temp_dir = TempDir::new().unwrap();

        // Create test files
        std::fs::write(temp_dir.path().join("test.rs"), "content").unwrap();
        std::fs::write(temp_dir.path().join("main.rs"), "content").unwrap();
        std::fs::write(temp_dir.path().join("test.txt"), "content").unwrap();

        let files = find_files(temp_dir.path(), r"\.rs$").unwrap();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn test_find_files_recursive() {
        let temp_dir = TempDir::new().unwrap();
        let subdir = temp_dir.path().join("src");
        std::fs::create_dir_all(&subdir).unwrap();

        // Create files in subdirectory
        std::fs::write(subdir.join("lib.rs"), "content").unwrap();

        let files = find_files(temp_dir.path(), r"\.rs$").unwrap();
        assert_eq!(files.len(), 1);
    }

    #[test]
    fn test_read_file_limited_small_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        std::fs::write(&file_path, "Hello, World!").unwrap();

        let content = read_file_limited(&file_path, 1024).unwrap();
        assert_eq!(content, "Hello, World!");
    }

    #[test]
    fn test_read_file_limited_large_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        let large_content = "x".repeat(2000);
        std::fs::write(&file_path, &large_content).unwrap();

        let result = read_file_limited(&file_path, 1024);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));
    }

    #[test]
    fn test_read_file_limited_exact_size() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        let content = "x".repeat(1000);
        std::fs::write(&file_path, &content).unwrap();

        let read = read_file_limited(&file_path, 1000).unwrap();
        assert_eq!(read.len(), 1000);
    }

    #[test]
    fn test_find_files_no_matches() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::write(temp_dir.path().join("test.txt"), "content").unwrap();

        let files = find_files(temp_dir.path(), r"\.rs$").unwrap();
        assert!(files.is_empty());
    }

    #[test]
    fn test_find_files_complex_pattern() {
        let temp_dir = TempDir::new().unwrap();

        std::fs::write(temp_dir.path().join("test_rs.txt"), "content").unwrap();
        std::fs::write(temp_dir.path().join("test.rs"), "content").unwrap();

        let files = find_files(temp_dir.path(), r"test\.rs$").unwrap();
        assert_eq!(files.len(), 1);
    }
}
