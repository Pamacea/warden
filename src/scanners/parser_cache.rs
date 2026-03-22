//! Tree-sitter Parser Cache
//!
//! This module provides a caching mechanism for Tree-sitter parsers to avoid
//! reparsing the same file multiple times for different security checks.
//!
//! # Performance Benefits
//!
//! - Parse each source file only once per scan
//! - Reuse AST across multiple security rules
//! - Lazy initialization of language parsers
//! - Thread-safe access using Arc<Mutex<...>>
//!
//! # Example
//!
//! ```rust
//! use oalacea_warden::scanners::parser_cache::ParserCache;
//!
//! let cache = ParserCache::new();
//! let ast = cache.parse_file("src/main.rs")?;
//! // Run multiple checks on the same AST
//! ```

use once_cell::sync::Lazy;
use rayon::prelude::*;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tree_sitter::{Parser, Tree};

/// Supported programming languages for AST parsing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParserLanguage {
    Rust,
    JavaScript,
    TypeScript,
    Python,
    Go,
    Java,
    Php,
    C,
    Cpp,
}

impl ParserLanguage {
    /// Detect language from file extension
    pub fn from_path(path: &Path) -> Option<Self> {
        path.extension()
            .and_then(|ext| ext.to_str())
            .and_then(Self::from_extension)
    }

    /// Get language from file extension
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext {
            "rs" => Some(ParserLanguage::Rust),
            "js" | "jsx" | "mjs" => Some(ParserLanguage::JavaScript),
            "ts" | "tsx" => Some(ParserLanguage::TypeScript),
            "py" => Some(ParserLanguage::Python),
            "go" => Some(ParserLanguage::Go),
            "java" => Some(ParserLanguage::Java),
            "php" => Some(ParserLanguage::Php),
            "c" | "h" => Some(ParserLanguage::C),
            "cpp" | "cc" | "cxx" | "hpp" | "hh" | "hxx" => Some(ParserLanguage::Cpp),
            _ => None,
        }
    }

    /// Get file extensions for this language
    pub fn extensions(&self) -> &'static [&'static str] {
        match self {
            ParserLanguage::Rust => &["rs"],
            ParserLanguage::JavaScript => &["js", "jsx", "mjs"],
            ParserLanguage::TypeScript => &["ts", "tsx"],
            ParserLanguage::Python => &["py"],
            ParserLanguage::Go => &["go"],
            ParserLanguage::Java => &["java"],
            ParserLanguage::Php => &["php"],
            ParserLanguage::C => &["c", "h"],
            ParserLanguage::Cpp => &["cpp", "cc", "cxx", "hpp", "hh", "hxx"],
        }
    }

    /// Get the tree-sitter language for this parser
    fn tree_sitter_language(&self) -> &'static tree_sitter::Language {
        // Store the language objects in static variables to get 'static references
        use once_cell::sync::Lazy;

        static RUST_LANG: Lazy<tree_sitter::Language> = Lazy::new(tree_sitter_rust::language);
        static JS_LANG: Lazy<tree_sitter::Language> = Lazy::new(tree_sitter_javascript::language);
        static TS_LANG: Lazy<tree_sitter::Language> = Lazy::new(tree_sitter_typescript::language_typescript);
        static PYTHON_LANG: Lazy<tree_sitter::Language> = Lazy::new(tree_sitter_python::language);

        match self {
            ParserLanguage::Rust => &RUST_LANG,
            ParserLanguage::JavaScript => &JS_LANG,
            ParserLanguage::TypeScript => &TS_LANG,
            ParserLanguage::Python => &PYTHON_LANG,
            ParserLanguage::Go => unimplemented!("Go parser not yet integrated"),
            ParserLanguage::Java => unimplemented!("Java parser not yet integrated"),
            ParserLanguage::Php => unimplemented!("PHP parser not yet integrated"),
            ParserLanguage::C => unimplemented!("C parser not yet integrated"),
            ParserLanguage::Cpp => unimplemented!("C++ parser not yet integrated"),
        }
    }
}

/// Cached parse result for a single file
#[derive(Debug, Clone)]
pub struct CachedParse {
    /// Path to the parsed file
    pub path: PathBuf,
    /// Language detected
    pub language: ParserLanguage,
    /// The parsed AST tree
    pub tree: Option<Tree>,
    /// Source code content
    pub content: String,
    /// When this cache entry was created
    pub cached_at: std::time::Instant,
}

impl CachedParse {
    /// Create a new cached parse result
    pub fn new(path: PathBuf, language: ParserLanguage, content: String, tree: Option<Tree>) -> Self {
        Self {
            path,
            language,
            tree,
            content,
            cached_at: std::time::Instant::now(),
        }
    }

    /// Get the age of this cache entry
    pub fn age(&self) -> std::time::Duration {
        self.cached_at.elapsed()
    }

    /// Check if this cache entry is still valid (younger than max_age)
    pub fn is_valid(&self, max_age: std::time::Duration) -> bool {
        self.age() < max_age
    }
}

/// Thread-safe parser cache
///
/// Maintains a cache of parsed AST trees and their source code,
/// allowing multiple security checks to reuse the same parse results.
pub struct ParserCache {
    /// Cache of parsed files
    cache: Arc<Mutex<HashMap<PathBuf, CachedParse>>>,
    /// Maximum age for cache entries
    max_age: std::time::Duration,
    /// Maximum cache size
    max_size: usize,
}

impl ParserCache {
    /// Create a new parser cache with default settings
    pub fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
            max_age: std::time::Duration::from_secs(300), // 5 minutes
            max_size: 1000, // Maximum 1000 cached files
        }
    }

    /// Create a new parser cache with custom settings
    pub fn with_settings(max_age: std::time::Duration, max_size: usize) -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
            max_age,
            max_size,
        }
    }

    /// Parse a file and cache the result
    pub fn parse_file(&self, path: impl AsRef<Path>) -> anyhow::Result<Option<Arc<CachedParse>>> {
        let path = path.as_ref();

        // Check cache first
        {
            let cache = self.cache.lock().unwrap();
            if let Some(cached) = cache.get(path) {
                if cached.is_valid(self.max_age) {
                    return Ok(Some(Arc::new(cached.clone())));
                }
            }
        }

        // Read file content
        let content = std::fs::read_to_string(path)?;

        // Detect language
        let language = match ParserLanguage::from_path(path) {
            Some(lang) => lang,
            None => return Ok(None), // Unsupported language
        };

        // Parse with tree-sitter
        let tree = self.parse_with_language(&content, language)?;

        // Create cached entry
        let cached = CachedParse::new(path.to_path_buf(), language, content, tree);

        // Update cache (with size management)
        {
            let mut cache = self.cache.lock().unwrap();

            // Evict old entries if cache is too large
            if cache.len() >= self.max_size {
                self.evict_old_entries(&mut cache);
            }

            cache.insert(path.to_path_buf(), cached);
        }

        // Return the cached entry
        let cache = self.cache.lock().unwrap();
        Ok(cache.get(path).map(|c| Arc::new(c.clone())))
    }

    /// Parse content with a specific language
    fn parse_with_language(&self, content: &str, language: ParserLanguage) -> anyhow::Result<Option<Tree>> {
        let mut parser = Parser::new();
        parser.set_language(language.tree_sitter_language())
            .map_err(|e| anyhow::anyhow!("Failed to set language: {}", e))?;

        let tree = parser.parse(content, None);
        Ok(tree)
    }

    /// Evict old entries from the cache
    fn evict_old_entries(&self, cache: &mut HashMap<PathBuf, CachedParse>) {
        // Remove expired entries
        cache.retain(|_, cached| cached.is_valid(self.max_age));

        // If still too large, remove oldest entries
        if cache.len() >= self.max_size {
            // Collect paths to remove first to avoid borrow issues
            let mut entries: Vec<(PathBuf, std::time::Instant)> = cache.iter()
                .map(|(path, cached)| (path.clone(), cached.cached_at))
                .collect();
            entries.sort_by_key(|(_, time)| *time);

            // Remove oldest 20% of entries
            let to_remove = (cache.len() / 5).max(1);
            for (path, _) in entries.into_iter().take(to_remove) {
                cache.remove(&path);
            }
        }
    }

    /// Clear the entire cache
    pub fn clear(&self) {
        let mut cache = self.cache.lock().unwrap();
        cache.clear();
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let cache = self.cache.lock().unwrap();
        let total_entries = cache.len();
        let valid_entries = cache.values().filter(|c| c.is_valid(self.max_age)).count();
        let oldest_entry = cache.values().map(|c| c.age()).max();

        CacheStats {
            total_entries,
            valid_entries,
            max_size: self.max_size,
            oldest_entry_age: oldest_entry,
        }
    }

    /// Parse multiple files in parallel using rayon
    pub fn parse_files_parallel(&self, paths: &[PathBuf]) -> Vec<(PathBuf, anyhow::Result<Option<Arc<CachedParse>>>)> {
        paths.par_iter()
            .map(|path| {
                let result = self.parse_file(path);
                (path.clone(), result)
            })
            .collect()
    }

    /// Run a query on a cached parse tree
    ///
    /// Returns captured node byte ranges matching the query pattern
    pub fn query(
        &self,
        cached: &CachedParse,
        query_source: &str,
    ) -> anyhow::Result<Vec<std::ops::Range<usize>>> {
        let tree = cached.tree.as_ref().ok_or_else(|| {
            anyhow::anyhow!("No parse tree available for {}", cached.path.display())
        })?;

        let language = cached.language.tree_sitter_language();
        let query = tree_sitter::Query::new(language, query_source)?;

        let mut query_cursor = tree_sitter::QueryCursor::new();
        let matches = query_cursor.matches(&query, tree.root_node(), cached.content.as_bytes());

        // Collect captured node byte ranges from matches
        let mut ranges = Vec::new();
        for m in matches {
            for capture in m.captures {
                let node = capture.node;
                ranges.push(node.byte_range());
            }
        }

        Ok(ranges)
    }
}

impl Default for ParserCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Total number of entries in cache
    pub total_entries: usize,
    /// Number of valid (non-expired) entries
    pub valid_entries: usize,
    /// Maximum cache size
    pub max_size: usize,
    /// Age of the oldest entry
    pub oldest_entry_age: Option<std::time::Duration>,
}

impl CacheStats {
    /// Calculate cache hit rate (placeholder - would need tracking)
    pub fn utilization(&self) -> f64 {
        if self.max_size == 0 {
            0.0
        } else {
            self.total_entries as f64 / self.max_size as f64
        }
    }
}

impl std::fmt::Display for CacheStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Cache: {}/{} entries ({}% utilized)",
            self.valid_entries,
            self.max_size,
            (self.utilization() * 100.0) as u32
        )
    }
}

/// Global parser cache instance
static GLOBAL_CACHE: Lazy<ParserCache> = Lazy::new(ParserCache::new);

/// Get the global parser cache instance
pub fn global_cache() -> &'static ParserCache {
    &GLOBAL_CACHE
}

/// Convenience function to parse a file using the global cache
pub fn parse_file_cached(path: impl AsRef<Path>) -> anyhow::Result<Option<Arc<CachedParse>>> {
    global_cache().parse_file(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_language_detection() {
        assert_eq!(ParserLanguage::from_extension("rs"), Some(ParserLanguage::Rust));
        assert_eq!(ParserLanguage::from_extension("js"), Some(ParserLanguage::JavaScript));
        assert_eq!(ParserLanguage::from_extension("ts"), Some(ParserLanguage::TypeScript));
        assert_eq!(ParserLanguage::from_extension("py"), Some(ParserLanguage::Python));
        assert_eq!(ParserLanguage::from_extension("unknown"), None);
    }

    #[test]
    fn test_parser_cache_creation() {
        let cache = ParserCache::new();
        let stats = cache.stats();
        assert_eq!(stats.total_entries, 0);
        assert_eq!(stats.max_size, 1000);
    }

    #[test]
    fn test_parser_cache_custom_settings() {
        let cache = ParserCache::with_settings(
            std::time::Duration::from_secs(60),
            100,
        );
        let stats = cache.stats();
        assert_eq!(stats.max_size, 100);
    }

    #[test]
    fn test_parser_cache_clear() {
        let cache = ParserCache::new();
        cache.clear();
        let stats = cache.stats();
        assert_eq!(stats.total_entries, 0);
    }

    #[test]
    fn test_cached_parse_validation() {
        let cached = CachedParse::new(
            PathBuf::from("/test.rs"),
            ParserLanguage::Rust,
            "fn main() {}".to_string(),
            None,
        );

        // Should be valid for a fresh cache
        assert!(cached.is_valid(std::time::Duration::from_secs(1)));

        // Should be invalid for a very short max_age
        assert!(!cached.is_valid(std::time::Duration::from_nanos(1)));
    }

    #[test]
    fn test_cache_stats_utilization() {
        let stats = CacheStats {
            total_entries: 500,
            valid_entries: 450,
            max_size: 1000,
            oldest_entry_age: Some(std::time::Duration::from_secs(10)),
        };

        assert_eq!(stats.utilization(), 0.5);
    }

    #[test]
    fn test_global_cache() {
        let cache = global_cache();
        let stats = cache.stats();
        // Global cache should be initialized
        assert_eq!(stats.max_size, 1000);
    }
}
