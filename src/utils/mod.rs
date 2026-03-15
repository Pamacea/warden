//! Utility functions

pub mod network;
pub mod fs;
pub mod templates;
pub mod update;

// Re-export commonly used utility functions for test compatibility
#[allow(unused_imports)]
pub use network::validate_url;
#[allow(unused_imports)]
pub use fs::{find_files, get_extension, read_file_limited};
#[allow(unused_imports)]
pub use templates::{generate_review_prompt, report_filename};
#[allow(unused_imports)]
pub use update::{check_latest_version_blocking, update_warden};
