//! # Rust-Based File Deduplicator
//! 
//! A high-performance, parallel file deduplicator that can find exact and fuzzy duplicates
//! across different file types including images and text files.
//! 
//! ## Features
//! 
//! - **Parallel processing** for maximum performance
//! - **Multiple hash algorithms** (Blake3, SHA256, XXHash)
//! - **Fuzzy matching** for similar files
//! - **Smart caching** to avoid re-hashing unchanged files
//! - **Safe quarantine system** with restore capability
//! - **Detailed reporting** in JSON format
//! 
//! ## Usage
//! 
//! ```bash
//! # Basic usage
//! cargo run -- ./folder_to_scan
//! 
//! # With fuzzy matching
//! cargo run -- ./folder_to_scan --fuzzy
//! 
//! # Dry run (preview only)
//! cargo run -- ./folder_to_scan --dry-run --fuzzy
//! 
//! # Restore quarantined files
//! cargo run -- ./folder_to_scan --undo
//! ```

use walkdir::WalkDir;
use std::path::PathBuf;
use std::fs::File;
use std::io::{BufReader, Read};
use std::collections::HashMap;
use rayon::prelude::*;
use std::env;
use std::time::SystemTime;
use regex::Regex;
use serde::{Serialize, Deserialize};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use img_hash::{HasherConfig, HashAlg};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/// Configuration for file filtering during scanning
#[derive(Debug, Clone)]
pub struct FileFilter {
    /// Minimum file size in bytes (files smaller than this are ignored)
    pub min_size: Option<u64>,
    /// Maximum file size in bytes (files larger than this are ignored)
    pub max_size: Option<u64>,
    /// List of allowed file extensions (if None, all extensions are allowed)
    pub allowed_extensions: Option<Vec<String>>,
    /// Only process files modified after this timestamp
    pub modified_after: Option<SystemTime>,
}

/// Log entry for quarantined files to enable restoration
#[derive(Serialize, Deserialize, Debug, Clone)]
struct QuarantineLogEntry {
    /// Original file path before quarantine
    original: String,
    /// Path in quarantine directory
    quarantined: String,
}

/// Available hash algorithms for file comparison
#[derive(Debug, Clone)]
enum HashAlgo {
    /// Blake3 - Fast and secure (default)
    Blake3,
    /// SHA256 - Industry standard
    Sha256,
    /// XXHash - Extremely fast, less secure
    XxHash,
}

/// Represents a group of duplicate files in the JSON report
#[derive(Serialize, Debug)]
struct DuplicateGroup {
    /// Hash or identifier for this group
    hash: String,
    /// Similarity percentage (if calculated)
    similarity: Option<f64>,
    /// List of file paths in this group
    files: Vec<String>,
}

/// Complete deduplication report
#[derive(Serialize, Debug)]
struct FullReport {
    /// Total bytes that could be saved by removing duplicates
    saved_bytes: u64,
    /// Same as saved_bytes but in megabytes for readability
    saved_mb: f64,
    /// All duplicate groups found
    groups: Vec<DuplicateGroup>,
}

/// Cached file information to avoid re-hashing unchanged files
#[derive(Clone, Serialize, Deserialize, Debug)]
struct CachedFile {
    /// File path
    path: String,
    /// Last modified timestamp (Unix epoch seconds)
    modified: u64,
    /// File size in bytes
    size: u64,
    /// Computed hash value
    hash: String,
}

// ============================================================================
// CORE HASHING FUNCTIONS
// ============================================================================

/// Computes hash of a file using the specified algorithm
/// 
/// # Arguments
/// 
/// * `path` - Path to the file to hash
/// * `algo` - Hash algorithm to use
/// 
/// # Returns
/// 
/// * `Some(String)` - Hex-encoded hash if successful
/// * `None` - If file cannot be read or hashed
/// 
/// # Example
/// 
/// ```rust
/// let hash = hash_file(&PathBuf::from("test.txt"), &HashAlgo::Blake3);
/// ```
fn hash_file(path: &PathBuf, algo: &HashAlgo) -> Option<String> {
    let file = File::open(path).ok()?;
    let mut reader = BufReader::new(file);
    let mut buffer = [0u8; 8192]; // 8KB buffer for optimal I/O performance

    match algo {
        HashAlgo::Blake3 => {
            let mut hasher = blake3::Hasher::new();
            while let Ok(n) = reader.read(&mut buffer) {
                if n == 0 { break; }
                hasher.update(&buffer[..n]);
            }
            Some(hasher.finalize().to_hex().to_string())
        }
        HashAlgo::Sha256 => {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            while let Ok(n) = reader.read(&mut buffer) {
                if n == 0 { break; }
                hasher.update(&buffer[..n]);
            }
            Some(format!("{:x}", hasher.finalize()))
        }
        HashAlgo::XxHash => {
            use xxhash_rust::xxh3::Xxh3;
            let mut hasher = Xxh3::new();
            while let Ok(n) = reader.read(&mut buffer) {
                if n == 0 { break; }
                hasher.update(&buffer[..n]);
            }
            Some(format!("{:x}", hasher.digest()))
        }
    }
}

// ============================================================================
// FILE DISCOVERY AND COLLECTION
// ============================================================================

/// Recursively scans a directory for files matching the given criteria
/// 
/// This function walks through all subdirectories and applies the specified
/// filters to determine which files should be included in deduplication.
/// 
/// # Arguments
/// 
/// * `dir` - Root directory to scan
/// * `filter` - File filtering criteria
/// * `regex` - Optional regex pattern for filename matching
/// 
/// # Returns
/// 
/// Vector of PathBuf objects representing all files that passed the filters
/// 
/// # Example
/// 
/// ```rust
/// let filter = FileFilter {
///     min_size: Some(100),
///     max_size: None,
///     allowed_extensions: Some(vec!["txt".to_string(), "jpg".to_string()]),
///     modified_after: None,
/// };
/// let files = collect_files("./my_folder", &filter, None);
/// ```
fn collect_files(dir: &str, filter: &FileFilter, regex: Option<&Regex>) -> Vec<PathBuf> {
    println!("🔄 Scanning files recursively in {}...", dir);
    
    let mut results = Vec::new();
    
    for entry in WalkDir::new(dir) {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                eprintln!("❌ Error reading entry: {}", e);
                continue;
            }
        };
        
        let path = entry.path();

        // Skip quarantine directories and subdirectories
        if path.components().any(|c| c.as_os_str() == ".quarantine") {
            continue;
        }
        
        // Skip directories themselves
        if entry.file_type().is_dir() {
            continue;
        }

        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(e) => {
                eprintln!("❌ Failed to get metadata for {}: {}", path.display(), e);
                continue;
            }
        };
        
        let size = meta.len();

        // Apply size filters
        if let Some(min) = filter.min_size { 
            if size < min { continue; } 
        }
        if let Some(max) = filter.max_size { 
            if size > max { continue; } 
        }
        
        // Apply modification time filter
        if let Some(after) = filter.modified_after { 
            if let Ok(modified) = meta.modified() {
                if modified < after { continue; }
            }
        }
        
        // Apply extension filter
        if let Some(ref exts) = filter.allowed_extensions {
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                let file_ext = ext.to_lowercase();
                if !exts.contains(&file_ext) { continue; }
            } else {
                continue; // No extension but extensions are required
            }
        }
        
        // Apply regex filter
        if let Some(rgx) = regex {
            if !rgx.is_match(&entry.file_name().to_string_lossy()) { 
                continue; 
            }
        }

        results.push(path.to_path_buf());
    }
    
    println!("📊 Total files collected: {}", results.len());
    results
}

// ============================================================================
// DUPLICATE DETECTION
// ============================================================================

/// Groups files by their hash values using parallel processing and caching
/// 
/// This function is the core of the deduplication process. It:
/// 1. Loads cached hash values from previous runs
/// 2. Computes hashes for new or modified files in parallel
/// 3. Groups files with identical hashes
/// 4. Updates the cache for future runs
/// 
/// # Arguments
/// 
/// * `files` - Vector of file paths to process
/// * `algo` - Hash algorithm to use
/// 
/// # Returns
/// 
/// HashMap where keys are hash values and values are vectors of files with that hash
/// 
/// # Performance Notes
/// 
/// - Uses all available CPU cores for parallel hashing
/// - Maintains a cache file to avoid re-hashing unchanged files
/// - Progress is reported every 100 files processed
fn group_duplicates_parallel(files: Vec<PathBuf>, algo: &HashAlgo) -> HashMap<String, Vec<PathBuf>> {
    let args: Vec<String> = std::env::args().collect();
    let folder = args.get(1).expect("Please provide a folder path");
    let cache_path = format!("{}/.dedup_cache.json", folder);
    
    // Load existing cache
    let cache_map: HashMap<String, CachedFile> = std::fs::read_to_string(&cache_path)
        .ok()
        .and_then(|data| serde_json::from_str(&data).ok())
        .unwrap_or_default();
    
    let cache_map = Arc::new(cache_map);
    let new_cache = Arc::new(Mutex::new(HashMap::<String, CachedFile>::new()));
    let progress = Arc::new(AtomicUsize::new(0));
    let total = files.len();
    
    println!("🔄 Hashing {} files using {} threads...", total, rayon::current_num_threads());
    
    // Process files in parallel
    let results: Vec<((String, PathBuf), Option<CachedFile>)> = files
        .into_par_iter()
        .filter_map(|path| {
            let current = progress.fetch_add(1, Ordering::Relaxed);
            if current % 100 == 0 || current == total - 1 { 
                println!("📊 Progress: {}/{}", current + 1, total); 
            }

            let meta = path.metadata().ok()?;
            let modified = meta.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
            let size = meta.len();
            let path_str = path.display().to_string();

            // Check cache for existing hash
            if let Some(cached) = cache_map.get(&path_str) {
                if cached.modified == modified && cached.size == size {
                    // Cache hit - use existing hash
                    return Some(((cached.hash.clone(), path), None));
                }
            }

            // Cache miss - compute new hash
            let hash = hash_file(&path, algo)?;
            let cached_file = CachedFile { 
                path: path_str, 
                modified, 
                size, 
                hash: hash.clone() 
            };
            Some(((hash, path), Some(cached_file)))
        })
        .collect();

    // Update cache with new entries
    for ((_, _), cache_entry) in &results {
        if let Some(cached_file) = cache_entry {
            new_cache.lock().unwrap().insert(cached_file.path.clone(), cached_file.clone());
        }
    }

    // Group files by hash
    let mut groups: HashMap<String, Vec<PathBuf>> = HashMap::new();
    for ((hash, path), _) in results {
        groups.entry(hash).or_default().push(path);
    }

    // Save updated cache
    let _ = std::fs::write(cache_path, serde_json::to_string_pretty(&*new_cache.lock().unwrap()).unwrap());
    
    let duplicate_groups = groups.iter().filter(|(_, paths)| paths.len() > 1).count();
    println!("✅ Found {} duplicate groups", duplicate_groups);
    
    groups
}

// ============================================================================
// FUZZY MATCHING ALGORITHMS
// ============================================================================

/// Calculates the edit distance (Levenshtein distance) between two strings
/// 
/// This is used for fuzzy text comparison to determine how similar two text files are.
/// 
/// # Arguments
/// 
/// * `a` - First string
/// * `b` - Second string
/// 
/// # Returns
/// 
/// Number of single-character edits required to change `a` into `b`
/// 
/// # Algorithm
/// 
/// Uses dynamic programming with O(n*m) time complexity where n and m are string lengths.
fn edit_distance(a: &str, b: &str) -> usize {
    let mut dp = vec![vec![0; b.len() + 1]; a.len() + 1];
    
    // Initialize base cases
    for i in 0..=a.len() { dp[i][0] = i; }
    for j in 0..=b.len() { dp[0][j] = j; }

    // Fill DP table
    for (i, ca) in a.chars().enumerate() {
        for (j, cb) in b.chars().enumerate() {
            dp[i + 1][j + 1] = if ca == cb {
                dp[i][j] // No edit needed
            } else {
                1 + dp[i][j].min(dp[i + 1][j]).min(dp[i][j + 1]) // Min of insert, delete, replace
            };
        }
    }
    
    dp[a.len()][b.len()]
}

/// Finds groups of similar text files using fuzzy string matching
/// 
/// Compares all text files against each other using edit distance and groups
/// files that are similar above the specified threshold.
/// 
/// # Arguments
/// 
/// * `paths` - Vector of text file paths to compare
/// * `threshold` - Minimum similarity percentage (0.0 to 100.0)
/// 
/// # Returns
/// 
/// HashMap with fuzzy group identifiers as keys and file groups as values
/// 
/// # Algorithm
/// 
/// 1. Read and normalize all text files (handle line endings)
/// 2. Compare each file against all others using edit distance
/// 3. Group files that meet the similarity threshold
/// 4. Avoid double-counting files in multiple groups
fn fuzzy_text_match(paths: &[PathBuf], threshold: f64) -> HashMap<String, Vec<PathBuf>> {
    if paths.len() < 2 { return HashMap::new(); }

    println!("🔍 Fuzzy matching {} text files (threshold: {:.1}%)...", paths.len(), threshold);
    
    // Read and normalize all text files
    let contents: Vec<_> = paths
        .iter()
        .filter_map(|path| {
            match std::fs::read_to_string(path) {
                Ok(content) => {
                    // Normalize line endings and whitespace
                    let cleaned = content.replace("\r\n", "\n").trim().to_string();
                    Some((path.clone(), cleaned))
                }
                Err(e) => {
                    eprintln!("❌ Failed to read {}: {}", path.display(), e);
                    None
                }
            }
        })
        .collect();

    println!("📝 Successfully read {} text files", contents.len());

    let mut groups = Vec::new();
    let mut processed = std::collections::HashSet::new();

    // Compare each file against all others
    for (i, (path1, content1)) in contents.iter().enumerate() {
        if processed.contains(path1) { continue; }
        
        let mut group = vec![path1.clone()];
        
        for (path2, content2) in contents.iter().skip(i + 1) {
            if processed.contains(path2) { continue; }
            
            // Calculate similarity percentage
            let similarity = if content1 == content2 {
                100.0 // Identical content
            } else if content1.is_empty() && content2.is_empty() {
                100.0 // Both empty
            } else {
                let max_len = content1.len().max(content2.len()).max(1);
                let dist = edit_distance(content1, content2);
                100.0 - (dist as f64 * 100.0 / max_len as f64)
            };
            
            if similarity >= threshold {
                group.push(path2.clone());
                processed.insert(path2.clone());
            }
        }
        
        if group.len() > 1 {
            println!(" 📝 Fuzzy text group: {} files", group.len());
            for file in &group {
                println!("    - {}", file.display());
            }
            groups.push(group);
        }
        
        processed.insert(path1.clone());
    }

    // Convert to HashMap with unique keys
    groups.into_iter().enumerate()
        .map(|(i, group)| (format!("fuzzy_txt_{}", i), group))
        .collect()
}

/// Finds groups of visually similar images using perceptual hashing
/// 
/// Uses image perceptual hashing to find images that look similar even if
/// they have different file sizes, formats, or minor modifications.
/// 
/// # Arguments
/// 
/// * `paths` - Vector of image file paths to compare
/// * `threshold` - Maximum hash distance for similarity (lower = more similar)
/// 
/// # Returns
/// 
/// HashMap with fuzzy group identifiers as keys and image groups as values
/// 
/// # Algorithm
/// 
/// 1. Generate perceptual hashes for all images in parallel
/// 2. Compare hash distances between all image pairs
/// 3. Group images with hash distance below threshold
/// 4. Report similarity percentages based on bit differences
fn fuzzy_image_match(paths: &[PathBuf], threshold: u32) -> HashMap<String, Vec<PathBuf>> {
    if paths.len() < 2 { return HashMap::new(); }

    println!("🔍 Fuzzy matching {} images (threshold: {})...", paths.len(), threshold);
    
    // Generate perceptual hashes for all images in parallel
    let hashes: Vec<_> = paths
        .par_iter()
        .filter_map(|path| {
            let hasher = HasherConfig::new().hash_alg(HashAlg::Gradient).to_hasher();
            match img_hash::image::open(path) {
                Ok(img) => Some((path.clone(), hasher.hash_image(&img))),
                Err(e) => {
                    eprintln!("❌ Failed to load image {}: {}", path.display(), e);
                    None
                }
            }
        })
        .collect();

    if hashes.len() < 2 {
        println!("⚠️  Not enough valid images for comparison");
        return HashMap::new();
    }

    println!("✅ Generated hashes for {}/{} images", hashes.len(), paths.len());

    let mut groups = Vec::new();
    let mut processed = std::collections::HashSet::new();

    // Compare all image pairs
    for (i, (path1, hash1)) in hashes.iter().enumerate() {
        if processed.contains(path1) { continue; }
        
        let mut group = vec![path1.clone()];
        
        for (path2, hash2) in hashes.iter().skip(i + 1) {
            if processed.contains(path2) { continue; }
            
            let distance = hash1.dist(hash2);
            if distance <= threshold {
                group.push(path2.clone());
                processed.insert(path2.clone());
            }
        }
        
        if group.len() > 1 {
            // Calculate similarity percentage for reporting
            let first_pair_distance = if group.len() >= 2 {
                let second_hash = &hashes.iter().find(|(p, _)| p == &group[1]).unwrap().1;
                hash1.dist(second_hash)
            } else {
                0
            };
            
            let similarity = 100.0 - (first_pair_distance as f64 * 100.0 / 64.0);
            println!(" 🖼️ Fuzzy image group: {} files ({:.1}% similar)", group.len(), similarity);
            
            for file in &group {
                println!("    - {}", file.display());
            }
            
            groups.push(group);
        }
        
        processed.insert(path1.clone());
    }

    // Convert to HashMap with unique keys
    groups.into_iter().enumerate()
        .map(|(i, group)| (format!("fuzzy_img_{}", i), group))
        .collect()
}

// ============================================================================
// SIMILARITY CALCULATION
// ============================================================================

/// Calculates similarity percentage for a group of files
/// 
/// This function automatically detects the file type and uses the appropriate
/// similarity calculation method (text comparison or image perceptual hashing).
/// 
/// # Arguments
/// 
/// * `paths` - Vector of file paths in the same duplicate group
/// 
/// # Returns
/// 
/// * `Some(f64)` - Similarity percentage (0.0 to 100.0)
/// * `None` - If similarity cannot be calculated
/// 
/// # File Type Detection
/// 
/// - Text files: Uses edit distance on normalized content
/// - Image files: Uses perceptual hash comparison
/// - Other files: Assumes 100% similarity (exact duplicates)
fn calculate_similarity(paths: &[PathBuf]) -> Option<f64> {
    if paths.len() < 2 { return None; }

    // Detect if all files are text files
    if paths.iter().all(|f| f.extension().map(|e| e == "txt").unwrap_or(false)) {
        let contents: Vec<_> = paths.iter()
            .filter_map(|f| std::fs::read_to_string(f).ok())
            .collect();
        
        if contents.len() < 2 { return Some(100.0); }
        
        let mut total_similarity = 0.0;
        let mut comparisons = 0;
        
        // Compare all pairs of text files
        for i in 0..contents.len() {
            for j in i+1..contents.len() {
                let a_replaced = contents[i].replace("\r\n", "\n");
                let a = a_replaced.trim();
                let b_replaced = contents[j].replace("\r\n", "\n");
                let b = b_replaced.trim();
                
                let similarity = if a == b {
                    100.0
                } else {
                    let max_len = a.len().max(b.len()).max(1);
                    let dist = edit_distance(a, b);
                    100.0 - (dist as f64 * 100.0 / max_len as f64)
                };
                
                total_similarity += similarity;
                comparisons += 1;
            }
        }
        
        return Some(if comparisons > 0 { total_similarity / comparisons as f64 } else { 100.0 });
    }

    // Detect if all files are images
    if paths.iter().all(|f| {
        f.extension()
            .and_then(|e| e.to_str())
            .map(|e| matches!(e.to_ascii_lowercase().as_str(), "jpg" | "jpeg" | "png" | "gif" | "bmp"))
            .unwrap_or(false)
    }) {
        // Generate perceptual hashes in parallel
        let hashes: Vec<_> = paths
            .par_iter()
            .filter_map(|path| {
                let hasher = HasherConfig::new().hash_alg(HashAlg::Gradient).to_hasher();
                img_hash::image::open(path).ok().map(|img| hasher.hash_image(&img))
            })
            .collect();

        if hashes.len() < 2 { return Some(100.0); }

        // Calculate all pairwise similarities
        let pairs: Vec<_> = (0..hashes.len())
            .flat_map(|i| (i+1..hashes.len()).map(move |j| (i, j)))
            .collect();

        let similarities: Vec<f64> = pairs
            .par_iter()
            .map(|(i, j)| {
                let distance = hashes[*i].dist(&hashes[*j]);
                let bits = hashes[*i].as_bytes().len() * 8;
                100.0 - (distance as f64 * 100.0 / bits as f64)
            })
            .collect();

        return Some(if similarities.is_empty() { 
            100.0 
        } else { 
            similarities.iter().sum::<f64>() / similarities.len() as f64 
        });
    }

    // For other file types, assume exact duplicates
    Some(100.0)
}

// ============================================================================
// GROUP DEDUPLICATION
// ============================================================================

/// Removes overlapping files between exact and fuzzy duplicate groups
/// 
/// When both exact and fuzzy matching are enabled, the same files might appear
/// in multiple groups. This function prioritizes exact matches over fuzzy matches
/// and removes overlapping files to avoid processing the same file multiple times.
/// 
/// # Arguments
/// 
/// * `duplicates` - Mutable reference to the duplicate groups HashMap
/// 
/// # Priority Order
/// 
/// 1. Exact hash matches (highest priority)
/// 2. Fuzzy matches (only for files not in exact matches)
/// 3. Empty fuzzy groups are removed
fn deduplicate_groups(duplicates: &mut HashMap<String, Vec<PathBuf>>) {
    let mut seen_files = std::collections::HashSet::new();
    let mut keys_to_remove = Vec::new();

    // First pass: collect all files from exact hash matches (highest priority)
    for (hash, files) in duplicates.iter() {
        if !hash.starts_with("fuzzy_") && files.len() > 1 {
            for file in files {
                seen_files.insert(file.clone());
            }
        }
    }

    // Second pass: remove overlapping files from fuzzy matches
    for (hash, files) in duplicates.iter_mut() {
        if hash.starts_with("fuzzy_") {
            files.retain(|file| !seen_files.contains(file));
            
            // If fuzzy group has less than 2 files after deduplication, mark for removal
            if files.len() < 2 {
                keys_to_remove.push(hash.clone());
            } else {
                // Add remaining files to seen_files to prevent further overlaps
                for file in files {
                    seen_files.insert(file.clone());
                }
            }
        }
    }

    // Remove empty fuzzy groups
    for key in keys_to_remove {
        duplicates.remove(&key);
    }

    println!("🔧 Deduplicated overlapping groups");
}

// ============================================================================
// FILE QUARANTINE SYSTEM
// ============================================================================

/// Moves duplicate files to a quarantine directory while preserving folder structure
/// 
/// This function safely removes duplicate files by moving them to a `.quarantine`
/// subdirectory. The original directory structure is preserved to enable easy restoration.
/// 
/// # Arguments
/// 
/// * `groups` - HashMap of duplicate file groups
/// * `base_dir` - Base directory for quarantine folder
/// * `dry_run` - If true, only shows what would be quarantined without actually moving files
/// 
/// # Returns
/// 
/// Total number of bytes that were (or would be) freed
/// 
/// # Safety Features
/// 
/// - Preserves directory structure in quarantine
/// - Keeps one file from each group (the first one)
/// - Creates detailed log for restoration
/// - Handles path conflicts gracefully
fn quarantine_duplicates(groups: &HashMap<String, Vec<PathBuf>>, base_dir: &str, dry_run: bool) -> u64 {
    let mut total_saved = 0u64;
    let quarantine_dir = PathBuf::from(format!("{}/.quarantine", base_dir));
    let mut log = Vec::new();
    let base_path = PathBuf::from(base_dir);

    for files in groups.values().filter(|files| files.len() > 1) {
        // Skip the first file (keep it), quarantine the rest
        for file in files.iter().skip(1) {
            if let Ok(meta) = file.metadata() {
                total_saved += meta.len();
            }

            // Preserve directory structure in quarantine
            let relative_path = if let Ok(rel) = file.strip_prefix(&base_path) {
                rel
            } else {
                // Fallback for absolute paths
                file.file_name().map(|name| std::path::Path::new(name)).unwrap_or(file)
            };
            
            let dest = quarantine_dir.join(relative_path);
            
            // Create parent directories in quarantine
            if let Some(parent) = dest.parent() {
                if !dry_run {
                    if let Err(e) = std::fs::create_dir_all(parent) {
                        eprintln!("Failed to create quarantine directory {}: {}", parent.display(), e);
                        continue;
                    }
                }
            }

            if dry_run {
                println!("[Dry Run] Would quarantine: {} -> {}", file.display(), dest.display());
            } else {
                match std::fs::rename(file, &dest) {
                    Ok(_) => {
                        println!("Quarantined: {} -> {}", file.display(), dest.display());
                        log.push(QuarantineLogEntry {
                            original: file.display().to_string(),
                            quarantined: dest.display().to_string(),
                        });
                    }
                    Err(e) => eprintln!("Failed to quarantine {}: {}", file.display(), e),
                }
            }
        }
    }

    // Save quarantine log for restoration
    if !dry_run && !log.is_empty() {
        let log_path = format!("{}/.quarantine_log.json", base_dir);
        if let Err(e) = std::fs::write(&log_path, serde_json::to_string_pretty(&log).unwrap()) {
            eprintln!("Failed to save quarantine log: {}", e);
        } else {
            println!("📋 Quarantine log saved to {}", log_path);
        }
    }

    total_saved
}

/// Restores all quarantined files to their original locations
/// 
/// Reads the quarantine log and moves all files back to their original paths.
/// This function completely reverses the quarantine operation.
/// 
/// # Arguments
/// 
/// * `base_dir` - Base directory containing the quarantine folder and log
/// 
/// # Error Handling
/// 
/// - Creates missing parent directories as needed
/// - Reports failures but continues with other files
/// - Removes the quarantine log after successful restoration
fn undo_quarantine(base_dir: &str) {
    let log_path = format!("{}/.quarantine_log.json", base_dir);
    
    let entries: Vec<QuarantineLogEntry> = match std::fs::read_to_string(&log_path) {
        Ok(data) => serde_json::from_str(&data).unwrap_or_else(|e| {
            eprintln!("Failed to parse quarantine log: {}", e);
            Vec::new()
        }),
        Err(e) => {
            eprintln!("Failed to read quarantine log {}: {}", log_path, e);
            return;
        }
    };

    if entries.is_empty() {
        println!("No quarantine log found or log is empty");
        return;
    }

    let entries_len = entries.len();
    println!("🔄 Restoring {} quarantined files...", entries_len);

    let mut restored = 0;
    for entry in entries {
        let from = std::path::Path::new(&entry.quarantined);
        let to = std::path::Path::new(&entry.original);
        
        // Create parent directories if they don't exist
        if let Some(parent) = to.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!("Failed to create directory {}: {}", parent.display(), e);
                continue;
            }
        }
        
        match std::fs::rename(from, to) {
            Ok(_) => {
                println!("Restored: {}", entry.original);
                restored += 1;
            }
            Err(e) => eprintln!("Failed to restore {}: {}", entry.original, e),
        }
    }
    
    // Remove the quarantine log after successful restoration
    if restored > 0 {
        let _ = std::fs::remove_file(&log_path);
        println!("✅ Successfully restored {}/{} files", restored, entries_len);
    }
}

// ============================================================================
// REPORTING SYSTEM
// ============================================================================

/// Generates a detailed JSON report of all duplicate groups found
/// 
/// Creates a comprehensive report including file groups, similarity percentages,
/// and space savings information that can be used for further analysis.
/// 
/// # Arguments
/// 
/// * `path` - Output file path for the JSON report
/// * `groups` - HashMap of all duplicate groups
/// * `saved_bytes` - Total bytes freed by quarantining
/// * `similarity_cache` - Precomputed similarity percentages
/// 
/// # Report Format
/// 
/// The JSON report includes:
/// - Total space saved (bytes and MB)
/// - List of all duplicate groups
/// - Similarity percentages where available
/// - Full file paths for each duplicate
fn save_report(path: &str, groups: &HashMap<String, Vec<PathBuf>>, saved_bytes: u64, similarity_cache: &HashMap<String, f64>) {
    let duplicate_groups: Vec<DuplicateGroup> = groups
        .iter()
        .filter(|(_, files)| files.len() > 1)
        .map(|(hash, files)| DuplicateGroup {
            hash: hash.clone(),
            similarity: similarity_cache.get(hash).copied(),
            files: files.iter().map(|p| p.display().to_string()).collect(),
        })
        .collect();

    let report = FullReport {
        saved_bytes,
        saved_mb: saved_bytes as f64 / (1024.0 * 1024.0),
        groups: duplicate_groups,
    };

    match std::fs::write(path, serde_json::to_string_pretty(&report).unwrap()) {
        Ok(_) => println!("📄 Report saved to {}", path),
        Err(e) => eprintln!("Failed to save report: {}", e),
    }
}

// ============================================================================
// DEBUG AND UTILITY FUNCTIONS
// ============================================================================

/// Displays detailed information about all found files for debugging
/// 
/// # Arguments
/// 
/// * `files` - Vector of file paths to display
fn debug_file_structure(files: &[PathBuf]) {
    println!("\n🔍 Debug: Found files:");
    for file in files {
        println!("  {}", file.display());
    }
    println!("Total files found: {}\n", files.len());
}

/// Displays detailed information about files in subfolders for debugging
/// 
/// This function helps diagnose issues with subfolder scanning and shows
/// the content of text files for verification.
/// 
/// # Arguments
/// 
/// * `files` - Vector of all file paths to analyze
fn debug_subfolder_files(files: &[PathBuf]) {
    let subfolder_files: Vec<_> = files.iter()
        .filter(|f| f.components().any(|c| c.as_os_str() == "subfolder"))
        .collect();
    
    println!("🗂️  Subfolder files found: {}", subfolder_files.len());
    for file in &subfolder_files {
        println!("   📁 {}", file.display());
        if let Ok(meta) = file.metadata() {
            println!("      📏 Size: {} bytes", meta.len());
            if let Ok(content) = std::fs::read_to_string(file) {
                let preview = if content.len() > 50 {
                    format!("{}...", &content[..50])
                } else {
                    content
                };
                println!("      📝 Content: {:?}", preview);
            }
        }
    }
    
    let text_files: Vec<_> = files.iter()
        .filter(|f| f.extension().map(|e| e == "txt").unwrap_or(false))
        .collect();
    
    println!("\n📝 All text files found: {}", text_files.len());
    for file in &text_files {
        println!("   📝 {}", file.display());
        if let Ok(content) = std::fs::read_to_string(file) {
            println!("      Content: {:?}", content.trim());
        }
    }
    println!();
}

// ============================================================================
// MAIN APPLICATION ENTRY POINT
// ============================================================================

/// Main application entry point
/// 
/// Coordinates the entire deduplication process including:
/// - Command line argument parsing
/// - File scanning and collection
/// - Duplicate detection (exact and fuzzy)
/// - File quarantine or restoration
/// - Report generation
/// 
/// # Command Line Arguments
/// 
/// - `folder_path` - Directory to scan for duplicates
/// - `--fuzzy` - Enable fuzzy matching for similar files
/// - `--dry-run` - Preview mode (no files are actually moved)
/// - `--hash <algorithm>` - Hash algorithm: blake3, sha256, or xxhash
/// - `--regex <pattern>` - Only process files matching this regex
/// - `--undo` - Restore all quarantined files
/// 
/// # Examples
/// 
/// ```bash
/// # Basic usage
/// cargo run -- ./my_folder
/// 
/// # Fuzzy matching with dry run
/// cargo run -- ./my_folder --fuzzy --dry-run
/// 
/// # Using different hash algorithm
/// cargo run -- ./my_folder --hash sha256
/// 
/// # Restore quarantined files
/// cargo run -- ./my_folder --undo
/// ```
fn main() {
    // Initialize thread pool for optimal performance
    rayon::ThreadPoolBuilder::new()
        .num_threads(num_cpus::get())
        .build_global()
        .expect("Failed to initialize thread pool");

    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    let folder = args.get(1).map(|s| s.as_str()).unwrap_or("./test_folder");
    let dry_run = args.contains(&"--dry-run".to_string());
    let use_fuzzy = args.contains(&"--fuzzy".to_string());

    // Parse hash algorithm
    let hash_algo = args.iter()
        .position(|x| x == "--hash")
        .and_then(|i| args.get(i + 1))
        .map(|val| match val.to_lowercase().as_str() {
            "sha256" => HashAlgo::Sha256,
            "xxhash" => HashAlgo::XxHash,
            _ => HashAlgo::Blake3,
        })
        .unwrap_or(HashAlgo::Blake3);

    // Parse regex pattern
    let regex_pattern = args.iter()
        .position(|x| x == "--regex")
        .and_then(|i| args.get(i + 1))
        .and_then(|pattern| Regex::new(pattern).ok());

    // Handle restore operation
    if args.contains(&"--undo".to_string()) {
        undo_quarantine(folder);
        return;
    }

    println!("🚀 Starting deduplicator with {} threads", rayon::current_num_threads());
    println!("📁 Target folder: {}", folder);
    if use_fuzzy { println!("🔍 Fuzzy matching enabled"); }
    if dry_run { println!("👁️  Dry run mode (no files will be moved)"); }
    
    let start_time = std::time::Instant::now();

    // Phase 1: File Discovery
    let files = collect_files(
        folder,
        &FileFilter { 
            min_size: Some(0),  // Allow 0-byte files
            max_size: None, 
            allowed_extensions: None, 
            modified_after: None 
        },
        regex_pattern.as_ref(),
    );

    // Debug output
    debug_file_structure(&files);
    debug_subfolder_files(&files);

    // Classify files by type
    let (images, texts): (Vec<_>, Vec<_>) = files
        .par_iter()
        .partition_map(|path| {
            match path.extension().and_then(|e| e.to_str()).map(|e| e.to_ascii_lowercase()) {
                Some(ext) if matches!(ext.as_str(), "jpg" | "jpeg" | "png" | "gif" | "bmp") => 
                    rayon::iter::Either::Left(path.clone()),
                _ => rayon::iter::Either::Right(path.clone()),
            }
        });

    println!("📁 Classification: {} total files ({} images, {} text/other)", 
             files.len(), images.len(), texts.len());

    // Phase 2: Duplicate Detection
    let mut duplicates = group_duplicates_parallel(files, &hash_algo);
    
    if use_fuzzy {
        println!("\n🔍 Starting fuzzy analysis...");
        
        // Fuzzy image matching
        let fuzzy_imgs = fuzzy_image_match(&images, 10);
        for (k, v) in fuzzy_imgs {
            duplicates.entry(k).or_default().extend(v);
        }
        
        // Fuzzy text matching
        let fuzzy_texts = fuzzy_text_match(&texts, 80.0);
        for (k, v) in fuzzy_texts {
            duplicates.entry(k).or_default().extend(v);
        }
        
        // Remove overlapping groups
        deduplicate_groups(&mut duplicates);
    }

    println!("⏱️  Analysis completed in {:.1?}", start_time.elapsed());

    // Phase 3: Similarity Calculation and Reporting
    let mut similarity_cache = HashMap::new();
    
    println!("\n📊 Duplicate Groups Found:");
    for (hash, paths) in &duplicates {
        if paths.len() > 1 {
            let group_type = if hash.starts_with("fuzzy_img") {
                "🖼️ Fuzzy Image"
            } else if hash.starts_with("fuzzy_txt") {
                "📝 Fuzzy Text"
            } else {
                "📦 Exact Hash"
            };
            
            println!("\n{} Group ({}): {} files", group_type, &hash[..8.min(hash.len())], paths.len());
            for p in paths { println!("   {}", p.display()); }
            
            if let Some(similarity) = calculate_similarity(paths) {
                similarity_cache.insert(hash.clone(), similarity);
                println!("   Similarity: {:.1}%", similarity);
            }
        }
    }

    // Phase 4: File Management
    let saved_bytes = quarantine_duplicates(&duplicates, folder, dry_run);
    save_report("report.json", &duplicates, saved_bytes, &similarity_cache);

    // Final summary
    println!("\n✅ {} {:.1} MB in {} duplicate groups", 
        if dry_run { "Would save" } else { "Saved" },
        saved_bytes as f64 / (1024.0 * 1024.0),
        duplicates.iter().filter(|(_, files)| files.len() > 1).count()
    );
    
    println!("⏱️  Total runtime: {:.1?}", start_time.elapsed());
}