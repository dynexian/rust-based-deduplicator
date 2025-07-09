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
// STRUCTS & ENUMS
// ============================================================================

pub struct FileFilter {
    pub min_size: Option<u64>,
    pub max_size: Option<u64>,
    pub allowed_extensions: Option<Vec<String>>,
    pub modified_after: Option<SystemTime>,
}

#[derive(Serialize, Deserialize)]
struct QuarantineLogEntry {
    original: String,
    quarantined: String,
}

enum HashAlgo {
    Blake3,
    Sha256,
    XxHash,
}

#[derive(Serialize)]
struct DuplicateGroup {
    hash: String,
    similarity: Option<f64>,
    files: Vec<String>,
}

#[derive(Serialize)]
struct FullReport {
    saved_bytes: u64,
    saved_mb: f64,
    groups: Vec<DuplicateGroup>,
}

#[derive(Clone, Serialize, Deserialize)]
struct CachedFile {
    path: String,
    modified: u64,
    size: u64,
    hash: String,
}

// ============================================================================
// CORE FUNCTIONS
// ============================================================================

fn hash_file(path: &PathBuf, algo: &HashAlgo) -> Option<String> {
    let file = File::open(path).ok()?;
    let mut reader = BufReader::new(file);
    let mut buffer = [0u8; 8192]; // Increased buffer size for better performance

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

fn collect_files_parallel(dir: &str, filter: &FileFilter, regex: Option<&Regex>) -> Vec<PathBuf> {
    println!("🔄 Scanning files recursively in {}...", dir);
    
    // Use sequential scanning to avoid race conditions
    let mut results = Vec::new();
    
    for entry in WalkDir::new(dir) {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                println!("❌ Error reading entry: {}", e);
                continue;
            }
        };
        
        let path = entry.path();

        // Skip quarantine and directories
        if path.components().any(|c| c.as_os_str() == ".quarantine") {
            continue;
        }
        
        if entry.file_type().is_dir() {
            continue;
        }

        println!("📁 Found: {}", path.display());

        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(e) => {
                println!("   ❌ Failed to get metadata: {}", e);
                continue;
            }
        };
        
        let size = meta.len();

        // Apply filters
        if let Some(min) = filter.min_size { 
            if size < min { 
                println!("   ⏭️ Skipped: size {} < min {}", size, min);
                continue; 
            } 
        }
        if let Some(max) = filter.max_size { 
            if size > max { 
                println!("   ⏭️ Skipped: size {} > max {}", size, max);
                continue; 
            } 
        }
        if let Some(after) = filter.modified_after { 
            if let Ok(modified) = meta.modified() {
                if modified < after { 
                    println!("   ⏭️ Skipped: too old");
                    continue; 
                }
            }
        }
        if let Some(ref exts) = filter.allowed_extensions {
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                let file_ext = ext.to_lowercase();
                if !exts.contains(&file_ext) { 
                    println!("   ⏭️ Skipped: extension {} not allowed", file_ext);
                    continue; 
                }
            } else {
                println!("   ⏭️ Skipped: no extension");
                continue;
            }
        }
        if let Some(rgx) = regex {
            if !rgx.is_match(&entry.file_name().to_string_lossy()) { 
                println!("   ⏭️ Skipped: doesn't match regex");
                continue; 
            }
        }

        println!("   ✅ Included");
        results.push(path.to_path_buf());
    }
    
    println!("📊 Total files collected: {}", results.len());
    results
}

fn group_duplicates_parallel(files: Vec<PathBuf>, algo: &HashAlgo) -> HashMap<String, Vec<PathBuf>> {
    let args: Vec<String> = std::env::args().collect();
    let folder = args.get(1).expect("Please provide a folder path");
    let cache_path = format!("{}/.dedup_cache.json", folder);
    
    // Load cache
    let cache_map: HashMap<String, CachedFile> = std::fs::read_to_string(&cache_path)
        .ok()
        .and_then(|data| serde_json::from_str(&data).ok())
        .unwrap_or_default();
    
    let cache_map = Arc::new(cache_map);
    let new_cache = Arc::new(Mutex::new(HashMap::<String, CachedFile>::new()));
    let progress = Arc::new(AtomicUsize::new(0));
    let total = files.len();
    
    println!("🔄 Hashing {} files using {} threads...", total, rayon::current_num_threads());
    
    let results: Vec<((String, PathBuf), Option<CachedFile>)> = files
        .into_par_iter()
        .filter_map(|path| {
            let current = progress.fetch_add(1, Ordering::Relaxed);
            if current % 100 == 0 { println!("📊 Progress: {}/{}", current + 1, total); }

            let meta = path.metadata().ok()?;
            let modified = meta.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
            let size = meta.len();
            let path_str = path.display().to_string();

            // Check cache hit
            if let Some(cached) = cache_map.get(&path_str) {
                if cached.modified == modified && cached.size == size {
                    return Some(((cached.hash.clone(), path), None));
                }
            }

            // Cache miss - calculate hash
            let hash = hash_file(&path, algo)?;
            let cached_file = CachedFile { path: path_str, modified, size, hash: hash.clone() };
            Some(((hash, path), Some(cached_file)))
        })
        .collect();

    // Update cache
    for ((_, _), cache_entry) in &results {
        if let Some(cached_file) = cache_entry {
            new_cache.lock().unwrap().insert(cached_file.path.clone(), cached_file.clone());
        }
    }

    // Group by hash
    let mut map: HashMap<String, Vec<PathBuf>> = HashMap::new();
    for ((hash, path), _) in results {
        map.entry(hash).or_default().push(path);
    }

    // Save cache
    let _ = std::fs::write(cache_path, serde_json::to_string_pretty(&*new_cache.lock().unwrap()).unwrap());
    
    println!("✅ Found {} duplicate groups", map.iter().filter(|(_, paths)| paths.len() > 1).count());
    map
}

fn edit_distance(a: &str, b: &str) -> usize {
    let mut dp = vec![vec![0; b.len() + 1]; a.len() + 1];
    
    for i in 0..=a.len() { dp[i][0] = i; }
    for j in 0..=b.len() { dp[0][j] = j; }

    for (i, ca) in a.chars().enumerate() {
        for (j, cb) in b.chars().enumerate() {
            dp[i + 1][j + 1] = if ca == cb {
                dp[i][j]
            } else {
                1 + dp[i][j].min(dp[i + 1][j]).min(dp[i][j + 1])
            };
        }
    }
    dp[a.len()][b.len()]
}

fn calculate_similarity(paths: &[PathBuf]) -> Option<f64> {
    if paths.len() < 2 { return None; }

    // Text files
    if paths.iter().all(|f| f.extension().map(|e| e == "txt").unwrap_or(false)) {
        let contents: Vec<_> = paths.iter()
            .filter_map(|f| std::fs::read_to_string(f).ok())
            .collect();
        
        if contents.len() < 2 { return Some(100.0); }
        
        let mut total_sim = 0.0;
        let mut comparisons = 0;
        
        for i in 0..contents.len() {
            for j in i+1..contents.len() {
                let a_replaced = contents[i].replace("\r\n", "\n");
                let a = a_replaced.trim();
                let b_replaced = contents[j].replace("\r\n", "\n");
                let b = b_replaced.trim();
                
                let sim = if a == b {
                    100.0
                } else {
                    let max_len = a.len().max(b.len()).max(1);
                    let dist = edit_distance(a, b);
                    100.0 - (dist as f64 * 100.0 / max_len as f64)
                };
                
                total_sim += sim;
                comparisons += 1;
            }
        }
        
        return Some(if comparisons > 0 { total_sim / comparisons as f64 } else { 100.0 });
    }

    // Image files
    if paths.iter().all(|f| {
        f.extension()
            .and_then(|e| e.to_str())
            .map(|e| matches!(e.to_ascii_lowercase().as_str(), "jpg" | "jpeg" | "png" | "gif" | "bmp"))
            .unwrap_or(false)
    }) {
        let hashes: Vec<_> = paths
            .par_iter()
            .filter_map(|path| {
                let hasher = HasherConfig::new().hash_alg(HashAlg::Gradient).to_hasher();
                img_hash::image::open(path).ok().map(|img| hasher.hash_image(&img))
            })
            .collect();

        if hashes.len() < 2 { return Some(100.0); }

        let pairs: Vec<_> = (0..hashes.len())
            .flat_map(|i| (i+1..hashes.len()).map(move |j| (i, j)))
            .collect();

        let similarities: Vec<f64> = pairs
            .par_iter()
            .map(|(i, j)| {
                let dist = hashes[*i].dist(&hashes[*j]);
                let bits = hashes[*i].as_bytes().len() * 8;
                100.0 - (dist as f64 * 100.0 / bits as f64)
            })
            .collect();

        return Some(if similarities.is_empty() { 100.0 } else { 
            similarities.iter().sum::<f64>() / similarities.len() as f64 
        });
    }

    Some(100.0) // Exact duplicates
}

fn fuzzy_image_match(paths: &[PathBuf], threshold: u32) -> HashMap<String, Vec<PathBuf>> {
    if paths.len() < 2 { return HashMap::new(); }

    println!("🔍 Fuzzy matching {} images...", paths.len());
    
    let hashes: Vec<_> = paths
        .par_iter()
        .filter_map(|path| {
            let hasher = HasherConfig::new().hash_alg(HashAlg::Gradient).to_hasher();
            img_hash::image::open(path).ok().map(|img| (path.clone(), hasher.hash_image(&img)))
        })
        .collect();

    let mut groups = Vec::new();
    let mut processed = std::collections::HashSet::new();

    for (i, (path1, hash1)) in hashes.iter().enumerate() {
        if processed.contains(path1) { continue; }
        
        let mut group = vec![path1.clone()];
        
        for (path2, hash2) in hashes.iter().skip(i + 1) {
            if processed.contains(path2) { continue; }
            
            if hash1.dist(hash2) <= threshold {
                group.push(path2.clone());
                processed.insert(path2.clone());
            }
        }
        
        if group.len() > 1 {
            let similarity = 100.0 - (hash1.dist(&hashes.iter().find(|(p, _)| p == &group[1]).unwrap().1) as f64 * 100.0 / 64.0);
            println!(" 🖼️ Fuzzy group: {} files ({:.1}% similar)", group.len(), similarity);
            groups.push(group);
        }
        
        processed.insert(path1.clone());
    }

    groups.into_iter().enumerate()
        .map(|(i, group)| (format!("fuzzy_img_{}", i), group))
        .collect()
}

fn fuzzy_text_match(paths: &[PathBuf], threshold: f64) -> HashMap<String, Vec<PathBuf>> {
    if paths.len() < 2 { return HashMap::new(); }

    println!("🔍 Fuzzy matching {} text files...", paths.len());
    
    // Debug: Show what text files we're processing
    for path in paths {
        println!("   📝 Processing: {}", path.display());
        if let Ok(content) = std::fs::read_to_string(path) {
            println!("      Content: {:?}", content.trim());
        } else {
            println!("      ❌ Failed to read file");
        }
    }
    
    // Read all text files
    let contents: Vec<_> = paths
        .iter()
        .filter_map(|path| {
            match std::fs::read_to_string(path) {
                Ok(content) => {
                    let cleaned = content.replace("\r\n", "\n").trim().to_string();
                    println!("   ✅ Read {}: {} chars", path.display(), cleaned.len());
                    Some((path.clone(), cleaned))
                }
                Err(e) => {
                    println!("   ❌ Failed to read {}: {}", path.display(), e);
                    None
                }
            }
        })
        .collect();

    println!("📝 Successfully read {} text files", contents.len());

    let mut groups = Vec::new();
    let mut processed = std::collections::HashSet::new();

    for (i, (path1, content1)) in contents.iter().enumerate() {
        if processed.contains(path1) { continue; }
        
        let mut group = vec![path1.clone()];
        
        for (path2, content2) in contents.iter().skip(i + 1) {
            if processed.contains(path2) { continue; }
            
            // Calculate similarity
            let similarity = if content1 == content2 {
                100.0
            } else if content1.is_empty() && content2.is_empty() {
                100.0  // Both empty files
            } else {
                let max_len = content1.len().max(content2.len()).max(1);
                let dist = edit_distance(content1, content2);
                100.0 - (dist as f64 * 100.0 / max_len as f64)
            };
            
            println!("   📊 Similarity between {} and {}: {:.1}%", 
                     path1.file_name().unwrap().to_string_lossy(),
                     path2.file_name().unwrap().to_string_lossy(),
                     similarity);
            
            if similarity >= threshold {
                group.push(path2.clone());
                processed.insert(path2.clone());
            }
        }
        
        if group.len() > 1 {
            // Calculate actual similarity for the first pair
            let first_similarity = if group.len() >= 2 {
                let content2 = &contents.iter().find(|(p, _)| p == &group[1]).unwrap().1;
                if content1 == content2 {
                    100.0
                } else {
                    let max_len = content1.len().max(content2.len()).max(1);
                    let dist = edit_distance(content1, content2);
                    100.0 - (dist as f64 * 100.0 / max_len as f64)
                }
            } else {
                100.0
            };
            
            println!(" 📝 Fuzzy text group: {} files ({:.1}% similar)", group.len(), first_similarity);
            for file in &group {
                println!("    - {}", file.display());
            }
            groups.push(group);
        }
        
        processed.insert(path1.clone());
    }

    groups.into_iter().enumerate()
        .map(|(i, group)| (format!("fuzzy_txt_{}", i), group))
        .collect()
}

fn quarantine_duplicates(map: &HashMap<String, Vec<PathBuf>>, base_dir: &str, dry_run: bool) -> u64 {
    let mut total_saved = 0u64;
    let quarantine_dir = PathBuf::from(format!("{}/.quarantine", base_dir));
    let mut log = Vec::new();
    let base_path = PathBuf::from(base_dir);

    for files in map.values().filter(|files| files.len() > 1) {
        for file in files.iter().skip(1) {
            if let Ok(meta) = file.metadata() {
                total_saved += meta.len();
            }

            // Preserve directory structure in quarantine
            let relative_path = if let Ok(rel) = file.strip_prefix(&base_path) {
                rel
            } else {
                // Fallback if strip_prefix fails
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

    if !dry_run && !log.is_empty() {
        let log_path = format!("{}/.quarantine_log.json", base_dir);
        let _ = std::fs::write(log_path, serde_json::to_string_pretty(&log).unwrap());
    }

    total_saved
}

fn save_report(path: &str, map: &HashMap<String, Vec<PathBuf>>, saved_bytes: u64, similarity_cache: &HashMap<String, f64>) {
    let groups: Vec<DuplicateGroup> = map
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
        groups,
    };

    std::fs::write(path, serde_json::to_string_pretty(&report).unwrap())
        .expect("Failed to write report");
    println!("📄 Report saved to {}", path);
}

fn undo_quarantine(base_dir: &str) {
    let log_path = format!("{}/.quarantine_log.json", base_dir);
    let entries: Vec<QuarantineLogEntry> = std::fs::read_to_string(&log_path)
        .ok()
        .and_then(|data| serde_json::from_str(&data).ok())
        .unwrap_or_default();

    for entry in entries {
        let from = std::path::Path::new(&entry.quarantined);
        let to = std::path::Path::new(&entry.original);
        
        if let Some(parent) = to.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        
        match std::fs::rename(from, to) {
            Ok(_) => println!("Restored: {}", entry.original),
            Err(e) => println!("Failed to restore {}: {}", entry.original, e),
        }
    }
    
    let _ = std::fs::remove_file(&log_path);
}

// ============================================================================
// MAIN FUNCTION
// ============================================================================

fn main() {
    // Setup
    rayon::ThreadPoolBuilder::new()
        .num_threads(num_cpus::get())
        .build_global()
        .expect("Failed to initialize thread pool");

    let args: Vec<String> = env::args().collect();
    let folder = args.get(1).map(|s| s.as_str()).unwrap_or("./test_folder");
    let dry_run = args.contains(&"--dry-run".to_string());
    let use_fuzzy = args.contains(&"--fuzzy".to_string());

    let hash_algo = args.iter()
        .position(|x| x == "--hash")
        .and_then(|i| args.get(i + 1))
        .map(|val| match val.to_lowercase().as_str() {
            "sha256" => HashAlgo::Sha256,
            "xxhash" => HashAlgo::XxHash,
            _ => HashAlgo::Blake3,
        })
        .unwrap_or(HashAlgo::Blake3);

    let regex_pattern = args.iter()
        .position(|x| x == "--regex")
        .and_then(|i| args.get(i + 1))
        .and_then(|pattern| Regex::new(pattern).ok());

    if args.contains(&"--undo".to_string()) {
        undo_quarantine(folder);
        return;
    }

    println!("🚀 Starting deduplicator with {} threads", rayon::current_num_threads());
    let start = std::time::Instant::now();

    // Collect files - ALLOW 0-BYTE FILES
    let files = collect_files_parallel(
        folder,
        &FileFilter { 
            min_size: Some(0),  // Changed from 1 to 0
            max_size: None, 
            allowed_extensions: None, 
            modified_after: None 
        },
        regex_pattern.as_ref(),
    );

    // Debug what we found
    debug_file_structure(&files);
    debug_subfolder_files(&files);  // Add this line

    let (images, texts): (Vec<_>, Vec<_>) = files
        .par_iter()
        .partition_map(|path| {
            match path.extension().and_then(|e| e.to_str()).map(|e| e.to_ascii_lowercase()) {
                Some(ext) if matches!(ext.as_str(), "jpg" | "jpeg" | "png" | "gif" | "bmp") => 
                    rayon::iter::Either::Left(path.clone()),
                _ => rayon::iter::Either::Right(path.clone()),
            }
        });

    println!("📁 Found {} files ({} images, {} other)", files.len(), images.len(), texts.len());

    // Find duplicates
    let mut duplicates = group_duplicates_parallel(files, &hash_algo);
    
    if use_fuzzy {
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
        
        // IMPORTANT: Deduplicate overlapping groups
        deduplicate_groups(&mut duplicates);
    }

    println!("⏱️  Processing completed in {:.1?}", start.elapsed());

    // Calculate similarities and create cache
    let mut similarity_cache = HashMap::new();
    for (hash, paths) in &duplicates {
        if paths.len() > 1 {
            let group_type = if hash.starts_with("fuzzy_img") {
                "🖼️ Fuzzy Image"
            } else if hash.starts_with("fuzzy_txt") {
                "📝 Fuzzy Text"
            } else {
                "📦 Exact Hash"
            };
            
            println!("\n{} Group ({}): {} files", group_type, &hash[..8], paths.len());
            for p in paths { println!("   {}", p.display()); }
            
            if let Some(sim) = calculate_similarity(paths) {
                similarity_cache.insert(hash.clone(), sim);
                println!("   Similarity: {:.1}%", sim);
            }
        }
    }

    // Execute actions
    let saved_bytes = quarantine_duplicates(&duplicates, folder, dry_run);
    save_report("report.json", &duplicates, saved_bytes, &similarity_cache);

    println!("\n✅ {} {:.1} MB", 
        if dry_run { "Would save" } else { "Saved" },
        saved_bytes as f64 / (1024.0 * 1024.0)
    );
}

// Add this function to debug what files are found:

fn debug_file_structure(files: &[PathBuf]) {
    println!("\n🔍 Debug: Found files:");
    for file in files {
        println!("  {}", file.display());
    }
    println!("Total files found: {}\n", files.len());
}

// Add this function to remove overlapping files:

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

// Add this function right after debug_file_structure:

fn debug_subfolder_files(files: &[PathBuf]) {
    let subfolder_files: Vec<_> = files.iter()
        .filter(|f| f.components().any(|c| c.as_os_str() == "subfolder"))
        .collect();
    
    println!("\n🗂️  Subfolder files found: {}", subfolder_files.len());
    for file in &subfolder_files {
        println!("   📁 {}", file.display());
        if let Ok(meta) = file.metadata() {
            println!("      📏 Size: {} bytes", meta.len());
            if let Ok(content) = std::fs::read_to_string(file) {
                println!("      📝 Content preview: {:?}", &content[..content.len().min(50)]);
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
