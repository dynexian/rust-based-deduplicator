use walkdir::WalkDir;
use std::path::PathBuf;
use std::fs::File;
use std::io::{BufReader, Read};
use blake3;
use std::collections::HashMap;
use rayon::prelude::*;
use std::env;
use std::time::SystemTime;
use std::fs;
use regex::Regex;
use serde::{Serialize, Deserialize};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};


pub struct FileFilter {
    pub min_size: Option<u64>,       // in bytes
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
    similarity: Option<f64>,  // New field
    files: Vec<String>,
}

#[derive(Serialize)]
struct FullReport {
    saved_bytes: u64,
    saved_mb: f64,
    groups: Vec<DuplicateGroup>,
}

// #[derive(Serialize)]
// struct SimilarEntry {
//     similarity: f64,         // in %
//     files: Vec<String>,      // the similar files
// }

#[derive(Clone, Serialize, Deserialize)]
struct CachedFile {
    path: String,
    modified: u64,
    size: u64,
    hash: String,
}



// fn collect_all_files(dir: &str, filter: &FileFilter, regex: Option<&Regex>) -> Vec<PathBuf> {
//     WalkDir::new(dir)
//         .into_iter()
//         .filter_map(|entry| {
//             let entry = entry.ok()?;
//             let path = entry.path();

//             // Skip .quarantine and hidden folders
//             if path.components().any(|c| c.as_os_str() == ".quarantine") {
//                 return None;
//             }
//             if entry.file_type().is_dir() {
//                 return None;
//             }

//             let meta = entry.metadata().ok()?;
//             let size = meta.len();
//             let modified = meta.modified().ok()?;

//             if let Some(min) = filter.min_size {
//                 if size < min {
//                     return None;
//                 }
//             }

//             if let Some(max) = filter.max_size {
//                 if size > max {
//                     return None;
//                 }
//             }

//             if let Some(after) = filter.modified_after {
//                 if modified < after {
//                     return None;
//                 }
//             }

//             if let Some(ref exts) = filter.allowed_extensions {
//                 let file_ext = entry.path().extension()?.to_str()?.to_lowercase();
//                 if !exts.contains(&file_ext) {
//                     return None;
//                 }
//             }

//             if let Some(rgx) = regex {
//                 let filename = entry.file_name().to_string_lossy();
//                 if !rgx.is_match(&filename) {
//                     return None;
//                 }
//             }

//             Some(path.to_path_buf())
//         })
//         .collect()
// }

fn hash_file(path: &PathBuf, algo: &HashAlgo) -> Option<String> {
    let file = File::open(path).ok()?;
    let mut reader = BufReader::new(file);
    let mut buffer = [0u8; 4096];

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

// fn group_duplicates(files: Vec<PathBuf>, algo: &HashAlgo) -> HashMap<String, Vec<PathBuf>> {
//     let args: Vec<String> = std::env::args().collect();
//     let folder = args.get(1).expect("Please provide a folder path"); 
//     let cache_path = format!("{}/.dedup_cache.json", folder);
//     let cache_map: HashMap<String, CachedFile> = if let Ok(data) = std::fs::read_to_string(&cache_path) {
//         serde_json::from_str(&data).unwrap_or_default()
//     } else {
//         HashMap::new()
//     };
    
//     let mut new_cache: HashMap<String, CachedFile> = HashMap::new();
//     let hashes_and_cache: Vec<((String, PathBuf), Option<CachedFile>)> = files
//         .into_par_iter()
//         .filter_map(|path| {
//             let meta = path.metadata().ok()?;
//             let modified = meta.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
//             let size = meta.len();
//             let path_str = path.display().to_string();

//             if let Some(cached) = cache_map.get(&path_str) {
//                 if cached.modified == modified && cached.size == size {
//                     return Some(((cached.hash.clone(), path), None));
//                 }
//             }

//             let hash = hash_file(&path, algo)?;
//             let cached_file = CachedFile {
//                 path: path_str.clone(),
//                 modified,
//                 size,
//                 hash: hash.clone(),
//             };

//             Some(((hash, path), Some(cached_file)))
//         })
//         .collect();

//     for ((_, _), cache_entry) in &hashes_and_cache {
//         if let Some(cached_file) = cache_entry {
//             new_cache.insert(cached_file.path.clone(), cached_file.clone());
//         }
//     }
//     let hashes: Vec<(String, PathBuf)> = hashes_and_cache.into_iter().map(|(hp, _)| hp).collect();

//     let mut map: HashMap<String, Vec<PathBuf>> = HashMap::new();
//     for (hash, path) in hashes {
//         map.entry(hash).or_default().push(path);
//     }
//     let _ = std::fs::write(
//     cache_path,
//     serde_json::to_string_pretty(&new_cache).unwrap()
//     );
//     map
// }

fn group_duplicates_parallel(files: Vec<PathBuf>, algo: &HashAlgo) -> HashMap<String, Vec<PathBuf>> {
    let args: Vec<String> = std::env::args().collect();
    let folder = args.get(1).expect("Please provide a folder path"); 
    let cache_path = format!("{}/.dedup_cache.json", folder);
    
    println!("🔄 Loading cache...");
    let cache_map: HashMap<String, CachedFile> = if let Ok(data) = std::fs::read_to_string(&cache_path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        HashMap::new()
    };
    
    let cache_map = Arc::new(cache_map);
    let new_cache = Arc::new(Mutex::new(HashMap::<String, CachedFile>::new()));
    let progress_counter = Arc::new(AtomicUsize::new(0));
    let total_files = files.len();
    
    println!("🔄 Hashing {} files in parallel using {} threads...", total_files, rayon::current_num_threads());
    
    let hashes_and_cache: Vec<((String, PathBuf), Option<CachedFile>)> = files
        .into_par_iter()
        .filter_map(|path| {
            let current = progress_counter.fetch_add(1, Ordering::Relaxed);
            if current % 100 == 0 || current == total_files - 1 {
                println!("📊 Hashing progress: {}/{} files", current + 1, total_files);
            }

            let meta = path.metadata().ok()?;
            let modified = meta.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
            let size = meta.len();
            let path_str = path.display().to_string();

            // Check cache
            if let Some(cached) = cache_map.get(&path_str) {
                if cached.modified == modified && cached.size == size {
                    return Some(((cached.hash.clone(), path), None));
                }
            }

            // Cache miss - calculate new hash
            let hash = hash_file(&path, algo)?;
            let cached_file = CachedFile {
                path: path_str.clone(),
                modified,
                size,
                hash: hash.clone(),
            };

            Some(((hash, path), Some(cached_file)))
        })
        .collect();

    println!("✅ Hashing completed! Updating cache...");

    // Update cache with new entries
    for ((_, _), cache_entry) in &hashes_and_cache {
        if let Some(cached_file) = cache_entry {
            let mut cache = new_cache.lock().unwrap();
            cache.insert(cached_file.path.clone(), cached_file.clone());
        }
    }

    // Group files by hash
    let mut map: HashMap<String, Vec<PathBuf>> = HashMap::new();
    for ((hash, path), _) in hashes_and_cache {
        map.entry(hash).or_default().push(path);
    }

    // Save updated cache
    let final_cache = new_cache.lock().unwrap();
    let _ = std::fs::write(
        cache_path,
        serde_json::to_string_pretty(&*final_cache).unwrap()
    );

    println!("✅ Found {} duplicate groups", 
        map.iter().filter(|(_, paths)| paths.len() > 1).count());

    map
}

// fn save_json_report(path: &str, map: HashMap<String, Vec<PathBuf>>, saved_bytes: u64) {
//     let groups: Vec<DuplicateGroup> = map.into_iter()
//         .filter(|(_, files)| files.len() > 1)
//         .map(|(hash, files)| {
//             let file_strs: Vec<String> = files.iter().map(|p| p.display().to_string()).collect();
            
//             // DEBUG: Show what we're processing
//             println!("DEBUG: Processing group with hash: {}", hash);
//             println!("DEBUG: Files: {:?}", file_strs);
            
//             let similarity = calculate_similarity_for_group(&files);
            
//             // DEBUG: Show calculated similarity
//             println!("DEBUG: Calculated similarity: {:?}", similarity);

//             DuplicateGroup {
//                 hash,
//                 similarity,
//                 files: file_strs,
//             }
//         })
//         .collect();

//     let report = FullReport {
//         saved_bytes,
//         saved_mb: saved_bytes as f64 / (1024.0 * 1024.0),
//         groups,
//     };

//     let json = serde_json::to_string_pretty(&report).unwrap();
//     std::fs::write(path, json).expect("Failed to write JSON report");
//     println!("\nSaved JSON report to {}", path);
// }

fn edit_distance(a: &str, b: &str) -> usize {
    let mut dp = vec![vec![0; b.len() + 1]; a.len() + 1];

    for i in 0..=a.len() {
        dp[i][0] = i;
    }
    for j in 0..=b.len() {
        dp[0][j] = j;
    }

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


fn quarantine_duplicates(map: HashMap<String, Vec<PathBuf>>, base_dir: &str, dry_run: bool) -> u64 {
    let mut total_saved: u64 = 0;
    let quarantine_dir = PathBuf::from(format!("{}/.quarantine", base_dir));
    let mut log: Vec<QuarantineLogEntry> = Vec::new();

    for files in map.values() {
        if files.len() < 2 {
            continue;
        }
        for file in files.iter().skip(1) {
            if let Ok(meta) = file.metadata() {
                total_saved += meta.len();
            }

            let filename = file.file_name().unwrap();
            let dest = quarantine_dir.join(filename);

            if dry_run {
                println!("[Dry Run] Would quarantine: {}", file.display());
            } else {
                std::fs::create_dir_all(&quarantine_dir).expect("Failed to create quarantine folder");
                if let Err(e) = std::fs::rename(file, &dest) {
                    eprintln!("Failed to quarantine {}: {}", file.display(), e);
                } else {
                    println!("Quarantined: {}", file.display());
                    log.push(QuarantineLogEntry {
                        original: file.display().to_string(),
                        quarantined: dest.display().to_string(),
                    });
                }
            }
        }
    }

    if !dry_run && !log.is_empty() {
        let log_path = format!("{}/.quarantine_log.json", base_dir);
        let json = serde_json::to_string_pretty(&log).unwrap();
        std::fs::write(log_path, json).expect("Failed to write quarantine log");
    }

    if dry_run {
        println!("\n[Dry Run] No files were moved.");
    }
    total_saved
}

fn fuzzy_text_match(paths: &[PathBuf], threshold: usize) -> HashMap<String, Vec<PathBuf>> {
    let mut groups: Vec<Vec<PathBuf>> = Vec::new();

    for path in paths {
        let content = fs::read_to_string(path).unwrap_or_default();
        let mut matched = false;

        for group in &mut groups {
            let first = fs::read_to_string(&group[0]).unwrap_or_default();
            let distance = strsim::levenshtein(&first, &content);
            if distance < threshold {
                group.push(path.clone());
                matched = true;
                break;
            }
        }

        if !matched {
            groups.push(vec![path.clone()]);
        }
    }

    let mut result = HashMap::new();
    for group in groups {
        if group.len() > 1 {
            let id = group[0].display().to_string();
            result.insert(id, group);
        }
    }

    result
}

// fn fuzzy_image_match(paths: &[PathBuf], threshold: u32) -> HashMap<String, Vec<PathBuf>> {
//     let hasher = HasherConfig::new().hash_alg(HashAlg::Gradient).to_hasher();
//     let mut groups: Vec<Vec<PathBuf>> = Vec::new();

//     for path in paths {
//         if let Ok(img) = img_hash::image::open(path) {
//             let hash = hasher.hash_image(&img);
//             let mut matched = false;

//             for group in &mut groups {
//                 if let Ok(existing_img) = img_hash::image::open(&group[0]) {
//                     let existing_hash = hasher.hash_image(&existing_img);
//                     let distance = hash.dist(&existing_hash);
//                     let bits = hash.as_bytes().len() * 8;
//                     let similarity = 100.0 - (distance as f64 * 100.0 / bits as f64);

//                     if distance <= threshold {
//                         println!(" 🖼️ Fuzzy match: {} and {} (similarity: {:.2}%)", 
//                             group[0].display(), path.display(), similarity);
//                         group.push(path.clone());
//                         matched = true;
//                         break;
//                     }
//                 }
//             }

//             if !matched {
//                 groups.push(vec![path.clone()]);
//             }
//         }
//     }

//     // Convert groups to HashMap format
//     let mut result = HashMap::new();
//     for group in groups {
//         if group.len() > 1 {
//             let key = format!("fuzzy_img_{}", group[0].display());
//             result.insert(key, group);
//         }
//     }

//     result
// }

fn fuzzy_image_match_parallel(paths: &[PathBuf], threshold: u32) -> HashMap<String, Vec<PathBuf>> {
    if paths.len() < 2 {
        return HashMap::new();
    }

    println!("🔍 Running parallel fuzzy image matching on {} images...", paths.len());
    
    use img_hash::{HasherConfig, HashAlg};
    let progress_counter = Arc::new(AtomicUsize::new(0));
    
    // Parallel hashing phase - create hasher in each thread
    let hash_results: Vec<_> = paths
        .par_iter()
        .map(|path| {
            let current = progress_counter.fetch_add(1, Ordering::Relaxed);
            if current % 50 == 0 || current == paths.len() - 1 {
                println!("📊 Hashing progress: {}/{} images", current + 1, paths.len());
            }

            // Create a new hasher for each thread
            let hasher = HasherConfig::new().hash_alg(HashAlg::Gradient).to_hasher();
            
            match img_hash::image::open(path) {
                Ok(img) => Some((path.clone(), hasher.hash_image(&img))),
                Err(_) => None,
            }
        })
        .collect();

    let valid_hashes: Vec<_> = hash_results.into_iter().flatten().collect();
    
    if valid_hashes.len() < 2 {
        return HashMap::new();
    }

    println!("✅ Hashed {}/{} images successfully", valid_hashes.len(), paths.len());

    // Parallel comparison phase
    let groups = Arc::new(Mutex::new(Vec::<Vec<PathBuf>>::new()));
    let processed = Arc::new(Mutex::new(std::collections::HashSet::<PathBuf>::new()));
    let comparison_counter = Arc::new(AtomicUsize::new(0));

    (0..valid_hashes.len()).into_par_iter().for_each(|i| {
        let (ref path1, ref hash1) = valid_hashes[i];
        
        // Check if already processed
        {
            let proc = processed.lock().unwrap();
            if proc.contains(path1) {
                return;
            }
        }

        let mut current_group = vec![path1.clone()];

        // Find similar images
        for j in i+1..valid_hashes.len() {
            let (ref path2, ref hash2) = valid_hashes[j];
            
            {
                let proc = processed.lock().unwrap();
                if proc.contains(path2) {
                    continue;
                }
            }

            let distance = hash1.dist(hash2);
            let current = comparison_counter.fetch_add(1, Ordering::Relaxed);
            if current % 1000 == 0 {
                println!("📊 Comparison progress: {} comparisons completed", current);
            }

            if distance <= threshold {
                current_group.push(path2.clone());
                
                // Mark as processed
                let mut proc = processed.lock().unwrap();
                proc.insert(path2.clone());
            }
        }

        if current_group.len() > 1 {
            let similarity = 100.0 - (hash1.dist(&valid_hashes.iter()
                .find(|(p, _)| p == &current_group[1]).unwrap().1) as f64 * 100.0 / 64.0);
            
            println!(" 🖼️ Fuzzy match: {} files (similarity: {:.2}%)", 
                     current_group.len(), similarity);

            let mut groups_lock = groups.lock().unwrap();
            groups_lock.push(current_group);
        }

        // Mark first image as processed
        let mut proc = processed.lock().unwrap();
        proc.insert(path1.clone());
    });

    // Convert to HashMap format
    let final_groups = groups.lock().unwrap();
    let mut result = HashMap::new();
    
    for (_i, group) in final_groups.iter().enumerate() {
        let key = format!("fuzzy_img_{}", group[0].display());
        result.insert(key, group.clone());
    }

    println!("✅ Fuzzy matching completed! Found {} groups", result.len());
    result
}

// Stub for undo_quarantine (implement as needed)
fn undo_quarantine(base_dir: &str) {
    let log_path = format!("{}/.quarantine_log.json", base_dir);
    let log_data = match std::fs::read_to_string(&log_path) {
        Ok(data) => data,
        Err(_) => {
            println!("No quarantine log found.");
            return;
        }
    };

    let entries: Vec<QuarantineLogEntry> = match serde_json::from_str(&log_data) {
        Ok(e) => e,
        Err(_) => {
            println!("Failed to parse quarantine log.");
            return;
        }
    };

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

    // Optionally, remove the quarantine log after restoring
    let _ = std::fs::remove_file(&log_path);
}
fn print_similarity_for_group(paths: &Vec<PathBuf>) {
    if paths.len() < 2 {
        return;
    }

    println!("DEBUG: Checking similarity for {} files", paths.len());
    for p in paths {
        println!("DEBUG: File: {} (ext: {:?})", p.display(), p.extension());
    }

    // Check if all files are text files
    let all_txt = paths.iter().all(|f| f.extension().map(|e| e == "txt").unwrap_or(false));
    println!("DEBUG: All text files: {}", all_txt);
    
    if all_txt {
        let contents: Vec<String> = paths.iter()
            .map(|f| std::fs::read_to_string(f).unwrap_or_default())
            .collect();

        let mut total_similarity = 0.0;
        let mut comparisons = 0;

        for i in 0..contents.len() {
            for j in i+1..contents.len() {
                let a = contents[i].replace("\r\n", "\n").trim().to_string();
                let b = contents[j].replace("\r\n", "\n").trim().to_string();
                let max_len = a.len().max(b.len()).max(1);
                let dist = edit_distance(&a, &b);
                let sim = 100.0 - (dist as f64 * 100.0 / max_len as f64);
                println!("   Text similarity between {} and {}: {:.2}%", 
                    paths[i].display(), paths[j].display(), sim);
                total_similarity += sim;
                comparisons += 1;
            }
        }

        if comparisons > 0 {
            println!("   Average text similarity: {:.2}%", total_similarity / comparisons as f64);
        }
        return;
    }

    // Check if all files are images
    let all_img = paths.iter().all(|f| {
        f.extension()
            .and_then(|e| e.to_str())
            .map(|e| {
                let e = e.to_ascii_lowercase();
                e == "jpg" || e == "jpeg" || e == "png" || e == "gif" || e == "bmp"
            })
            .unwrap_or(false)
    });
    println!("DEBUG: All image files: {}", all_img);

    if all_img {
        println!("DEBUG: Processing image similarity...");
        use img_hash::{HasherConfig, HashAlg};
        let hasher = HasherConfig::new().hash_alg(HashAlg::Gradient).to_hasher();
        let mut hashes = Vec::new();
        
        // Generate hashes for all images
        for p in paths {
            match img_hash::image::open(p) {
                Ok(img) => {
                    hashes.push((p, hasher.hash_image(&img)));
                    println!("DEBUG: Successfully hashed image: {}", p.display());
                }
                Err(e) => {
                    println!("DEBUG: Failed to open image {}: {}", p.display(), e);
                }
            }
        }
        
        if hashes.len() < 2 {
            println!("   Could not calculate image similarity (only {} images loaded)", hashes.len());
            return;
        }
        
        let mut total_similarity = 0.0;
        let mut comparisons = 0;
        
        for i in 0..hashes.len() {
            for j in i+1..hashes.len() {
                let dist = hashes[i].1.dist(&hashes[j].1);
                let bits = hashes[i].1.as_bytes().len() * 8;
                let sim = 100.0 - (dist as f64 * 100.0 / bits as f64);
                println!("   Image similarity between {} and {}: {:.2}%", 
                    hashes[i].0.display(), hashes[j].0.display(), sim);
                total_similarity += sim;
                comparisons += 1;
            }
        }
        
        if comparisons > 0 {
            println!("   Average image similarity: {:.2}%", total_similarity / comparisons as f64);
        }
    } else {
        println!("DEBUG: Mixed file types or non-image files");
        // For mixed file types or exact duplicates
        println!("   File similarity: 100.00% (exact duplicates)");
    }
}


fn calculate_similarity_for_group(paths: &Vec<PathBuf>) -> Option<f64> {
    println!("DEBUG: calculate_similarity_for_group called with {} files", paths.len());
    
    if paths.len() < 2 {
        println!("DEBUG: Less than 2 files, returning None");
        return None;
    }

    // Check if all files are text files
    if paths.iter().all(|f| f.extension().map(|e| e == "txt").unwrap_or(false)) {
        println!("DEBUG: Processing text similarity...");
        let contents: Vec<String> = paths.iter()
            .map(|f| {
                match std::fs::read_to_string(f) {
                    Ok(content) => {
                        println!("DEBUG: Successfully read text file: {}", f.display());
                        content
                    }
                    Err(e) => {
                        println!("DEBUG: Failed to read text file {}: {}", f.display(), e);
                        String::new()
                    }
                }
            })
            .collect();

        let mut total_similarity = 0.0;
        let mut comparisons = 0;

        for i in 0..contents.len() {
            for j in i+1..contents.len() {
                let a = contents[i].replace("\r\n", "\n").trim().to_string();
                let b = contents[j].replace("\r\n", "\n").trim().to_string();
                
                if a == b {
                    println!("DEBUG: Text files are identical");
                    total_similarity += 100.0;
                } else {
                    let max_len = a.len().max(b.len()).max(1);
                    let dist = edit_distance(&a, &b);
                    let sim = 100.0 - (dist as f64 * 100.0 / max_len as f64);
                    println!("DEBUG: Text similarity calculated: {:.2}%", sim);
                    total_similarity += sim;
                }
                comparisons += 1;
            }
        }

        if comparisons > 0 {
            let avg = total_similarity / comparisons as f64;
            println!("DEBUG: Average text similarity: {:.2}%", avg);
            return Some(avg);
        } else {
            println!("DEBUG: No text comparisons made, returning 100.0");
            return Some(100.0);
        }
    }

    // Check if all files are images - USE PARALLEL VERSION
    if paths.iter().all(|f| {
        f.extension()
            .and_then(|e| e.to_str())
            .map(|e| {
                let e = e.to_ascii_lowercase();
                e == "jpg" || e == "jpeg" || e == "png" || e == "gif" || e == "bmp"
            })
            .unwrap_or(false)
    }) {
        return calculate_image_similarity_parallel(paths);
    }

    println!("DEBUG: Mixed files or exact duplicates, returning 100.0");
    Some(100.0)
}

// fn compute_similarity(files: &[PathBuf]) -> Option<f64> {
//     if files.len() < 2 {
//         return None;
//     }

//     // Text files
//     let all_txt = files.iter().all(|f| f.extension().map(|e| e == "txt").unwrap_or(false));
//     if all_txt {
//         let contents: Vec<String> = files.iter()
//             .map(|f| std::fs::read_to_string(f).unwrap_or_default())
//             .collect();

//         let mut total_similarity = 0.0;
//         let mut comparisons = 0;

//         for i in 0..contents.len() {
//             for j in i+1..contents.len() {
//                 let a = contents[i].replace("\r\n", "\n").trim().to_string();
//                 let b = contents[j].replace("\r\n", "\n").trim().to_string();
//                 let max_len = a.len().max(b.len()).max(1);
//                 let dist = edit_distance(&a, &b);
//                 let sim = 100.0 - (dist as f64 * 100.0 / max_len as f64);
//                 total_similarity += sim;
//                 comparisons += 1;
//             }
//         }

//         return if comparisons > 0 {
//             Some(total_similarity / comparisons as f64)
//         } else {
//             Some(100.0)
//         };
//     }

//     // Image files
//     let all_img = files.iter().all(|f| {
//         f.extension()
//             .and_then(|e| e.to_str())
//             .map(|e| {
//                 let e = e.to_ascii_lowercase();
//                 e == "jpg" || e == "jpeg" || e == "png" || e == "gif" || e == "bmp"
//             })
//             .unwrap_or(false)
//     });

//     if all_img {
//         let hasher = HasherConfig::new().hash_alg(HashAlg::Gradient).to_hasher();
//         let mut hashes = Vec::new();

//         for p in files {
//             if let Ok(img) = img_hash::image::open(p) {
//                 hashes.push(hasher.hash_image(&img));
//             }
//         }

//         if hashes.len() < 2 {
//             return None;
//         }

//         let mut total_similarity = 0.0;
//         let mut comparisons = 0;

//         for i in 0..hashes.len() {
//             for j in i+1..hashes.len() {
//                 let dist = hashes[i].dist(&hashes[j]);
//                 let bits = hashes[i].as_bytes().len() * 8;
//                 let sim = 100.0 - (dist as f64 * 100.0 / bits as f64);
//                 total_similarity += sim;
//                 comparisons += 1;
//             }
//         }

//         return if comparisons > 0 {
//             Some(total_similarity / comparisons as f64)
//         } else {
//             Some(100.0)
//         };
//     }

//     // Mixed/other file types (e.g., binary): consider exact duplicate
//     Some(100.0)
// }

fn main() {
    // Configure optimal thread pool
    let num_threads = num_cpus::get();
    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()
        .expect("Failed to initialize thread pool");
    
    println!("🚀 Starting parallel deduplicator with {} threads", num_threads);
    let start_time = std::time::Instant::now();

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

    println!("Scanning folder: {}", folder);
    if let Some(ref rgx) = regex_pattern {
        println!("Using regex filter: {}", rgx);
    } else {
        println!("No regex filter applied. Scanning all files.");
    }

    // Use parallel file collection
    let all_files = collect_all_files_parallel(
        folder,
        &FileFilter {
            min_size: Some(1),
            max_size: None,
            allowed_extensions: None,
            modified_after: None,
        },
        regex_pattern.as_ref(),
    );

    // Parallel file type classification
    let (images, texts): (Vec<_>, Vec<_>) = all_files
        .par_iter()
        .partition_map(|path| {
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                let ext = ext.to_ascii_lowercase();
                if ext == "jpg" || ext == "jpeg" || ext == "png" || ext == "gif" || ext == "bmp" {
                    rayon::iter::Either::Left(path.clone())
                } else if ext == "txt" {
                    rayon::iter::Either::Right(path.clone())
                } else {
                    rayon::iter::Either::Right(path.clone())
                }
            } else {
                rayon::iter::Either::Right(path.clone())
            }
        });

    println!("Found {} files total", all_files.len());
    println!("Images found: {}", images.len());
    println!("Texts found: {}", texts.len());

    // Use parallel hashing
    let mut duplicates_map = group_duplicates_parallel(all_files.clone(), &hash_algo);
    
    if use_fuzzy {
        println!("DEBUG: Running parallel fuzzy matching...");
        let fuzzy_text = fuzzy_text_match(&texts, 10);
        println!("DEBUG: Fuzzy text groups: {}", fuzzy_text.len());
        for (k, v) in fuzzy_text {
            duplicates_map.entry(k).or_default().extend(v);
        }

        // Use parallel fuzzy image matching
        let fuzzy_img = fuzzy_image_match_parallel(&images, 10);
        println!("DEBUG: Fuzzy image groups: {}", fuzzy_img.len());
        for (k, v) in fuzzy_img {
            duplicates_map.entry(k).or_default().extend(v);
        }
    }

    let processing_time = start_time.elapsed();
    println!("⏱️  Processing completed in {:.2?}", processing_time);

    // Store similarity values as we calculate them
    let mut similarity_cache: HashMap<String, f64> = HashMap::new();

    for (hash, paths) in &duplicates_map {
        if paths.len() > 1 {
            println!("\nDuplicate group (hash: {}):", &hash[..10.min(hash.len())]);
            for p in paths {
                println!(" - {}", p.display());
            }

            // Debug text files specifically
            if paths.iter().all(|f| f.extension().map(|e| e == "txt").unwrap_or(false)) {
                debug_text_files(paths);
            }

            // Calculate and store similarity BEFORE quarantining
            if let Some(similarity) = calculate_similarity_for_group(paths) {
                similarity_cache.insert(hash.clone(), similarity);
                println!("DEBUG: Cached similarity for {}: {:.2}%", hash, similarity);
            }

            print_similarity_for_group(paths);
        }
    }

    if args.contains(&"--undo".to_string()) {
        undo_quarantine(folder);
        return;
    }

    let total_saved_bytes = quarantine_duplicates(duplicates_map.clone(), folder, dry_run);
    
    // Pass the cached similarities to the report function
    save_json_report_with_cache("report.json", duplicates_map.clone(), total_saved_bytes, similarity_cache);

    if !dry_run {
        let mb = total_saved_bytes as f64 / (1024.0 * 1024.0);
        println!("\n✅ Saved {:.2} MB by removing duplicates", mb);
    } else {
        println!("\n(Dry Run) Total potential space saving: {:.2} MB", total_saved_bytes as f64 / (1024.0 * 1024.0));
    }

    println!("\nTotal duplicate groups found: {}", 
        duplicates_map.iter().filter(|(_, paths)| paths.len() > 1).count());
}
fn save_json_report_with_cache(path: &str, map: HashMap<String, Vec<PathBuf>>, saved_bytes: u64, similarity_cache: HashMap<String, f64>) {
    let groups: Vec<DuplicateGroup> = map.into_iter()
        .filter(|(_, files)| files.len() > 1)
        .map(|(hash, files)| {
            let file_strs: Vec<String> = files.iter().map(|p| p.display().to_string()).collect();
            
            // Use cached similarity instead of recalculating
            let similarity = similarity_cache.get(&hash).copied();
            
            println!("DEBUG: Using cached similarity for {}: {:?}", hash, similarity);

            DuplicateGroup {
                hash,
                similarity,
                files: file_strs,
            }
        })
        .collect();

    let report = FullReport {
        saved_bytes,
        saved_mb: saved_bytes as f64 / (1024.0 * 1024.0),
        groups,
    };

    let json = serde_json::to_string_pretty(&report).unwrap();
    std::fs::write(path, json).expect("Failed to write JSON report");
    println!("\nSaved JSON report to {}", path);
}
fn debug_text_files(paths: &Vec<PathBuf>) {
    println!("\n=== DEBUG: Text File Contents ===");
    for (i, path) in paths.iter().enumerate() {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                let preview = if content.len() > 100 {
                    format!("{}...", &content[..100])
                } else {
                    content.clone()
                };
                println!("File {}: {} ({} bytes)", i+1, path.display(), content.len());
                println!("Content preview: {:?}", preview);
                println!("---");
            }
            Err(e) => {
                println!("File {}: {} - ERROR: {}", i+1, path.display(), e);
            }
        }
    }
    println!("=== END DEBUG ===\n");
}

fn collect_all_files_parallel(dir: &str, filter: &FileFilter, regex: Option<&Regex>) -> Vec<PathBuf> {
    println!("🔄 Scanning files in parallel...");
    
    WalkDir::new(dir)
        .into_iter()
        .par_bridge()  // Convert to parallel iterator
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();

            // Skip .quarantine and hidden folders
            if path.components().any(|c| c.as_os_str() == ".quarantine") {
                return None;
            }
            if entry.file_type().is_dir() {
                return None;
            }

            let meta = entry.metadata().ok()?;
            let size = meta.len();
            let modified = meta.modified().ok()?;

            if let Some(min) = filter.min_size {
                if size < min {
                    return None;
                }
            }

            if let Some(max) = filter.max_size {
                if size > max {
                    return None;
                }
            }

            if let Some(after) = filter.modified_after {
                if modified < after {
                    return None;
                }
            }

            if let Some(ref exts) = filter.allowed_extensions {
                let file_ext = entry.path().extension()?.to_str()?.to_lowercase();
                if !exts.contains(&file_ext) {
                    return None;
                }
            }

            if let Some(rgx) = regex {
                let filename = entry.file_name().to_string_lossy();
                if !rgx.is_match(&filename) {
                    return None;
                }
            }

            Some(path.to_path_buf())
        })
        .collect()
}

fn calculate_image_similarity_parallel(paths: &Vec<PathBuf>) -> Option<f64> {
    if paths.len() < 2 {
        return None;
    }

    println!("🖼️  Calculating image similarity for {} images in parallel...", paths.len());
    
    use img_hash::{HasherConfig, HashAlg};
    
    // Parallel image hashing - create hasher in each thread
    let hash_results: Vec<_> = paths
        .par_iter()
        .map(|path| {
            // Create a new hasher for each thread
            let hasher = HasherConfig::new().hash_alg(HashAlg::Gradient).to_hasher();
            
            match img_hash::image::open(path) {
                Ok(img) => {
                    let hash = hasher.hash_image(&img);
                    Some((path.clone(), hash))
                }
                Err(e) => {
                    println!("⚠️  Failed to load {}: {}", path.display(), e);
                    None
                }
            }
        })
        .collect();

    let hashes: Vec<_> = hash_results.into_iter().flatten().collect();

    if hashes.len() < 2 {
        return Some(100.0); // Exact duplicates
    }

    println!("✅ Successfully hashed {}/{} images", hashes.len(), paths.len());

    // Parallel similarity calculation - FIX: Clone variables before moving
    let total_comparisons = hashes.len() * (hashes.len() - 1) / 2;
    let progress_counter = Arc::new(AtomicUsize::new(0));
    
    // Create all comparison pairs first
    let mut pairs = Vec::new();
    for i in 0..hashes.len() {
        for j in i+1..hashes.len() {
            pairs.push((i, j));
        }
    }
    
    let similarities: Vec<f64> = pairs
        .into_par_iter()
        .map(|(i, j)| {
            let dist = hashes[i].1.dist(&hashes[j].1);
            let bits = hashes[i].1.as_bytes().len() * 8;
            let sim = 100.0 - (dist as f64 * 100.0 / bits as f64);
            
            let current = progress_counter.fetch_add(1, Ordering::Relaxed);
            if current % 50 == 0 || current == total_comparisons - 1 {
                println!("📊 Similarity progress: {}/{} comparisons", current + 1, total_comparisons);
            }
            
            sim
        })
        .collect();

    if !similarities.is_empty() {
        let avg = similarities.iter().sum::<f64>() / similarities.len() as f64;
        println!("✅ Average image similarity: {:.2}%", avg);
        Some(avg)
    } else {
        Some(100.0)
    }
}
