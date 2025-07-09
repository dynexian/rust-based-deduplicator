# Rust-Based File Deduplicator

A high-performance, parallel file deduplicator that can find exact and fuzzy duplicates across different file types including images and text files.

## Features

- **🚀 Parallel processing** for maximum performance using all CPU cores
- **🔐 Multiple hash algorithms** (Blake3, SHA256, XXHash) for file comparison
- **🔍 Fuzzy matching** for similar files (text similarity and image perceptual hashing)
- **💾 Smart caching** to avoid re-hashing unchanged files
- **🛡️ Safe quarantine system** with restore capability (no permanent deletion)
- **📊 Detailed reporting** in JSON format with similarity percentages
- **🎯 Flexible filtering** with regex patterns and file type support

## Installation

### Prerequisites
- Rust 1.70+ 
- Cargo package manager

### Build from source
```bash
git clone https://github.com/your-username/rust-based-deduplicator.git
cd rust-based-deduplicator
cargo build --release
```

## Usage

### Basic Commands

```bash
# Scan for exact duplicates
cargo run -- ./test_folder

# Enable fuzzy matching for similar files
cargo run -- ./test_folder --fuzzy

# Preview mode (no files moved)
cargo run -- ./test_folder --dry-run

# Restore quarantined files
cargo run -- ./test_folder --undo
```

### Advanced Usage

```bash
# Use specific hash algorithm
cargo run -- ./test_folder --hash sha256

# Filter by file extension
cargo run -- ./test_folder --regex ".*\\.txt$"

# Target specific image patterns
cargo run -- ./test_folder --regex "^img[0-9]+\\.jpg$"

# Fuzzy matching with filtering
cargo run -- ./test_folder --fuzzy --regex ".*backup.*"

# Combined options
cargo run -- ./test_folder --fuzzy --dry-run --hash blake3
```

## Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `folder_path` | Directory to scan | `./my_documents` |
| `--fuzzy` | Enable fuzzy matching for similar files | `--fuzzy` |
| `--dry-run` | Preview mode (no files moved) | `--dry-run` |
| `--hash <algo>` | Hash algorithm: `blake3`, `sha256`, `xxhash` | `--hash sha256` |
| `--regex <pattern>` | Filter files by regex pattern | `--regex ".*\\.txt$"` |
| `--undo` | Restore all quarantined files | `--undo` |

## How It Works

### 1. File Discovery
- Recursively scans directories
- Applies filters (regex, file types, sizes)
- Skips quarantine directories automatically

### 2. Duplicate Detection
- **Exact matching**: Uses cryptographic hashes (Blake3, SHA256, XXHash)
- **Fuzzy text matching**: Uses edit distance algorithm with configurable similarity threshold
- **Fuzzy image matching**: Uses perceptual hashing to find visually similar images

### 3. Safe Quarantine System
- Moves duplicates to `.quarantine` folder instead of deleting
- Preserves original directory structure
- Creates restoration log for undo capability
- Never touches the first file in each duplicate group

### 4. Performance Features
- **Parallel processing**: Utilizes all CPU cores
- **Smart caching**: Avoids re-hashing unchanged files using `.dedup_cache.json`
- **Memory efficient**: Streams large files with 8KB buffer
- **Progress reporting**: Shows real-time processing status

## Output Files

- **`report.json`**: Detailed duplicate groups with similarity percentages
- **`.quarantine/`**: Folder containing quarantined duplicate files
- **`.quarantine_log.json`**: Log for restoring quarantined files
- **`.dedup_cache.json`**: Cache to speed up subsequent runs

## Example Workflow

```bash
# 1. Initial scan with preview
cargo run -- ./my_photos --fuzzy --dry-run

# 2. Run actual deduplication
cargo run -- ./my_photos --fuzzy

# 3. Check the generated report
cat report.json

# 4. If needed, restore files
cargo run -- ./my_photos --undo
```

## File Type Support

### Text Files
- **Extensions**: `.txt`, `.md`, `.log`, `.cfg`, etc.
- **Fuzzy matching**: Edit distance with 80% similarity threshold
- **Normalization**: Handles different line endings and whitespace

### Image Files
- **Extensions**: `.jpg`, `.jpeg`, `.png`, `.gif`, `.bmp`
- **Fuzzy matching**: Perceptual hashing with configurable distance threshold
- **Detection**: Finds visually similar images regardless of format/size differences

### All Other Files
- **Method**: Exact hash comparison
- **Algorithms**: Blake3 (default), SHA256, XXHash

## Safety Features

- **No permanent deletion**: Files are quarantined, not deleted
- **Undo capability**: Complete restoration of quarantined files
- **Dry run mode**: Preview changes before applying
- **Original preservation**: Always keeps the first file in each duplicate group
- **Directory structure**: Preserved in quarantine folder

## Performance Tips

- Use **Blake3** hash (default) for best speed/security balance
- Enable **fuzzy matching** only when needed (slower but finds more duplicates)
- Use **regex filtering** to focus on specific file types
- **Cache files** (`.dedup_cache.json`) speed up repeated scans significantly

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit changes: `git commit -am 'Add feature'`
4. Push to branch: `git push origin feature-name`
5. Submit a pull request

## License

This project is licensed under the MIT License.

## Acknowledgments


### Special Thanks
This project was developed as part of an internship mini project. Special gratitude to my mentors who guided me through learning Rust and provided invaluable support:

- **[Sourav Mishra](https://www.linkedin.com/in/web3-mishra/)**
- **[Mahavir Ganpati Dash](https://www.linkedin.com/in/crypto-priest/)**
- **[Sumeet Naik](https://www.linkedin.com/in/sumeetnaik19/)**


Their mentorship went beyond just teaching Rust - they provided thoughtful guidance, collaborative support, and always focused on what would genuinely help us grow as developers. Their friendly approach and future-oriented thinking made this learning journey both enjoyable and meaningful.

This project will continue to be developed and enhanced with new features and optimizations.

## Future Development
This deduplicator is actively being developed with planned features including:
- GUI interface for easier usage
- More file type support (videos, documents)
- Advanced similarity algorithms
- Performance optimizations
