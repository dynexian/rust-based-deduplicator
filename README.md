Example CLI Usage

cargo run -- ./test_folder
 * Scans all files


cargo run -- ./test_folder --regex ".*\\.txt$"
 * Only .txt files


cargo run -- ./test_folder --regex "^img[0-9]+\\.jpg$"
 * Only files like img1.jpg, img2.jpg


cargo run -- ./test_folder
🔹 Only exact matching


cargo run -- ./test_folder --fuzzy
🔹 Fuzzy match text & images


cargo run -- ./test_folder --fuzzy --regex ".*backup.*"
🔹 Fuzzy + only files with “backup” in name

