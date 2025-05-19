from pathlib import Path
import argparse

def scan_txt_files(directory, min_size_kb=0):
    directory = Path(directory)
    if not directory.exists():
        print("Directory does not exist.")
        return

    txt_files = list(directory.rglob("*.txt"))

    print(f"\nScanning: {directory.resolve()}")
    print(f"Found {len(txt_files)} text files (before filtering):\n")

    # Filter files based on min_size_kb
    filtered_files = []
    total_size = 0

    for file in txt_files:
        size_kb = file.stat().st_size / 1024
        if size_kb >= min_size_kb:
            filtered_files.append((file, size_kb))
            total_size += size_kb

    print(f"{'File':<40} {'Size (KB)':>10}")
    print("-" * 52)

    for file, size_kb in filtered_files:
        print(f"{str(file.relative_to(directory)):<40} {size_kb:>10.1f}")

    print("-" * 52)
    print(f"Total size: {total_size:.1f} KB")
    print(f"Files shown: {len(filtered_files)}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Recursively scan directory for .txt files.")
    parser.add_argument("path", help="Path to directory to scan")
    parser.add_argument("--min-size", type=float, default=0, help="Minimum file size in KB to include")
    args = parser.parse_args()
    scan_txt_files(args.path, args.min_size)