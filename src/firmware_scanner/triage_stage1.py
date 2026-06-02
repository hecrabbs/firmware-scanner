from pathlib import Path
import subprocess


def _find_root(extracted_dir: Path) -> Path:
    """
    Recursively searches an extraction directory for the true Linux root filesystem.
    Looks for the directory that contains the classic IoT configuration/binary layout.
    """
    # Essential directories that must coexist in a true Linux root filesystem
    critical_markers = {"etc", "bin", "sbin"}

    # Track candidate directories and how many markers they match
    candidates = []

    # rglob('*') finds every single file and folder recursively
    for path in extracted_dir.rglob('*'):
        if path.is_dir():
            # Check which of our critical markers exist directly inside this directory
            subdirs = {child.name for child in path.iterdir() if child.is_dir()}
            matches = critical_markers.intersection(subdirs)

            if matches:
                # Store the path along with the number of matched markers
                candidates.append((path, len(matches)))

    if candidates:
        # Sort candidates so the directory matching the most markers comes first
        # If there's a tie, pick the shortest path (closest to the extraction root)
        candidates.sort(key=lambda x: (-x[1], len(x[0].parts)))
        true_root = candidates[0][0]
        print(f"[+] Automated Root Finder located the OS root at: /{true_root.relative_to(extracted_dir)}")
        return true_root

    # Fallback: If no markers match, default back to the raw extraction folder
    print("[!] Warning: Could not confidently locate a standard Linux root filesystem. Using base path.")
    return extracted_dir

def triage_stage1(extracted_dir: Path):
    root_dir = _find_root(extracted_dir)

    # Get filetree
    result = subprocess.run(["tree", root_dir], capture_output=True, text=True)
    tree = result.stdout
    # tree_lines = _generate_compact_tree(root_dir)
    # tree = "\n".join(tree_lines)
    # print(tree)
