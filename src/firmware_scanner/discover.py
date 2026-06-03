import os
import subprocess
from pathlib import Path

from google import genai


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

def discover(extracted_dir: Path, client: genai.Client):
    print(f"\n[*] Running agentic discovery...")

    root_dir = _find_root(extracted_dir)
    # Get filetree
    try:
        tree_result = subprocess.run(["tree", "-h", "--du", '.'],
                                    cwd=root_dir,
                                    capture_output=True,
                                    text=True,
                                    check=True)
        tree_str = tree_result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running tree: {e.stderr}")
        tree_str = "Error running tree."

    prompt = (
        "You are an expert firmware security analyst specializing in botnet "
        "prevention. I have extracted a firmware filesystem and generated the "
        "structural directory map below.\n"
        "\n"
        "Firmware Filesystem Map:\n"
        "```text\n"
        f"{tree_str}\n"
        "```\n"
        "\n"
        "YOUR MISSION:\n"
        "1. Analyze the directory map to locate primary configuration "
        "directories, initialization scripts, custom binaries, and active "
        "network services.\n"
        "2. Use the provided tool `read_file` to investigate suspected entry "
        "points. Specifically look for default service permissions, "
        "hardcoded accounts, or shell execution scripts that could allow a "
        "device to be recruited into a botnet.\n"
        "3. Do not try to read binary executable images inline; prioritize "
        "script files (.sh, .rc), configuration files (.conf, .cfg, .json), "
        "and user tables (passwd, shadow).\n"
        "\n"
        "Begin your analysis by invoking the tool on at most, 10 top priority "
        "targets. Report the selected targets."
    )

    def read_file(relative_path: str) -> str:
        """Reads up to 100KB of text from a path inside the firmware root."""
        full_path = os.path.join(root_dir, relative_path.lstrip('./'))
        try:
            if os.path.getsize(full_path) > 100000:
                return "Error: File is too large. Choose a smaller configuration or script file."
            with open(full_path, 'r', errors='ignore') as f:
                return f.read()
        except Exception as e:
            return f"Error: Could not read file. {str(e)}"

    # Launching Turn 1 using the native Interactions API
    interaction = client.interactions.create(
        model='gemini-2.5-flash-lite', # Flash is excellent at large contexts like raw trees
        input=prompt,
        tools=[{
            "type": "function",
            "name": "read_file",
            "description": "Reads up to 100KB of text from a path inside the firmware root",
            "parameters": {
                "type": "object",
                "properties": {
                    "relative_path": {
                        "type": "string",
                        "description": "Path of the file you want to read relative to firmware root"
                    }
                },
                "required": ["relative_path"]
            }
        }],
        system_instruction = (
            "You are an expert firmware security analyst. You have a strict "
            "token and time budget. You may only select a MAXIMUM of 10 "
            "of the highest-risk configuration or startup files to inspect "
            "using the `read_file` tool."
        )
    )

    return interaction
