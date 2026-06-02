import os
import subprocess
from pathlib import Path


def extract_firmware(input_file: str | os.PathLike,
                     output_dir: str | os.PathLike):
    """Extracts firmware using binwalk."""
    input_file = Path(input_file).resolve()
    output_dir = Path(output_dir).resolve()

    # Check input file exists
    if not input_file.is_file():
        raise ValueError(f"Input file '{input_file}' not found.")

    # Make output dir if necessary
    if not output_dir.is_dir():
        print(f"[*] Creating output directory: {output_dir}")
        output_dir.mkdir(parents=True)

    print(f"[*] Target Firmware: {input_file.name}")
    print(f"[*] Output Directory: {output_dir}")
    print(f"[*] Running binwalk...")

    docker_cmd = [
        "docker", "run", "--rm",
        # Mount file location as Read-Only
        "-v", f"{str(input_file.parent)}:/input:ro",
        # Mount output target as Read-Write
        "-v", f"{str(output_dir)}:/output:rw",
        "binwalkv3",
        "-Me", # Perform deep recursive extraction
        "-C", "/output", # Pipe everything straight to our output folder
        f"/input/{input_file.name}",
    ]

    # Run binwalk
    try:
        result = subprocess.run(
            docker_cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        print("\n[+] Extraction Complete!")
    except subprocess.CalledProcessError as e:
        print("\n[-] Error occurred during Binwalk extraction:")
        print("[-]", e.stdout)
        raise
    except FileNotFoundError:
        raise RuntimeError(
            "'docker'. Make sure docker is installed and running")

    return result
