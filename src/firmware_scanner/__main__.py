import argparse
import os
import shutil
from pathlib import Path
import sys

from google import genai

from firmware_scanner.extract import extract_firmware
from firmware_scanner.discover import discover
from firmware_scanner.analyze import analyze


def main():

    # Check API key
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("Error: GEMINI_API_KEY environment variable not found.")
        print("Please set it in your terminal before running the script:")
        print("export GEMINI_API_KEY='your_actual_api_key_here'")
        sys.exit(1)

    this_dir = Path(__file__).resolve().parent
    default_output_dir = this_dir / "../../extractions/"

    parser = argparse.ArgumentParser(description="IoT Firmware Scanner")
    parser.add_argument("input_file",
                        help="Path to the firmware zip/bin file")
    parser.add_argument("--output-dir",
                        default=default_output_dir,
                        help="Directory to extract the filesystem into")
    parser.add_argument("--overwrite",
                        action="store_true",
                        help="Overwrite the extracted files for this firmware")
    args = parser.parse_args()

    input_file = Path(args.input_file)
    output_dir = Path(args.output_dir)

    # Make output dir per firmware input
    output_dir = output_dir / input_file.stem

    # Overwrite?
    if args.overwrite and output_dir.is_dir():
        shutil.rmtree(str(output_dir), ignore_errors=True)

    # Extract firmware with binwalk
    if args.overwrite or not output_dir.is_dir():
        extract_firmware(input_file, output_dir)

    # Create client
    client = genai.Client()

    # Use agent for discovery
    discovery_interaction = discover(output_dir, client)
    print()
    print()
    print(discovery_interaction.output_text)

    # Use agent for analysis
    analysis_interaction = analyze(discovery_interaction, client)
    print()
    print()
    print(analysis_interaction.output_text)

if __name__ == "__main__":
    main()
