import argparse
from pathlib import Path

from firmware_scanner.extract import extract_firmware
from firmware_scanner.scan import scan_firmware
from firmware_scanner.triage_stage1 import triage_stage1
import shutil

def main():
    this_dir = Path(__file__).resolve().parent
    default_output_dir = this_dir / "../../extractions/"

    parser = argparse.ArgumentParser(description="IoT Firmware Scanner")
    parser.add_argument("input_file", help="Path to the firmware zip/bin file")
    parser.add_argument("--output-dir", default=default_output_dir,
                        help="Directory to extract the filesystem into")
    parser.add_argument("--overwrite", action="store_true",
                        help="Overwrite the extracted files for this firmware")
    args = parser.parse_args()

    input_file = Path(args.input_file)
    output_dir = Path(args.output_dir)

    output_dir = output_dir / input_file.stem
    if args.overwrite and output_dir.is_dir():
        shutil.rmtree(str(output_dir), ignore_errors=True)

    result = extract_firmware(input_file, output_dir)
    print(result.stderr)
    print(result.stdout)
    print()
    print()
    # scan_firmware(output_dir)
    triage_stage1(output_dir)

if __name__ == "__main__":
    main()
