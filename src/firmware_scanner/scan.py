#!/usr/bin/env python3
import argparse
import re
import sys
from pathlib import Path

# Configuration for the regex hunter
INTERESTING_KEYWORDS = [
    r"password\s*=\s*['\"].*?['\"]",
    r"passwd\s*=\s*['\"].*?['\"]",
    r"admin_pass\s*=\s*['\"].*?['\"]",
    r"key\s*=\s*['\"].*?['\"]",
    r"secret\s*=\s*['\"].*?['\"]",
    r"api_key\s*=\s*['\"].*?['\"]",
    r"-----BEGIN .*? PRIVATE KEY-----"
]

BOTNET_VECTORS = [
    r"telnetd",
    r"sshd",
    r"dropbear",
    r"upnp",
    r"iptables\s+-A\s+INPUT",
    r"tftpd",
    r"nc\s+-e"
]

from pathlib import Path



def scan_firmware(extracted_dir: Path):
    """
    Scans the extracted firmware filesystem for configuration weaknesses,
    hardcoded credentials, and active network daemons.
    """
    extracted_root = _find_root(extracted_dir)
    findings = []
    findings.append(f"=== FIRMWARE STATIC SCAN REPORT ===")
    findings.append(f"Target Root: {extracted_root}\n")

    # --- STEP 1: Audit Sensitive Linux Configuration Files ---
    findings.append("--- 1. CRITICAL CONFIGURATION FILES ---")
    critical_files = [
        "etc/passwd",
        "etc/shadow",
        "etc/hosts",
        "etc/fstab",
        "etc/resolv.conf"
    ]

    for rel_path in critical_files:
        target_file = extracted_root / rel_path
        if target_file.is_file():
            findings.append(f"[File Found] /{rel_path}")
            try:
                content = target_file.read_text(encoding='utf-8', errors='ignore')
                # Snip content to avoid blowing out context window, but keep the core data
                lines = [line.strip() for line in content.splitlines() if line.strip()]
                for line in lines[:20]:  # Keep first 20 lines (usually enough for shadow/passwd hashes)
                    findings.append(f"  | {line}")
                if len(lines) > 20:
                    findings.append("  | ... [truncated]")
            except Exception as e:
                findings.append(f"  | [Error reading file: {e}]")
            findings.append("")

    # --- STEP 2: Scan for Hardcoded Secrets & Credentials ---
    findings.append("--- 2. HARDCODED SECRETS & KEYWORDS ---")
    secret_compiled = [re.compile(pattern, re.IGNORECASE) for pattern in INTERESTING_KEYWORDS]

    # We target high-value directories to save time and reduce noise
    target_dirs = ["etc", "www", "config", "usr/etc"]
    scanned_secrets_count = 0

    for t_dir in target_dirs:
        dir_path = extracted_root / t_dir
        if not dir_path.exists():
            continue

        for file_path in dir_path.rglob('*'):
            if not file_path.is_file():
                continue
            # Skip massive files and binaries (> 500 KB) to optimize performance
            if file_path.stat().st_size > 500000:
                continue

            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                for pattern in secret_compiled:
                    matches = pattern.findall(content)
                    for match in matches:
                        scanned_secrets_count += 1
                        # Drop absolute path path constraints for clean reporting
                        rel_file = file_path.relative_to(extracted_root)
                        findings.append(f"[Secret Match] /{rel_file} -> {match.strip()}")
            except Exception:
                pass # Skip files that completely fail text parsing

    if scanned_secrets_count == 0:
        findings.append("No obvious hardcoded password patterns or private keys discovered.")
    findings.append("")

    # --- STEP 3: Audit Boot Scripts for Botnet Vectors ---
    findings.append("--- 3. STARTUP SCRIPTS & NETWORK DAEMONS ---")
    boot_compiled = [re.compile(pattern, re.IGNORECASE) for pattern in BOTNET_VECTORS]
    boot_dirs = ["etc/init.d", "etc/rc.d", "etc"]
    boot_files_searched = ["rcS", "rc.local", "inittab"]

    boot_targets = []
    # Collect directories
    for b_dir in boot_dirs:
        d_path = extracted_root / b_dir
        if d_path.exists():
            boot_targets.extend([f for f in d_path.iterdir() if f.is_file()])
    # Collect explicit standard files
    for b_file in boot_files_searched:
        f_path = extracted_root / "etc" / b_file
        if f_path.is_file():
            boot_targets.append(f_path)

    # De-duplicate targets
    boot_targets = list(set(boot_targets))
    botnet_vectors_count = 0

    for file_path in boot_targets:
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            for line in content.splitlines():
                for pattern in boot_compiled:
                    if pattern.search(line):
                        botnet_vectors_count += 1
                        rel_file = file_path.relative_to(extracted_root)
                        findings.append(f"[Daemon Vector] /{rel_file}: {line.strip()}")
        except Exception:
            pass

    if botnet_vectors_count == 0:
        findings.append("No common persistent botnet startup daemons (telnetd/dropbear) flagged in basic scripts.")
    findings.append("\n=== END OF REPORT ===")

    # --- STEP 4: Write Aggregated Findings to Text Asset ---
    output_file = extracted_dir / "scan_findings.txt"
    output_file.write_text("\n".join(findings), encoding='utf-8')
    print(f"[+] Scan Complete! Raw findings written to: {output_file}")
