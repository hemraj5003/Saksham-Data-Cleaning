#!/usr/bin/env python3
"""
SecWipe - Secure wipe prototype (file/dir/device/freespace).
Features:
 - modes: file, dir, device, ata-secure, nvme-format, freespace
 - multiple targets allowed
 - dry-run produces preview files (out/previews/*.preview...)
 - JSON + PDF certificate generation and RSA signing (ephemeral key by default)
 - WARNING: destructive operations WILL ERASE DATA when not using --dry-run and when using --confirm for device ops.
Dependencies: cryptography, reportlab, psutil (optional)
"""

import os
import sys
import json
import argparse
import hashlib
import getpass
import platform
import subprocess
import tempfile
import shutil
from datetime import datetime
from pathlib import Path

# Crypto / PDF libs (install cryptography, reportlab)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

# Optional: psutil for device metadata
try:
    import psutil
except Exception:
    psutil = None

# ---------- Config ----------
PREVIEW_MAX_BYTES = 16 * 1024  # 16 KiB preview
DEFAULT_OUTDIR = "./out"

# ---------- Utilities ----------
def human_now():
    return datetime.now().isoformat()

def sha256_hex(data: bytes):
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()

def save_json(obj, filepath):
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=4, sort_keys=True)

# ---------- Key management & signing ----------
def generate_rsa_keypair(key_size=2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    pub = private_key.public_key()
    return private_key, pub

def save_private_key_to_pem(private_key, filepath, password: bytes = None):
    enc = (serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption())
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=enc
    )
    with open(filepath, "wb") as f:
        f.write(pem)

def load_private_key_from_pem(filepath, password: bytes = None):
    with open(filepath, "rb") as f:
        data = f.read()
    return serialization.load_pem_private_key(data, password=password)

def save_public_key_to_pem(public_key, filepath):
    pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    with open(filepath, "wb") as f:
        f.write(pem)

def load_public_key_from_pem(filepath):
    with open(filepath, "rb") as f:
        data = f.read()
    return serialization.load_pem_public_key(data)

def sign_bytes(private_key, data: bytes):
    signature = private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key, signature: bytes, data: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# ---------- Wipe algorithms (destructive ops) ----------
def overwrite_with_pattern(handle, size, pattern: bytes, chunk_size=4*1024*1024):
    handle.seek(0)
    written = 0
    pat_len = len(pattern) or 1
    buffer = (pattern * ((chunk_size // pat_len) + 1))[:chunk_size]
    while written < size:
        to_write = min(chunk_size, size - written)
        handle.write(buffer[:to_write])
        written += to_write
    handle.flush()
    try:
        os.fsync(handle.fileno())
    except Exception:
        pass

def overwrite_with_random(handle, size, chunk_size=4*1024*1024):
    handle.seek(0)
    written = 0
    while written < size:
        to_write = min(chunk_size, size - written)
        handle.write(os.urandom(to_write))
        written += to_write
    handle.flush()
    try:
        os.fsync(handle.fileno())
    except Exception:
        pass

def nist_clear_file(filepath):
    size = os.path.getsize(filepath)
    with open(filepath, "r+b") as f:
        overwrite_with_random(f, size)
    os.remove(filepath)

def dod_wipe_file(filepath):
    size = os.path.getsize(filepath)
    with open(filepath, "r+b") as f:
        overwrite_with_pattern(f, size, b"\x00")
        f.seek(0)
        overwrite_with_pattern(f, size, b"\xFF")
        f.seek(0)
        overwrite_with_random(f, size)
    os.remove(filepath)

def gutmann_wipe_file(filepath):
    size = os.path.getsize(filepath)
    with open(filepath, "r+b") as f:
        # prototype: simulate heavy overwrite with 10 random passes
        for _ in range(10):
            overwrite_with_random(f, size)
            f.seek(0)
    os.remove(filepath)

def zero_fill_file(filepath):
    size = os.path.getsize(filepath)
    with open(filepath, "r+b") as f:
        overwrite_with_pattern(f, size, b"\x00")
    os.remove(filepath)

# ---------- Dry-run preview helper ----------
def create_dryrun_preview_for_file(filepath: str, algorithm: str, passes: int, outdir: Path) -> Path:
    src = Path(filepath)
    previews_dir = outdir / "previews"
    previews_dir.mkdir(parents=True, exist_ok=True)
    safe_name = src.name.replace(" ", "_")
    preview_name = f"{safe_name}.preview.{algorithm}.{passes}p.bin"
    preview_path = previews_dir / preview_name

    size = src.stat().st_size if src.exists() else PREVIEW_MAX_BYTES
    preview_size = min(size, PREVIEW_MAX_BYTES)

    # For preview show the final pass contents (approximate)
    if algorithm == "zero":
        final_chunk = b"\x00" * preview_size
    else:
        final_chunk = os.urandom(preview_size)

    with open(preview_path, "wb") as p:
        p.write(final_chunk)

    return preview_path

# ---------- Device-level operations ----------
def raw_overwrite_device(device_path, method="random", passes=1, dry_run=True):
    if dry_run:
        return {"status": "dry-run", "device": device_path}
    # destructive: open raw and overwrite
    with open(device_path, "r+b", buffering=0) as dev:
        dev.seek(0, os.SEEK_END)
        size = dev.tell()
        for _ in range(passes):
            dev.seek(0)
            if method == "zeros":
                overwrite_with_pattern(dev, size, b"\x00")
            elif method == "random":
                overwrite_with_random(dev, size)
            elif method == "dod":
                overwrite_with_pattern(dev, size, b"\x00")
                dev.seek(0)
                overwrite_with_pattern(dev, size, b"\xFF")
                dev.seek(0)
                overwrite_with_random(dev, size)
            else:
                overwrite_with_random(dev, size)
    return {"status": "wiped", "device": device_path}

def ata_secure_erase_linux(device_path, dry_run=True):
    if dry_run:
        return {"status": "dry-run", "device": device_path}
    try:
        # minimal; in production ensure user safe-guards
        pwd = "wipepwd"
        subprocess.run(["hdparm", "-I", device_path], check=True)
        subprocess.run(["hdparm", "--user-master", "u", "--security-set-pass", pwd, device_path], check=True)
        subprocess.run(["hdparm", "--user-master", "u", "--security-erase", pwd, device_path], check=True)
        return {"status": "secure-erase-issued", "device": device_path}
    except Exception as e:
        return {"status": "error", "error": str(e)}

def nvme_secure_format(device_path, dry_run=True):
    if dry_run:
        return {"status": "dry-run", "device": device_path}
    try:
        subprocess.run(["nvme", "format", device_path], check=True)
        return {"status": "nvme-format-issued", "device": device_path}
    except Exception as e:
        return {"status": "error", "error": str(e)}

# ---------- Freespace wipe ----------
def wipe_freespace_on_mount(mount_point: str, algorithm: str, passes: int, dry_run: bool, outdir: Path):
    """
    Overwrite free space by creating a large temporary file until the filesystem is full,
    then applying the chosen algorithm to that file (or producing a preview if dry-run).
    mount_point should be a writable directory on the target filesystem (e.g., "C:\\" or "/mnt/data").
    """
    method_name = f"{algorithm.upper()} (freespace)"
    previews_dir = outdir / "previews"
    previews_dir.mkdir(parents=True, exist_ok=True)
    temp_dir = None
    try:
        temp_dir = tempfile.mkdtemp(dir=mount_point)
        temp_file = Path(temp_dir) / "secwipe_freespace.fill"
        if dry_run:
            # create a small preview file showing final overwrite content
            preview_path = previews_dir / f"freespace_preview.{Path(mount_point).name}.{algorithm}.{passes}p.bin"
            preview_size = min(PREVIEW_MAX_BYTES, 64 * 1024)
            if algorithm == "zero":
                final = b"\x00" * preview_size
            else:
                final = os.urandom(preview_size)
            with open(preview_path, "wb") as p:
                p.write(final)
            return {"status": "dry-run", "preview": str(preview_path)}
        # fill free space until OSError
        block = 1024 * 1024  # 1 MiB
        written = 0
        with open(temp_file, "wb") as f:
            try:
                while True:
                    f.write(b"\x00" * block)
                    written += block
            except OSError:
                # disk full or no space left for temp file
                pass
        # apply algorithm to the temp file (full size)
        size = temp_file.stat().st_size
        with open(temp_file, "r+b") as f:
            if algorithm == "zero":
                overwrite_with_pattern(f, size, b"\x00")
            elif algorithm == "dod":
                overwrite_with_pattern(f, size, b"\x00")
                f.seek(0)
                overwrite_with_pattern(f, size, b"\xFF")
                f.seek(0)
                overwrite_with_random(f, size)
            elif algorithm == "gutmann":
                for _ in range(passes or 10):
                    overwrite_with_random(f, size)
                    f.seek(0)
            else:  # random / nist
                for _ in range(passes or 1):
                    overwrite_with_random(f, size)
                    f.seek(0)
        # delete the temp file and directory
        try:
            temp_file.unlink()
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass
        return {"status": "wiped-freespace", "bytes_written": written, "mount_point": mount_point}
    except Exception as e:
        if temp_dir:
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                pass
        return {"status": "error", "error": str(e)}

# ---------- Certificate generation ----------
def gather_device_metadata(target_path):
    meta = {
        "host": platform.node(),
        "platform": platform.system(),
        "platform_version": platform.version(),
        "user": getpass.getuser(),
        "timestamp": human_now(),
        "target": str(target_path),
    }
    if psutil:
        try:
            if os.path.exists(target_path) and os.path.isfile(target_path):
                st = os.stat(target_path)
                meta["file_size_bytes"] = st.st_size
                meta["file_mtime"] = datetime.fromtimestamp(st.st_mtime).isoformat()
            partitions = []
            for p in psutil.disk_partitions():
                partitions.append({"device": p.device, "mountpoint": p.mountpoint, "fstype": p.fstype})
            meta["partitions"] = partitions
        except Exception:
            pass
    return meta

def generate_pdf_certificate(log: dict, pdf_path: str):
    c = canvas.Canvas(pdf_path, pagesize=A4)
    width, height = A4
    margin = 50
    text_y = height - margin
    c.setFont("Helvetica-Bold", 16)
    c.drawString(margin, text_y, "Secure Wipe Certificate")
    text_y -= 30
    c.setFont("Helvetica", 10)
    for key in ["target", "method", "status", "timestamp", "operator"]:
        if key in log:
            c.drawString(margin, text_y, f"{key.capitalize()}: {log.get(key)}")
            text_y -= 14
    text_y -= 6
    c.drawString(margin, text_y, "Metadata:")
    text_y -= 14
    for k, v in log.get("metadata", {}).items():
        if text_y < margin + 50:
            c.showPage()
            text_y = height - margin
        c.drawString(margin + 10, text_y, f"{k}: {v}")
        text_y -= 12
    text_y -= 8
    c.drawString(margin, text_y, "Signature (hex, truncated):")
    text_y -= 12
    sig_hex = log.get("signature_hex", "")
    sig_display = sig_hex[:200] + "..." if len(sig_hex) > 200 else sig_hex
    c.drawString(margin + 10, text_y, sig_display)
    c.save()

# ---------- Logging helper ----------
def create_wipe_log(target, method_name, status, extra=None, signature_hex=None, operator=None):
    meta = gather_device_metadata(target)
    log = {
        "target": str(target),
        "method": method_name,
        "status": status,
        "timestamp": human_now(),
        "operator": operator or getpass.getuser(),
        "metadata": meta,
        "extra": extra or {}
    }
    if signature_hex:
        log["signature_hex"] = signature_hex
    return log

# ---------- CLI ----------
def parse_args():
    parser = argparse.ArgumentParser(description="SecWipe - Prototype secure wipe tool")
    parser.add_argument("--target", nargs="+", required=True, help="File(s), dir(s), mount(s) or device path(s) to wipe")
    parser.add_argument("--mode", choices=["file", "dir", "device", "ata-secure", "nvme-format", "freespace"], default="file")
    parser.add_argument("--algorithm", choices=["nist", "dod", "gutmann", "zero", "random"], default="nist")
    parser.add_argument("--passes", type=int, default=1)
    parser.add_argument("--dry-run", action="store_true", help="Simulate actions; do not change originals")
    parser.add_argument("--confirm", action="store_true", help="Confirm destructive device-level operations")
    parser.add_argument("--output-dir", default=DEFAULT_OUTDIR)
    parser.add_argument("--private-key", default=None, help="PEM private key path to sign logs (optional)")
    parser.add_argument("--public-key-out", default=None, help="Save new public key to this path (if no private key provided)")
    parser.add_argument("--no-pdf", action="store_true", help="Do not produce PDF certificates")
    return parser.parse_args()

# ---------- flows ----------
def wipe_single_file_flow(target_path: Path, alg: str, passes: int, dry_run: bool, outdir: Path, private_key, no_pdf: bool):
    method_name = f"{alg.upper()} (file)"
    extra = {}
    if dry_run:
        preview = create_dryrun_preview_for_file(str(target_path), alg, passes, outdir)
        status = "dry-run"
        extra = {"preview_path": str(preview)}
        print(f"[DRY-RUN] Preview created: {preview} (original NOT modified)")
    else:
        if not target_path.exists() or not target_path.is_file():
            raise FileNotFoundError(f"File not found: {target_path}")
        if alg == "nist":
            nist_clear_file(str(target_path))
            status = "wiped-nist"
        elif alg == "dod":
            dod_wipe_file(str(target_path))
            status = "wiped-dod"
        elif alg == "gutmann":
            gutmann_wipe_file(str(target_path))
            status = "wiped-gutmann"
        elif alg == "zero":
            zero_fill_file(str(target_path))
            status = "wiped-zero"
        elif alg == "random":
            for _ in range(passes):
                with open(str(target_path), "r+b") as f:
                    overwrite_with_random(f, os.path.getsize(str(target_path)))
            os.remove(str(target_path))
            status = f"wiped-random-{passes}p"
        else:
            raise ValueError("Unknown algorithm")
        extra = {"notes": "file-level wipe executed"}
        print(f"[OK] File wiped: {target_path}")

    # create log and sign
    log = create_wipe_log(str(target_path), method_name, status, extra=extra)
    log_bytes = json.dumps(log, sort_keys=True).encode("utf-8")
    signature = sign_bytes(private_key, log_bytes) if private_key else b""
    log["signature_hex"] = signature.hex() if signature else ""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = outdir / f"wipe_log_{ts}.json"
    save_json(log, json_path)
    if not no_pdf:
        pdf_path = outdir / f"wipe_certificate_{ts}.pdf"
        generate_pdf_certificate(log, str(pdf_path))
    print(f"[OK] Wipe log saved to {json_path}")

def wipe_directory_flow(target_dir: Path, alg: str, passes: int, dry_run: bool, outdir: Path, private_key, no_pdf: bool):
    if not target_dir.exists():
        print(f"[WARN] Directory not found: {target_dir}")
        return
    for root, _, files in os.walk(str(target_dir)):
        for fname in files:
            fpath = Path(root) / fname
            try:
                wipe_single_file_flow(fpath, alg, passes, dry_run, outdir, private_key, no_pdf)
            except Exception as e:
                print(f"[ERROR] wiping {fpath}: {e}")
    # optionally remove empty dirs when not dry-run
    if not dry_run:
        for root, dirs, _ in os.walk(str(target_dir), topdown=False):
            for d in dirs:
                p = Path(root) / d
                try:
                    p.rmdir()
                except OSError:
                    pass
        try:
            target_dir.rmdir()
        except Exception:
            pass

def wipe_device_flow(target_device: str, alg_or_mode: str, passes: int, dry_run: bool, outdir: Path, private_key, no_pdf: bool):
    # alg_or_mode: for ata-secure/nvme-format the arg is the mode string; for raw device it is the algorithm
    method_name = f"{alg_or_mode.upper()} (device)"
    if alg_or_mode == "ata-secure":
        res = ata_secure_erase_linux(target_device, dry_run=dry_run)
    elif alg_or_mode == "nvme-format":
        res = nvme_secure_format(target_device, dry_run=dry_run)
    else:
        # alg_or_mode here is algorithm name (random/zero/...)
        res = raw_overwrite_device(target_device, method=("random" if alg_or_mode == "random" else "zeros"), passes=passes, dry_run=dry_run)

    status = res.get("status", "unknown")
    log = create_wipe_log(str(target_device), method_name, status, extra=res)
    log_bytes = json.dumps(log, sort_keys=True).encode("utf-8")
    signature = sign_bytes(private_key, log_bytes) if private_key else b""
    log["signature_hex"] = signature.hex() if signature else ""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = outdir / f"device_wipe_log_{ts}.json"
    save_json(log, json_path)
    if not no_pdf:
        pdf_path = outdir / f"device_wipe_certificate_{ts}.pdf"
        generate_pdf_certificate(log, str(pdf_path))
    print(f"[OK] Device wipe log saved to {json_path} (status: {status})")

def wipe_freespace_flow(mount_point: str, alg: str, passes: int, dry_run: bool, outdir: Path, private_key, no_pdf: bool):
    method_name = f"{alg.upper()} (freespace)"
    res = wipe_freespace_on_mount(mount_point, alg, passes, dry_run, outdir)
    status = res.get("status", "unknown")
    extra = res
    log = create_wipe_log(mount_point, method_name, status, extra=extra)
    log_bytes = json.dumps(log, sort_keys=True).encode("utf-8")
    signature = sign_bytes(private_key, log_bytes) if private_key else b""
    log["signature_hex"] = signature.hex() if signature else ""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = outdir / f"freespace_wipe_log_{ts}.json"
    save_json(log, json_path)
    if not no_pdf:
        pdf_path = outdir / f"freespace_wipe_certificate_{ts}.pdf"
        generate_pdf_certificate(log, str(pdf_path))
    print(f"[OK] Freespace wipe log saved to {json_path} (status: {status})")

# ---------- Main ----------
def main():
    args = parse_args()
    outdir = Path(args.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)

    # Load or generate key
    private_key = None
    public_key = None
    if args.private_key:
        private_key = load_private_key_from_pem(args.private_key)
        public_key = private_key.public_key()
    else:
        private_key, public_key = generate_rsa_keypair()
        if args.public_key_out:
            save_public_key_to_pem(public_key, args.public_key_out)

    # Safety for device-level ops
    if args.mode in ("device", "ata-secure", "nvme-format") and not args.confirm and not args.dry_run:
        print("ERROR: Device-level destructive operations require --confirm (or run with --dry-run).")
        sys.exit(1)

    for t in args.target:
        p = Path(t)
        try:
            if args.mode == "file":
                if not p.exists() or not p.is_file():
                    print(f"[WARN] File not found or not a file: {t}")
                    continue
                wipe_single_file_flow(p, args.algorithm, args.passes, args.dry_run, outdir, private_key, args.no_pdf)

            elif args.mode == "dir":
                if not p.exists() or not p.is_dir():
                    print(f"[WARN] Directory not found or not a directory: {t}")
                    continue
                wipe_directory_flow(p, args.algorithm, args.passes, args.dry_run, outdir, private_key, args.no_pdf)

            elif args.mode == "freespace":
                # user should pass a mount path (like C:\ or /mnt/data or any folder on that filesystem)
                wipe_freespace_flow(t, args.algorithm, args.passes, args.dry_run, outdir, private_key, args.no_pdf)

            elif args.mode in ("device", "ata-secure", "nvme-format"):
                # For devices, t is passed as raw device path like /dev/sdb or \\.\PhysicalDrive0
                if args.mode == "device":
                    # raw device use algorithm name for method
                    wipe_device_flow(t, args.algorithm, args.passes, args.dry_run, outdir, private_key, args.no_pdf)
                else:
                    # ata-secure or nvme-format
                    wipe_device_flow(t, args.mode, args.passes, args.dry_run, outdir, private_key, args.no_pdf)

            else:
                print(f"[ERROR] Unsupported mode: {args.mode}")

        except Exception as e:
            print(f"[ERROR] while processing {t}: {e}")

    print("[DONE] All targets processed.")

if __name__ == "__main__":
    main()
