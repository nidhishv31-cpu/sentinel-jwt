"""
Module 4 — Automated File Carving & Extraction
Reconstructs transferred files from stream payloads using magic-byte signatures
(Foremost/Scalpel/Binwalk patterns), flags truncated streams, and stores as inert blobs.
"""

import os
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone

# Standard Foremost/Binwalk file signatures: (Header Magic, Optional Footer Magic, Extension, MIME)
FILE_SIGNATURES = [
    {
        "name": "PNG Image",
        "header": b"\x89PNG\r\n\x1a\n",
        "footer": b"IEND\xaeB`\x82",
        "ext": "png",
        "mime": "image/png",
        "max_size": 20 * 1024 * 1024
    },
    {
        "name": "JPEG Image",
        "header": b"\xff\xd8\xff",
        "footer": b"\xff\xd9",
        "ext": "jpg",
        "mime": "image/jpeg",
        "max_size": 15 * 1024 * 1024
    },
    {
        "name": "GIF Image",
        "header": b"GIF89a",
        "footer": b"\x00;",
        "ext": "gif",
        "mime": "image/gif",
        "max_size": 10 * 1024 * 1024
    },
    {
        "name": "PDF Document",
        "header": b"%PDF-",
        "footer": b"%%EOF",
        "ext": "pdf",
        "mime": "application/pdf",
        "max_size": 50 * 1024 * 1024
    },
    {
        "name": "ZIP Archive",
        "header": b"PK\x03\x04",
        "footer": b"PK\x05\x06",
        "ext": "zip",
        "mime": "application/zip",
        "max_size": 50 * 1024 * 1024
    },
    {
        "name": "GZIP Archive",
        "header": b"\x1f\x8b\x08",
        "footer": None,
        "ext": "gz",
        "mime": "application/gzip",
        "max_size": 30 * 1024 * 1024
    },
    {
        "name": "Windows PE / Executable (Inert)",
        "header": b"MZ",
        "footer": None,
        "ext": "bin",
        "mime": "application/octet-stream",
        "max_size": 30 * 1024 * 1024
    },
    {
        "name": "Linux ELF Binary (Inert)",
        "header": b"\x7fELF",
        "footer": None,
        "ext": "elf.bin",
        "mime": "application/octet-stream",
        "max_size": 30 * 1024 * 1024
    }
]

def carve_files_from_bytes(
    raw_data: bytes,
    capture_id: str = "unknown",
    stream_id: int = 0,
    output_dir: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Scans a continuous raw byte stream using rolling pattern matching to carve out files.
    Detects partial/truncated files and saves as safe inert blobs.
    """
    if not raw_data or len(raw_data) < 8:
        return []

    if output_dir is None:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        output_dir = os.path.join(base_dir, "uploads", "carved")
    os.makedirs(output_dir, exist_ok=True)

    carved_artifacts: List[Dict[str, Any]] = []
    data_len = len(raw_data)
    now_iso = datetime.now(timezone.utc).isoformat()

    for sig in FILE_SIGNATURES:
        header = sig["header"]
        footer = sig["footer"]
        ext = sig["ext"]
        mime = sig["mime"]
        name = sig["name"]
        max_sz = sig["max_size"]
        
        start_idx = 0
        while start_idx < data_len:
            found_start = raw_data.find(header, start_idx)
            if found_start == -1:
                break
                
            is_truncated = False
            file_data = b""
            
            if footer:
                found_end = raw_data.find(footer, found_start + len(header))
                if found_end != -1:
                    end_idx = found_end + len(footer)
                    # Bound size
                    if (end_idx - found_start) <= max_sz:
                        file_data = raw_data[found_start:end_idx]
                        start_idx = end_idx
                    else:
                        file_data = raw_data[found_start:found_start + max_sz]
                        is_truncated = True
                        start_idx = found_start + max_sz
                else:
                    # Footer not found: Stream was truncated mid-file
                    is_truncated = True
                    file_data = raw_data[found_start:min(data_len, found_start + max_sz)]
                    start_idx = data_len
            else:
                # No discrete footer: carve up to next known signature or stream boundary
                file_data = raw_data[found_start:min(data_len, found_start + max_sz)]
                start_idx = data_len

            if len(file_data) >= len(header) + 4:
                md5_val = hashlib.md5(file_data).hexdigest()
                sha256_val = hashlib.sha256(file_data).hexdigest()
                
                # Safe inert filename
                safe_filename = f"carved_{stream_id}_{md5_val[:10]}.{ext}"
                safe_filepath = os.path.join(output_dir, safe_filename)
                
                with open(safe_filepath, "wb") as f:
                    f.write(file_data)
                    
                carved_artifacts.append({
                    "capture_id": capture_id,
                    "stream_id": stream_id,
                    "filename": safe_filename,
                    "stored_path": safe_filepath,
                    "file_type": name,
                    "mime_type": mime,
                    "file_size": len(file_data),
                    "md5_hash": md5_val,
                    "sha256_hash": sha256_val,
                    "is_truncated": is_truncated,
                    "status": "partial_truncated" if is_truncated else "complete",
                    "carved_at": now_iso
                })
                
    return carved_artifacts
