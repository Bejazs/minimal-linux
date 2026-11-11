"""Safe unpacking of Chrome extensions (.crx v2/v3, .zip, or an unpacked folder).

Nothing in the sample is ever executed. Archives are extracted with path,
symlink, file-count and size checks so a crafted archive cannot write outside
the output folder or exhaust the disk.
"""

import hashlib
import io
import os
import shutil
import stat
import struct
import zipfile

MAX_FILES = 20000
MAX_TOTAL_BYTES = 500 * 1024 * 1024
MAX_RATIO = 200  # max uncompressed/compressed ratio per member (zip bomb guard)


class UnpackError(Exception):
    pass


def file_hashes(data: bytes) -> dict:
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
    }


def id_from_bytes(digest16: bytes) -> str:
    """Chrome extension IDs are the first 16 bytes of a hash, hex-encoded with a-p instead of 0-f."""
    return "".join(chr(ord("a") + int(c, 16)) for c in digest16.hex())


def id_from_pubkey(der: bytes) -> str:
    return id_from_bytes(hashlib.sha256(der).digest()[:16])


def _read_varint(buf: bytes, pos: int):
    result = shift = 0
    while True:
        if pos >= len(buf):
            raise UnpackError("truncated protobuf varint")
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            raise UnpackError("invalid protobuf varint")


def _pb_fields(buf: bytes):
    """Minimal protobuf reader: yields (field_number, wire_type, value)."""
    pos = 0
    while pos < len(buf):
        key, pos = _read_varint(buf, pos)
        field, wire = key >> 3, key & 7
        if wire == 0:
            val, pos = _read_varint(buf, pos)
        elif wire == 2:
            ln, pos = _read_varint(buf, pos)
            val = buf[pos:pos + ln]
            pos += ln
        elif wire == 1:
            val = buf[pos:pos + 8]
            pos += 8
        elif wire == 5:
            val = buf[pos:pos + 4]
            pos += 4
        else:
            raise UnpackError(f"unsupported protobuf wire type {wire}")
        yield field, wire, val


def parse_crx(data: bytes):
    """Return (zip_bytes, crx_info). Raises UnpackError if not a CRX."""
    if data[:4] != b"Cr24":
        raise UnpackError("not a CRX file")
    version = struct.unpack("<I", data[4:8])[0]
    info = {"crx_version": version, "crx_id": None}
    if version == 2:
        pk_len, sig_len = struct.unpack("<II", data[8:16])
        pubkey = data[16:16 + pk_len]
        info["crx_id"] = id_from_pubkey(pubkey)
        return data[16 + pk_len + sig_len:], info
    if version == 3:
        hdr_len = struct.unpack("<I", data[8:12])[0]
        header = data[12:12 + hdr_len]
        # CrxFileHeader.signed_header_data (field 10000) -> SignedData.crx_id (field 1)
        for field, wire, val in _pb_fields(header):
            if field == 10000 and wire == 2:
                for f2, w2, v2 in _pb_fields(val):
                    if f2 == 1 and w2 == 2 and len(v2) == 16:
                        info["crx_id"] = id_from_bytes(v2)
        return data[12 + hdr_len:], info
    raise UnpackError(f"unsupported CRX version {version}")


def _safe_extract(zip_bytes: bytes, dest: str) -> list:
    warnings = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile as e:
        raise UnpackError(f"invalid zip archive: {e}")
    members = zf.infolist()
    if len(members) > MAX_FILES:
        raise UnpackError(f"archive has {len(members)} entries (limit {MAX_FILES})")
    total = 0
    dest_real = os.path.realpath(dest)
    for m in members:
        name = m.filename.replace("\\", "/")
        if name.endswith("/"):
            continue
        mode = (m.external_attr >> 16) & 0xFFFF
        if stat.S_ISLNK(mode):
            warnings.append(f"skipped symlink entry: {name}")
            continue
        target = os.path.realpath(os.path.join(dest_real, name))
        if not target.startswith(dest_real + os.sep):
            warnings.append(f"skipped path-traversal entry: {name}")
            continue
        total += m.file_size
        if total > MAX_TOTAL_BYTES:
            raise UnpackError("archive expands beyond size limit")
        if m.compress_size and m.file_size / max(m.compress_size, 1) > MAX_RATIO and m.file_size > 10 * 1024 * 1024:
            raise UnpackError(f"suspicious compression ratio for {name}")
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with zf.open(m) as src, open(target, "wb") as dst:
            shutil.copyfileobj(src, dst, 1024 * 1024)
    return warnings


def unpack(sample_path: str, dest: str) -> dict:
    """Unpack sample into dest. Returns metadata about the input."""
    os.makedirs(dest, exist_ok=True)
    meta = {"input": os.path.basename(sample_path.rstrip("/")), "input_type": None,
            "hashes": None, "crx_version": None, "crx_id": None, "warnings": []}
    if os.path.isdir(sample_path):
        meta["input_type"] = "folder"
        src_real = os.path.realpath(sample_path)
        for root, dirs, files in os.walk(src_real, followlinks=False):
            for fn in files:
                p = os.path.join(root, fn)
                if os.path.islink(p):
                    meta["warnings"].append(f"skipped symlink: {os.path.relpath(p, src_real)}")
                    continue
                rel = os.path.relpath(p, src_real)
                out = os.path.join(dest, rel)
                os.makedirs(os.path.dirname(out), exist_ok=True)
                shutil.copyfile(p, out)
        return meta
    with open(sample_path, "rb") as f:
        data = f.read()
    meta["hashes"] = file_hashes(data)
    if data[:4] == b"Cr24":
        zip_bytes, info = parse_crx(data)
        meta.update(info)
        meta["input_type"] = "crx"
    elif data[:2] == b"PK":
        zip_bytes = data
        meta["input_type"] = "zip"
    else:
        raise UnpackError("input is not a folder, CRX or ZIP")
    meta["warnings"] += _safe_extract(zip_bytes, dest)
    return meta


def inventory(root: str) -> list:
    out = []
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d != "_deob"]
        for fn in sorted(files):
            p = os.path.join(dirpath, fn)
            with open(p, "rb") as f:
                data = f.read()
            out.append({"path": os.path.relpath(p, root), "size": len(data),
                        "sha256": hashlib.sha256(data).hexdigest()})
    return sorted(out, key=lambda x: x["path"])
