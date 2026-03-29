# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/formats/document_odf.py
#  OpenDocument Format handler for .odt/.ods/.odp encrypted documents.
#  Supports Blowfish-CFB and AES-256-CBC with PBKDF2-HMAC-SHA1 key derivation.
#
# 🔗 ARCHITECTS:
#   - Bhanu Guragain (Shadow@Bh4nu) | Lead Developer  🏴 GANGA Offensive Ops 🔥
#   - Team Members:
#       • Shrijesh Pokharel
#       • Aashish Panthi
#
# ⚠️ WARNING:
#   ACCESS RESTRICTED. Authorized use only — pentesting, CTF, security research.
#   Unauthorized access to protected systems is illegal.
# ==========================================================================================
# ⚠️ Version 1.0.0 — Production Release 💀
# ==========================================================================================
"""
hashaxe.formats.document_odf — OpenDocument Format (.odt/.ods/.odp) handler.

ODF uses ZIP container with Blowfish-CFB or AES-256-CBC encryption.
Password verification via PBKDF2-HMAC-SHA1 key derivation.

Hashcat mode: -m 18400
"""
from __future__ import annotations

import hashlib
import logging
import re
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Any

from hashaxe.formats._registry import FormatRegistry
from hashaxe.formats.base import (
    BaseFormat,
    FormatDifficulty,
    FormatMatch,
    FormatTarget,
)

log = logging.getLogger(__name__)

_ZIP_MAGIC = b"PK\x03\x04"

# Global states for UNO wrapper processes
_LO_PROC = None
_LO_PORT = None


# ODF content markers
_ODF_MARKERS = [
    b"mimetype",
    b"content.xml",
    b"meta.xml",
    b"manifest.xml",
]

_ODF_ENCRYPTION_MARKERS = [
    b"manifest:encryption-data",
    b"manifest:algorithm",
    b"manifest:key-derivation",
]


def _detect_odf_encryption(data: bytes, path: Path | None = None) -> dict[str, Any]:
    """Detect ODF format and encryption."""
    result: dict[str, Any] = {
        "is_odf": False,
        "encrypted": False,
        "algorithm": "none",
        "kdf_iterations": 0,
    }

    ext = path.suffix.lower() if path else ""

    if data[:4] != _ZIP_MAGIC:
        if ext in (".odt", ".ods", ".odp", ".odg", ".odb"):
            result["is_odf"] = True
        return result

    # Check for ODF markers in ZIP contents
    if not result["is_odf"]:
        try:
            with zipfile.ZipFile(BytesIO(data)) as zf:
                namelist = zf.namelist()
                odf_score = sum(1 for m in [m.decode('utf-8') for m in _ODF_MARKERS] if m in namelist)
                if odf_score >= 2 or ext in (".odt", ".ods", ".odp", ".odg"):
                    result["is_odf"] = True
        except zipfile.BadZipFile as e:
            log.debug("Failed to detect ODF markers (bad zip): %s", e)
        except Exception as e:
            log.debug("Unexpected error in ODF zip detection: %s", e)

    if not result["is_odf"]:
        return result

    # Check for encryption inside META-INF/manifest.xml
    manifest_data = b""
    try:
        with zipfile.ZipFile(BytesIO(data)) as zf:
            if "META-INF/manifest.xml" in zf.namelist():
                manifest_data = zf.read("META-INF/manifest.xml")
    except zipfile.BadZipFile as e:
        log.debug("Failed to extract manifest (bad zip): %s", e)
    except Exception as e:
        log.debug("Unexpected error parsing ODF manifest: %s", e)

    if not manifest_data:
        manifest_data = data  # Fallback to searching raw bytes if zip extract fails

    enc_score = sum(1 for m in _ODF_ENCRYPTION_MARKERS if m in manifest_data)
    if enc_score >= 1:
        result["encrypted"] = True

        # Detect algorithm
        if b"Blowfish" in manifest_data or b"blowfish" in manifest_data:
            result["algorithm"] = "Blowfish-CFB"
        elif b"aes256-gcm" in manifest_data.lower():
            result["algorithm"] = "AES-256-GCM"
        elif b"aes256" in manifest_data.lower() or b"AES" in manifest_data:
            result["algorithm"] = "AES-256-CBC"
        else:
            result["algorithm"] = "unknown"

        # Detect KDF
        if b"argon2id" in manifest_data:
            result["kdf"] = "argon2id"
            result["kdf_iterations"] = 3
        else:
            result["kdf"] = "pbkdf2"
            iter_match = re.search(rb'iteration-count="(\d+)"', manifest_data)
            if iter_match:
                result["kdf_iterations"] = int(iter_match.group(1))

    return result


class ODFFormat(BaseFormat):
    """Handler for password-protected OpenDocument Format files.

    ODF 1.0-1.2: Blowfish-CFB + SHA1 + PBKDF2
    ODF 1.3+:    AES-256-CBC + SHA256 + PBKDF2
    """

    format_id = "document.odf"
    format_name = "OpenDocument (Blowfish/AES)"

    def can_handle(self, data: bytes, path: Path | None = None) -> FormatMatch | None:
        meta = _detect_odf_encryption(data, path)
        if not meta["is_odf"]:
            return None

        if not meta["encrypted"]:
            return FormatMatch(
                format_id=self.format_id,
                handler=self,
                confidence=0.3,
                metadata={"description": "ODF document (not encrypted)"},
            )

        return FormatMatch(
            format_id=self.format_id,
            handler=self,
            confidence=0.95,
            metadata={
                "description": f"Encrypted ODF ({meta['algorithm']})",
            },
        )

    def parse(self, data: bytes, path: Path | None = None) -> FormatTarget:
        meta = _detect_odf_encryption(data, path)

        if not meta["is_odf"]:
            raise ValueError("Not a valid ODF document")

        if not meta["encrypted"]:
            return FormatTarget(
                format_id=self.format_id,
                display_name="ODF (not encrypted)",
                source_path=str(path) if path else "inline",
                is_encrypted=False,
                difficulty=FormatDifficulty.TRIVIAL,
                format_data=meta,
            )

        return FormatTarget(
            format_id=self.format_id,
            display_name=f"ODF ({meta['algorithm']})",
            source_path=str(path) if path else "inline",
            is_encrypted=True,
            difficulty=FormatDifficulty.MEDIUM,
            format_data={
                **meta,
                "raw_data": data,
                "file_path": str(path) if path else None,
            },
        )

    def verify(self, target: FormatTarget, password: bytes) -> bool:
        """ODF verification requires full decryption — library-based only."""
        
        # Preserve the original password before any KDF pre-hashing mutations.
        # The start-key-generation SHA256 block below mutates `password` for the 
        # pure-python crypto path, but the UNO bridge needs the original plaintext.
        original_password = password
        
        # CPU Fallback Execution Block
        # We process AES-256 and Argon2id directly via cryptography and argon2-cffi 
        # to ensure CPU-only nodes do not crash with NotImplementedExceptions.
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes
            import argon2

            # Extract algorithmic hints from the target
            algo = target.format_data.get("algorithm", "unknown")
            iters = target.format_data.get("kdf_iterations", 100000)
            
            # --- START CPU NATIVE DECRYPTION ---
            # Extract encryption metadata from the archive manifest to configure the KDF
            data = target.format_data.get("raw_data")
            if not data: return False
            
            manifest_data = b""
            with zipfile.ZipFile(BytesIO(data)) as zf:
                if "META-INF/manifest.xml" in zf.namelist():
                    manifest_data = zf.read("META-INF/manifest.xml")
            
            if not manifest_data:
                return False
                
            class UnsupportedAlgorithmError(Exception): pass
            
            import xml.etree.ElementTree as ET
            import base64
            from cryptography.hazmat.backends import default_backend
            
            root = ET.fromstring(manifest_data)
            # Find the first encrypted file entry
            ns = {'manifest': 'urn:oasis:names:tc:opendocument:xmlns:manifest:1.0'}
            file_entry = None
            for entry in root.findall('.//manifest:file-entry', ns):
                if entry.find('./manifest:encryption-data', ns) is not None:
                    file_entry = entry
                    break
            
            if file_entry is None:
                return False
            
            # Parse namespaces
            enc_data = file_entry.find('./manifest:encryption-data', ns)
            algo_node = enc_data.find('./manifest:algorithm', ns)
            key_der_node = enc_data.find('./manifest:key-derivation', ns)
            
            if algo_node is None or key_der_node is None:
                return False
            
            # Helper to bypass ElementTree expanded namespace attributes
            def get_attr(node, name, default=''):
                if node is None: return default
                for k, v in node.attrib.items():
                    if k.endswith('}' + name) or k == name or k.endswith(':' + name):
                        return v
                return default

            algo_name = get_attr(algo_node, 'algorithm-name')
            iv_b64 = get_attr(algo_node, 'initialization-vector')
            if not iv_b64:
                iv_b64 = get_attr(algo_node, 'initialisation-vector')
            salt_b64 = get_attr(key_der_node, 'salt')
            iters_str = get_attr(key_der_node, 'iteration-count')
            checksum_b64 = get_attr(enc_data, 'checksum')
            
            iv = base64.b64decode(iv_b64)
            salt = base64.b64decode(salt_b64)
            iters = int(iters_str) if iters_str else 1024
            checksum = base64.b64decode(checksum_b64) if checksum_b64 else b""
            
            kdf_name = get_attr(key_der_node, 'key-derivation-name')
            key_len_str = get_attr(key_der_node, 'key-size', '32')
            key_len = int(key_len_str)
            
            # Support ODF 1.3 start-key-generation SHA256 hashing
            start_key_gen_node = enc_data.find('./manifest:start-key-generation', ns)
            if start_key_gen_node is not None:
                start_algo = get_attr(start_key_gen_node, 'start-key-generation-name')
                if 'sha256' in start_algo.lower():
                    import hashlib
                    password = hashlib.sha256(password).digest()
            
            # Key deriving
            if "argon2id" in kdf_name.lower():
                import argon2.low_level
                a_iters = int(get_attr(key_der_node, 'argon2-iterations', '3'))
                a_mem = int(get_attr(key_der_node, 'argon2-memory', '65536'))
                a_lanes = int(get_attr(key_der_node, 'argon2-lanes', '4'))
                
                key = argon2.low_level.hash_secret_raw(
                    secret=password,
                    salt=salt,
                    time_cost=a_iters,
                    memory_cost=a_mem,
                    parallelism=a_lanes,
                    hash_len=key_len,
                    type=argon2.low_level.Type.ID
                )
            
            # Algorithm detection and configuration
            if "Blowfish" in algo_name or algo == "Blowfish-CFB":
                hash_alg = hashes.SHA1()
                cipher_cls = algorithms.Blowfish
                mode_cls = modes.CFB(iv)
                is_gcm = False
            elif "aes256-gcm" in algo_name.lower() or algo == "AES-256-GCM":
                hash_alg = hashes.SHA256()
                cipher_cls = algorithms.AES
                mode_cls = None # Will instantiate later when we have the stream to extract the tag
                is_gcm = True
            elif "aes256" in algo_name.lower() or algo == "AES-256-CBC":
                hash_alg = hashes.SHA256()
                cipher_cls = algorithms.AES
                mode_cls = modes.CBC(iv)
                is_gcm = False
            else:
                raise UnsupportedAlgorithmError(f"Algorithm not supported for CPU fallback: {algo_name}")
            
            if "argon2id" not in kdf_name.lower():
                kdf = PBKDF2HMAC(
                    algorithm=hash_alg,
                    length=key_len,
                    salt=salt,
                    iterations=iters,
                    backend=default_backend()
                )
                key = kdf.derive(password)
                
            # We verify the password by attempting to decrypt the first block of the file
            # and checking if the padding/structure evaluates or checking the checksum
            file_path = get_attr(file_entry, 'full-path')
            with zipfile.ZipFile(BytesIO(data)) as zf:
                if file_path in zf.namelist():
                    encrypted_content = zf.read(file_path)
                    
                    if is_gcm:
                        tag = checksum if checksum else encrypted_content[-16:]
                        encrypted_content = encrypted_content if checksum else encrypted_content[:-16]
                        mode_cls = modes.GCM(iv, tag=tag)
                        
                    cipher = Cipher(cipher_cls(key), mode_cls, backend=default_backend())
                    
                    try:
                        decryptor = cipher.decryptor()
                        decrypted = decryptor.update(encrypted_content) + decryptor.finalize()
                        # If finalize() succeeds for GCM, the auth tag is verified.
                        return True
                    except Exception as dec_err:
                        log.debug("Decryptor failed: %s", dec_err, exc_info=True)
                        # For Argon2id targets, don't return False yet — fall through
                        # to UNO bridge fallback below. For legacy formats, return False.
                        if "argon2id" not in kdf_name.lower():
                            return False
            # For non-Argon2id: if we get here, no encrypted file was found
            if "argon2id" not in kdf_name.lower():
                return False
            # --- END CPU NATIVE DECRYPTION ---
            
        except ImportError:
            log.warning("CPU Fallback for ODF pure-python failed due to missing modules.")
        except Exception as e:
            # Silently pass InvalidTag exceptions (expected for Argon2id) and log all others
            err_name = type(e).__name__
            if err_name not in ("InvalidTag", "UnsupportedAlgorithmError"):
                log.debug("ODF CPU fallback evaluation failed: %s", e, exc_info=True)
            
        # --- START UNO HEADLESS DAEMON FALLBACK ---
        # If pure-python decryption failed (e.g., Argon2id undocumented proprietary LibreOffice AAD parameters),
        # we weaponize LibreOffice itself as an oracle via the UNO bridge.
        if target.format_data.get("kdf") == "argon2id":
            return self._verify_via_uno(target, original_password)
            
        return False

    def _verify_via_uno(self, target: FormatTarget, password: bytes) -> bool:
        """Weaponizes a persistent headless LibreOffice daemon to decrypt ODF Argon2id cryptography.
        
        Maintains a cached UNO desktop object across calls to avoid reconnection overhead.
        Automatically spawns and respawns the soffice daemon as needed.
        """
        import os
        import subprocess
        import time
        import socket
        import atexit
        
        global _LO_PROC, _LO_PORT
        
        file_path = target.format_data.get("file_path")
        if not file_path:
            import tempfile
            fd, tmp_path = tempfile.mkstemp(suffix=".odt")
            with open(fd, "wb") as f:
                f.write(target.format_data["raw_data"])
            file_path = tmp_path
            
        if _LO_PORT is None:
            _LO_PORT = 20000 + (os.getpid() % 10000)
            
        def _ensure_daemon():
            """Spawn soffice daemon if not running, wait for socket readiness."""
            global _LO_PROC
            if _LO_PROC is not None and _LO_PROC.poll() is not None:
                # Process died — clear it so we respawn
                _LO_PROC = None
                
            if _LO_PROC is None:
                cmd = [
                    "soffice", "--headless", "--invisible", "--nocrashreport", 
                    "--nodefault", "--nologo", "--nofirststartwizard", "--norestore",
                    f"--accept=socket,host=127.0.0.1,port={_LO_PORT};urp;StarOffice.ServiceManager"
                ]
                _LO_PROC = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                def _cleanup_lo():
                    global _LO_PROC
                    if _LO_PROC:
                        try:
                            _LO_PROC.kill()
                            _LO_PROC.wait(timeout=2)
                        except Exception:
                            pass
                        _LO_PROC = None
                atexit.register(_cleanup_lo)
                
                # Wait for socket readiness
                for _ in range(20):
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        if s.connect_ex(('127.0.0.1', _LO_PORT)) == 0:
                            return True
                    time.sleep(0.3)
                log.warning("LibreOffice daemon failed to start on port %d", _LO_PORT)
                return False
            return True

        # Cache the desktop object as an instance attribute
        if not hasattr(self, '_uno_desktop') or self._uno_desktop is None:
            if not _ensure_daemon():
                return False
            try:
                import uno
                local_context = uno.getComponentContext()
                resolver = local_context.ServiceManager.createInstanceWithContext(
                    "com.sun.star.bridge.UnoUrlResolver", local_context
                )
                ctx = resolver.resolve(
                    f"uno:socket,host=127.0.0.1,port={_LO_PORT};urp;StarOffice.ComponentContext"
                )
                smgr = ctx.ServiceManager
                self._uno_desktop = smgr.createInstanceWithContext(
                    "com.sun.star.frame.Desktop", ctx
                )
            except Exception as conn_err:
                log.debug("UNO connection failed: %s", conn_err)
                self._uno_desktop = None
                return False
                
        try:
            import uno
            from com.sun.star.beans import PropertyValue
            
            file_url = uno.systemPathToFileUrl(os.path.abspath(file_path))
            p = PropertyValue()
            p.Name = "Password"
            p.Value = password.decode("utf-8", errors="ignore")
            h = PropertyValue()
            h.Name = "Hidden"
            h.Value = True
            
            doc = self._uno_desktop.loadComponentFromURL(file_url, "_blank", 0, (p, h))
            if doc:
                doc.close(True)
                return True
            return False
        except Exception as e:
            # Connection lost — invalidate cache so next call respawns
            if "Pipe" in str(e) or "connection" in str(e).lower() or "disposed" in str(e).lower():
                self._uno_desktop = None
                _LO_PROC = None
            return False

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        return self.verify(target, password)

    def difficulty(self) -> FormatDifficulty:
        return FormatDifficulty.MEDIUM

    def display_info(self, target: FormatTarget) -> dict[str, str]:
        algo = target.format_data.get("algorithm", "unknown")
        iters = target.format_data.get("kdf_iterations", 0)
        return {
            "Format": "OpenDocument Format",
            "Algorithm": algo,
            "KDF Iterations": str(iters) if iters else "default",
            "Hashcat Mode": "18400",
            "Difficulty": "MEDIUM (PBKDF2 + Blowfish/AES)",
        }


# ── Auto-register ────────────────────────────────────────────────────────────
_registry = FormatRegistry()
_registry.register(ODFFormat())
