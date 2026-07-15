"""
Shared constants and TCP control-channel helpers for the Hybrid FTP system.

Both server.py and client.py import from this module to guarantee
consistent reply codes, line framing, and PORT/PASV encoding.
"""

from __future__ import annotations

import logging
import os
import re
import socket
import stat
import sys
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

# ─────────────────────────────────────────────────────
#  FTP Reply Codes  (RFC 959 + common extensions)
# ─────────────────────────────────────────────────────

# 1xx — Positive Preliminary
R125 = 125  # Data connection already open; transfer starting
R150 = 150  # About to open data connection

# 2xx — Positive Completion
R200 = 200  # Command okay
R211 = 211  # System status / directory status
R213 = 213  # File status  (SIZE, MDTM, HASH)
R214 = 214  # Help message
R215 = 215  # NAME system type
R220 = 220  # Service ready for new user
R221 = 221  # Service closing control connection
R226 = 226  # Transfer complete
R227 = 227  # Entering Passive Mode
R230 = 230  # User logged in, proceed
R250 = 250  # Requested file action okay
R257 = 257  # "PATHNAME" created / current directory

# 3xx — Positive Intermediate
R331 = 331  # User name okay, need password
R350 = 350  # Requested file action pending (RNFR)

# 4xx — Transient Negative
R421 = 421  # Service not available
R425 = 425  # Can't open data connection
R426 = 426  # Transfer aborted
R450 = 450  # File unavailable (busy)
R451 = 451  # Local error in processing

# 5xx — Permanent Negative
R500 = 500  # Syntax error / unrecognized command
R501 = 501  # Syntax error in parameters
R502 = 502  # Command not implemented
R503 = 503  # Bad sequence of commands
R530 = 530  # Not logged in
R550 = 550  # File unavailable (not found / permission denied)
R553 = 553  # File name not allowed

# ─────────────────────────────────────────────────────
#  Configuration Defaults
# ─────────────────────────────────────────────────────

DEFAULT_HOST = "127.0.0.1"
DEFAULT_CTRL_PORT = 2121
ENCODING = "utf-8"
CRLF = "\r\n"
CTRL_MAX_LINE = 8192        # max bytes before discarding (anti-DoS)
RECV_CHUNK = 4096

# Hardcoded user store (username → password, empty string = no password)
USERS: Dict[str, str] = {
    "anonymous": "",
    "admin": "admin123",
    "user": "pass123",
}

# ─────────────────────────────────────────────────────
#  TCP Control-Channel I/O
# ─────────────────────────────────────────────────────

class ControlChannel:
    """
    Line-oriented FTP control message I/O over a TCP socket.

    Handles partial reads, CRLF framing, and buffer management.
    One instance per direction (server side or client side).
    """

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self._buf = b""

    # ── Sending ──────────────────────────────────────

    def send_reply(self, code: int, message: str) -> None:
        """Send ``### message\\r\\n``."""
        self.sock.sendall(f"{code} {message}{CRLF}".encode(ENCODING))

    def send_command(self, command: str) -> None:
        """Send ``COMMAND args\\r\\n``."""
        self.sock.sendall(f"{command}{CRLF}".encode(ENCODING))

    # ── Receiving ────────────────────────────────────

    def recv_line(self) -> Optional[str]:
        """
        Block until one CRLF-terminated line arrives.

        Returns the line *without* CRLF, or ``None`` on disconnect.
        Drops the buffer if a peer floods data without a CRLF.
        """
        while True:
            idx = self._buf.find(b"\r\n")
            if idx >= 0:
                line = self._buf[:idx]
                self._buf = self._buf[idx + 2:]
                return line.decode(ENCODING, errors="replace")

            if len(self._buf) > CTRL_MAX_LINE:
                self._buf = b""
                return None

            try:
                chunk = self.sock.recv(RECV_CHUNK)
            except (ConnectionResetError, ConnectionAbortedError, OSError):
                return None
            if not chunk:
                return None
            self._buf += chunk

    def recv_reply(self) -> Tuple[Optional[int], str]:
        """
        Read an FTP reply line.  Returns ``(code, message)`` or
        ``(None, "")`` on disconnect.

        Multi-line replies (``###-text``) are consumed until the
        final ``### text`` terminator.
        """
        lines: list[str] = []
        while True:
            raw = self.recv_line()
            if raw is None:
                return None, ""
            lines.append(raw)
            # A line that starts with 3 digits followed by a space
            # (not a hyphen) terminates the reply.
            if len(raw) >= 3 and raw[:3].isdigit() and (len(raw) == 3 or raw[3] == " "):
                code = int(raw[:3])
                message = raw[4:] if len(raw) > 4 else ""
                if len(lines) > 1:
                    message = "\n".join(lines)
                return code, message

    def peek_line_nonblocking(self) -> Optional[str]:
        """
        Non-blocking read attempt used during transfers to detect ABOR.
        Returns a line if available, ``None`` otherwise.
        """
        prev = self.sock.gettimeout()
        try:
            self.sock.setblocking(False)
            try:
                chunk = self.sock.recv(RECV_CHUNK)
                if chunk:
                    self._buf += chunk
            except BlockingIOError:
                pass
            except (ConnectionResetError, ConnectionAbortedError, OSError):
                return None
        finally:
            self.sock.settimeout(prev)

        idx = self._buf.find(b"\r\n")
        if idx >= 0:
            line = self._buf[:idx]
            self._buf = self._buf[idx + 2:]
            return line.decode(ENCODING, errors="replace")
        return None

    def close(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()

# ─────────────────────────────────────────────────────
#  PORT / PASV Encoding
# ─────────────────────────────────────────────────────

def parse_port_args(arg_str: str) -> Tuple[str, int]:
    """
    Parse ``h1,h2,h3,h4,p1,p2`` into ``(host, port)``.
    Raises ``ValueError`` on malformed input.
    """
    parts = [p.strip() for p in arg_str.split(",")]
    if len(parts) != 6:
        raise ValueError("PORT requires exactly 6 comma-separated values")
    nums = [int(p) for p in parts]
    for n in nums:
        if not 0 <= n <= 255:
            raise ValueError("PORT octet values must be 0–255")
    host = f"{nums[0]}.{nums[1]}.{nums[2]}.{nums[3]}"
    port = nums[4] * 256 + nums[5]
    if port == 0:
        raise ValueError("PORT port cannot be zero")
    return host, port


def format_port_args(host: str, port: int) -> str:
    """Format ``(host, port)`` as ``h1,h2,h3,h4,p1,p2``."""
    octets = host.split(".")
    if len(octets) != 4:
        raise ValueError("host must be a dotted-quad IPv4 address")
    p1, p2 = divmod(port, 256)
    return f"{octets[0]},{octets[1]},{octets[2]},{octets[3]},{p1},{p2}"


def parse_pasv_reply(message: str) -> Tuple[str, int]:
    """
    Extract ``(host, port)`` from a 227 Entering Passive Mode reply.
    Expected: ``... (h1,h2,h3,h4,p1,p2)``
    """
    match = re.search(r"\((\d+,\d+,\d+,\d+,\d+,\d+)\)", message)
    if not match:
        raise ValueError("cannot parse PASV reply: " + message)
    return parse_port_args(match.group(1))

# ─────────────────────────────────────────────────────
#  Transfer Negotiation Fields (in 150 / 226 replies)
# ─────────────────────────────────────────────────────

def format_150(transfer_id: int) -> str:
    """Build the message part of a 150 reply with embedded transfer ID."""
    return f"Opening data channel. TRANSFER_ID={transfer_id}"


def parse_150(message: str) -> int:
    """Extract ``TRANSFER_ID`` from a 150 reply message."""
    m = re.search(r"TRANSFER_ID=(\d+)", message)
    if not m:
        raise ValueError("cannot parse TRANSFER_ID from 150 reply")
    return int(m.group(1))


def format_226(sha256_hex: str, byte_count: int) -> str:
    return f"Transfer complete. SHA256={sha256_hex} BYTES={byte_count}"


def parse_226(message: str) -> Tuple[Optional[str], Optional[int]]:
    """Extract optional SHA256 and BYTES fields from a 226 reply."""
    sha_m = re.search(r"SHA256=([0-9a-fA-F]+)", message)
    bytes_m = re.search(r"BYTES=(\d+)", message)
    sha = sha_m.group(1) if sha_m else None
    nbytes = int(bytes_m.group(1)) if bytes_m else None
    return sha, nbytes

# ─────────────────────────────────────────────────────
#  Socket Helpers
# ─────────────────────────────────────────────────────

def create_udp_socket(host: str = "", port: int = 0) -> socket.socket:
    """Create, bind, and return a UDP socket (port 0 = OS-assigned)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    return sock

# ─────────────────────────────────────────────────────
#  Path Safety & FTP Path Formatting
# ─────────────────────────────────────────────────────

def safe_resolve(root: Path, cwd: Path, path_str: str) -> Path:
    """
    Resolve *path_str* (user input) relative to *cwd* inside the
    *root* jail.  Raises ``ValueError`` if the result escapes the root.

    FTP uses Unix-style paths regardless of OS.  An "absolute" FTP
    path like ``/foo`` is interpreted as ``root/foo``.
    """
    if not path_str or path_str.strip() == "":
        return cwd

    cleaned = path_str.replace("\\", "/").strip()

    if cleaned.startswith("/"):
        # Absolute FTP path → relative to root
        resolved = (root / cleaned.lstrip("/")).resolve()
    else:
        resolved = (cwd / cleaned).resolve()

    root_resolved = root.resolve()
    try:
        resolved.relative_to(root_resolved)
    except ValueError:
        raise ValueError(f"path escapes server root: {path_str}")
    return resolved


def to_ftp_path(root: Path, resolved: Path) -> str:
    """Convert a resolved server-side path to the FTP-visible path."""
    try:
        rel = resolved.resolve().relative_to(root.resolve())
        posix = rel.as_posix()
        if posix == ".":
            return "/"
        return "/" + posix
    except ValueError:
        return "/"

# ─────────────────────────────────────────────────────
#  Directory Listing Formatters
# ─────────────────────────────────────────────────────

def _perm_string(mode: int) -> str:
    """Convert a stat mode to a Unix ``-rwxrwxrwx`` or ``drwxrwxrwx`` string."""
    is_dir = "d" if stat.S_ISDIR(mode) else "-"
    perms = ""
    for who in ("USR", "GRP", "OTH"):
        r = "r" if mode & getattr(stat, f"S_IR{who}") else "-"
        w = "w" if mode & getattr(stat, f"S_IW{who}") else "-"
        x = "x" if mode & getattr(stat, f"S_IX{who}") else "-"
        perms += r + w + x
    return is_dir + perms


def format_list_line(entry: Path) -> str:
    """
    Produce one ``ls -l`` style line for a directory entry.
    Example: ``drwxr-xr-x  1 owner group  4096 Jul 15 12:34 dirname``
    """
    try:
        st = entry.stat()
    except OSError:
        return ""
    perm = _perm_string(st.st_mode)
    nlinks = 1
    owner = "owner"
    group = "group"
    size = st.st_size
    mtime = time.localtime(st.st_mtime)
    # If modified within the last 6 months, show time; otherwise year.
    six_months_ago = time.time() - 180 * 86400
    if st.st_mtime > six_months_ago:
        date_str = time.strftime("%b %d %H:%M", mtime)
    else:
        date_str = time.strftime("%b %d  %Y", mtime)
    return f"{perm} {nlinks:>3} {owner:<8} {group:<8} {size:>10} {date_str} {entry.name}"

# ─────────────────────────────────────────────────────
#  Logging
# ─────────────────────────────────────────────────────

def setup_logging(name: str, level: int = logging.INFO) -> logging.Logger:
    """Create a timestamped, thread-aware logger."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(threadName)s] %(levelname)s %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        ))
        logger.addHandler(handler)
    logger.setLevel(level)
    return logger

# ─────────────────────────────────────────────────────
#  Help Text
# ─────────────────────────────────────────────────────

COMMAND_HELP: Dict[str, str] = {
    "USER": "USER <username> — Specify the user for authentication.",
    "PASS": "PASS <password> — Specify the password for authentication.",
    "QUIT": "QUIT — Disconnect from the server.",
    "NOOP": "NOOP — No operation (keep-alive).",
    "PWD":  "PWD — Print the current working directory.",
    "CWD":  "CWD <path> — Change working directory.",
    "CDUP": "CDUP — Change to the parent directory.",
    "MKD":  "MKD <dirname> — Create a directory.",
    "RMD":  "RMD <dirname> — Remove an empty directory.",
    "LIST": "LIST [path] — List directory contents in detail.",
    "NLST": "NLST [path] — List directory names only.",
    "STAT": "STAT [path] — Show server or file/directory status.",
    "SIZE": "SIZE <filename> — Show file size in bytes.",
    "MDTM": "MDTM <filename> — Show file last-modified timestamp.",
    "TYPE": "TYPE {A|I} — Set transfer type (A=ASCII, I=Binary).",
    "MODE": "MODE {S} — Set transfer mode (S=Stream).",
    "PORT": "PORT h1,h2,h3,h4,p1,p2 — Set active mode data address.",
    "PASV": "PASV — Enter passive mode.",
    "RETR": "RETR <filename> — Download a file.",
    "STOR": "STOR <filename> — Upload a file.",
    "STOU": "STOU — Upload with a unique server-generated filename.",
    "APPE": "APPE <filename> — Append data to a file.",
    "DELE": "DELE <filename> — Delete a file.",
    "RNFR": "RNFR <oldname> — Specify rename source (followed by RNTO).",
    "RNTO": "RNTO <newname> — Specify rename destination.",
    "HASH": "HASH <filename> — Compute SHA-256 of a server-side file.",
    "ABOR": "ABOR — Abort the current data transfer.",
    "HELP": "HELP [command] — Show available commands or help for one command.",
}
