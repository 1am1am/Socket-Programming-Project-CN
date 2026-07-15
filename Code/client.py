"""
Interactive Hybrid FTP Client.

TCP control channel  +  custom Reliable-UDP data channel.
Supports both Active (PORT) and Passive (PASV) data modes.
"""

from __future__ import annotations

import getpass
import os
import socket
import sys
import time
from pathlib import Path
from typing import Optional, Tuple

from rdt_udp import (
    RDTError,
    TransferProgress,
    TransferResult,
    establish_udp,
    receive_bytes as rdt_receive_bytes,
    receive_file as rdt_receive_file,
    send_file as rdt_send_file,
)
from utils import (
    ControlChannel,
    DEFAULT_CTRL_PORT,
    DEFAULT_HOST,
    R150,
    R200,
    R226,
    R227,
    R230,
    R250,
    R331,
    R350,
    create_udp_socket,
    format_port_args,
    parse_150,
    parse_226,
    parse_pasv_reply,
)


def _human_bytes(n: int) -> str:
    """Format byte count for display."""
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} {unit}"
        n /= 1024  # type: ignore[assignment]
    return f"{n:.1f} TB"


def _progress_cb(p: TransferProgress) -> None:
    """Overwrite-line progress display during transfers."""
    done = _human_bytes(p.bytes_completed)
    total = _human_bytes(p.total_bytes) if p.total_bytes else "?"
    sys.stdout.write(
        f"\r  {p.direction}: {done} / {total}  "
        f"in-flight={p.packets_in_flight}  retx={p.retransmissions}  "
    )
    sys.stdout.flush()


def _print_result(result: TransferResult) -> None:
    """Print post-transfer statistics."""
    speed = result.bytes_transferred / result.duration if result.duration > 0 else 0
    print(
        f"\n  Transfer complete: {_human_bytes(result.bytes_transferred)} in "
        f"{result.duration:.2f}s ({_human_bytes(int(speed))}/s)"
    )
    print(f"  SHA-256: {result.sha256}")
    print(
        f"  Packets: sent={result.packets_sent} recv={result.packets_received} "
        f"retx={result.retransmissions} dup={result.duplicate_packets}"
    )


class FTPClient:
    """Interactive command-line FTP client with Reliable UDP data channel."""

    def __init__(self) -> None:
        self.ctrl: Optional[ControlChannel] = None
        self.server_host = ""
        self.server_port = 0
        self.local_host = DEFAULT_HOST
        self.passive_mode = True
        self.transfer_type = "I"
        self.connected = False
        self.logged_in = False
        self._quit_requested = False

    # ── Interactive CLI ──────────────────────────────

    def run(self) -> None:
        print("Hybrid FTP Client  (type 'help' for commands)")
        while not self._quit_requested:
            try:
                line = input("ftp> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                if self.connected:
                    self.do_quit("")
                break
            if not line:
                continue
            parts = line.split(None, 1)
            cmd = parts[0].lower()
            args = parts[1] if len(parts) > 1 else ""

            # Aliases
            if cmd in ("bye", "exit"):
                cmd = "quit"

            # Connection check (some commands don't require it)
            no_conn_cmds = {"open", "help", "quit", "passive"}
            if cmd not in no_conn_cmds and not self.connected:
                print("Not connected. Use 'open host [port]' first.")
                continue

            handler = getattr(self, f"do_{cmd}", None)
            if handler is None:
                print(f"Unknown command: {cmd}. Type 'help' for commands.")
                continue
            try:
                handler(args)
            except (ConnectionError, OSError) as e:
                print(f"Connection error: {e}")
                self._disconnect()
            except RDTError as e:
                print(f"Transfer error: {e}")
            except Exception as e:
                print(f"Error: {e}")

    # ── Connection & Auth ────────────────────────────

    def do_open(self, args: str) -> None:
        if self.connected:
            print("Already connected. Use 'quit' first.")
            return
        parts = args.split()
        if not parts:
            print("Usage: open host [port]")
            return
        host = parts[0]
        port = int(parts[1]) if len(parts) > 1 else DEFAULT_CTRL_PORT

        print(f"Connecting to {host}:{port}...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        try:
            sock.connect((host, port))
        except (ConnectionRefusedError, socket.timeout, OSError) as e:
            print(f"Connection failed: {e}")
            sock.close()
            return
        sock.settimeout(None)

        self.ctrl = ControlChannel(sock)
        self.server_host = host
        self.server_port = port
        self.connected = True

        # Receive welcome
        code, msg = self.ctrl.recv_reply()
        if code is None:
            print("Server closed connection.")
            self._disconnect()
            return
        print(f"{code} {msg}")

        # USER
        username = input("Username: ").strip()
        if not username:
            username = "anonymous"
        self.ctrl.send_command(f"USER {username}")
        code, msg = self.ctrl.recv_reply()
        print(f"{code} {msg}")
        if code is None:
            self._disconnect()
            return

        if code == R331:
            password = getpass.getpass("Password: ")
            self.ctrl.send_command(f"PASS {password}")
            code, msg = self.ctrl.recv_reply()
            print(f"{code} {msg}")
            if code is None:
                self._disconnect()
                return

        if code == R230:
            self.logged_in = True
        else:
            print("Login failed.")
            self._disconnect()

    # ── Data channel setup ───────────────────────────

    def _setup_data_channel(self) -> Optional[Tuple[socket.socket, bool, Tuple[str, int]]]:
        """
        Prepare the data channel before a transfer command.

        Returns (udp_sock, client_is_initiator, server_udp_addr) or None.

        PASV: send PASV → get server UDP addr → client will INITIATE
        PORT: bind local UDP → send PORT → client will RESPOND
        """
        if self.passive_mode:
            self.ctrl.send_command("PASV")
            code, msg = self.ctrl.recv_reply()
            if code != R227:
                print(f"{code} {msg}")
                return None
            try:
                server_udp_host, server_udp_port = parse_pasv_reply(msg)
            except ValueError as e:
                print(f"PASV parse error: {e}")
                return None
            # Create a local UDP socket for this transfer
            udp_sock = create_udp_socket(self.local_host, 0)
            return udp_sock, True, (server_udp_host, server_udp_port)

        else:
            # Active mode: bind local UDP socket, send PORT
            udp_sock = create_udp_socket(self.local_host, 0)
            bound_host, bound_port = udp_sock.getsockname()
            pa = format_port_args(bound_host, bound_port)
            self.ctrl.send_command(f"PORT {pa}")
            code, msg = self.ctrl.recv_reply()
            if code != R200:
                print(f"{code} {msg}")
                udp_sock.close()
                return None
            # Server will initiate to us → we are responder
            return udp_sock, False, (self.server_host, 0)

    def _establish_transfer(
        self,
        udp_sock: socket.socket,
        client_is_initiator: bool,
        server_udp_addr: Tuple[str, int],
        transfer_id: int,
    ):
        """Run the RDT handshake and return the session."""
        if client_is_initiator:
            return establish_udp(
                udp_sock, transfer_id,
                initiator=True,
                peer=server_udp_addr,
            )
        else:
            return establish_udp(
                udp_sock, transfer_id,
                initiator=False,
                expected_peer=server_udp_addr,
            )

    # ── Directory listing ────────────────────────────

    def do_ls(self, args: str) -> None:
        channel = self._setup_data_channel()
        if channel is None:
            return
        udp_sock, is_initiator, server_addr = channel

        cmd = f"LIST {args}".strip()
        self.ctrl.send_command(cmd)
        code, msg = self.ctrl.recv_reply()
        if code != R150:
            print(f"{code} {msg}")
            udp_sock.close()
            return

        try:
            tid = parse_150(msg)
            session = self._establish_transfer(udp_sock, is_initiator, server_addr, tid)
            data, _result = rdt_receive_bytes(session)
            print(data.decode("utf-8", errors="replace"))
        finally:
            udp_sock.close()

        code, msg = self.ctrl.recv_reply()
        if code:
            print(f"{code} {msg}")

    def do_dir(self, args: str) -> None:
        channel = self._setup_data_channel()
        if channel is None:
            return
        udp_sock, is_initiator, server_addr = channel

        cmd = f"NLST {args}".strip()
        self.ctrl.send_command(cmd)
        code, msg = self.ctrl.recv_reply()
        if code != R150:
            print(f"{code} {msg}")
            udp_sock.close()
            return

        try:
            tid = parse_150(msg)
            session = self._establish_transfer(udp_sock, is_initiator, server_addr, tid)
            data, _result = rdt_receive_bytes(session)
            print(data.decode("utf-8", errors="replace"))
        finally:
            udp_sock.close()

        code, msg = self.ctrl.recv_reply()
        if code:
            print(f"{code} {msg}")

    # ── File download ────────────────────────────────

    def do_get(self, args: str) -> None:
        parts = args.split()
        if not parts:
            print("Usage: get remote_file [local_file]")
            return
        remote = parts[0]
        local = parts[1] if len(parts) > 1 else Path(remote).name

        channel = self._setup_data_channel()
        if channel is None:
            return
        udp_sock, is_initiator, server_addr = channel

        self.ctrl.send_command(f"RETR {remote}")
        code, msg = self.ctrl.recv_reply()
        if code != R150:
            print(f"{code} {msg}")
            udp_sock.close()
            return

        try:
            tid = parse_150(msg)
            session = self._establish_transfer(udp_sock, is_initiator, server_addr, tid)
            result = rdt_receive_file(
                session, local, overwrite=True, progress=_progress_cb,
            )
            _print_result(result)
        finally:
            udp_sock.close()

        code, msg = self.ctrl.recv_reply()
        if code:
            sha, nbytes = parse_226(msg) if code == R226 else (None, None)
            print(f"{code} {msg}")

    # ── File upload ──────────────────────────────────

    def do_put(self, args: str) -> None:
        parts = args.split()
        if not parts:
            print("Usage: put local_file [remote_file]")
            return
        local = parts[0]
        remote = parts[1] if len(parts) > 1 else Path(local).name

        if not Path(local).is_file():
            print(f"Local file not found: {local}")
            return

        channel = self._setup_data_channel()
        if channel is None:
            return
        udp_sock, is_initiator, server_addr = channel

        self.ctrl.send_command(f"STOR {remote}")
        code, msg = self.ctrl.recv_reply()
        if code != R150:
            print(f"{code} {msg}")
            udp_sock.close()
            return

        try:
            tid = parse_150(msg)
            session = self._establish_transfer(udp_sock, is_initiator, server_addr, tid)
            result = rdt_send_file(
                session, local, progress=_progress_cb,
            )
            _print_result(result)
        finally:
            udp_sock.close()

        code, msg = self.ctrl.recv_reply()
        if code:
            print(f"{code} {msg}")

    def do_append(self, args: str) -> None:
        parts = args.split()
        if not parts:
            print("Usage: append local_file [remote_file]")
            return
        local = parts[0]
        remote = parts[1] if len(parts) > 1 else Path(local).name

        if not Path(local).is_file():
            print(f"Local file not found: {local}")
            return

        channel = self._setup_data_channel()
        if channel is None:
            return
        udp_sock, is_initiator, server_addr = channel

        self.ctrl.send_command(f"APPE {remote}")
        code, msg = self.ctrl.recv_reply()
        if code != R150:
            print(f"{code} {msg}")
            udp_sock.close()
            return

        try:
            tid = parse_150(msg)
            session = self._establish_transfer(udp_sock, is_initiator, server_addr, tid)
            result = rdt_send_file(session, local, progress=_progress_cb)
            _print_result(result)
        finally:
            udp_sock.close()

        code, msg = self.ctrl.recv_reply()
        if code:
            print(f"{code} {msg}")

    def do_stou(self, _args: str) -> None:
        # STOU requires a local file to upload
        local = input("Local file to upload: ").strip()
        if not local or not Path(local).is_file():
            print(f"Local file not found: {local}")
            return

        channel = self._setup_data_channel()
        if channel is None:
            return
        udp_sock, is_initiator, server_addr = channel

        self.ctrl.send_command("STOU")
        code, msg = self.ctrl.recv_reply()
        if code != R150:
            print(f"{code} {msg}")
            udp_sock.close()
            return

        try:
            tid = parse_150(msg)
            session = self._establish_transfer(udp_sock, is_initiator, server_addr, tid)
            result = rdt_send_file(session, local, progress=_progress_cb)
            _print_result(result)
        finally:
            udp_sock.close()

        code, msg = self.ctrl.recv_reply()
        if code:
            print(f"{code} {msg}")

    # ── Simple commands (no data channel) ────────────

    def _simple_cmd(self, command: str) -> Tuple[Optional[int], str]:
        """Send a command, receive and print the reply."""
        self.ctrl.send_command(command)
        code, msg = self.ctrl.recv_reply()
        if code is not None:
            print(f"{code} {msg}")
        else:
            print("Server disconnected.")
            self._disconnect()
        return code, msg

    def do_pwd(self, _args: str) -> None:
        self._simple_cmd("PWD")

    def do_cd(self, args: str) -> None:
        if not args:
            print("Usage: cd <path>")
            return
        self._simple_cmd(f"CWD {args}")

    def do_cdup(self, _args: str) -> None:
        self._simple_cmd("CDUP")

    def do_mkdir(self, args: str) -> None:
        if not args:
            print("Usage: mkdir <dirname>")
            return
        self._simple_cmd(f"MKD {args}")

    def do_rmdir(self, args: str) -> None:
        if not args:
            print("Usage: rmdir <dirname>")
            return
        self._simple_cmd(f"RMD {args}")

    def do_delete(self, args: str) -> None:
        if not args:
            print("Usage: delete <filename>")
            return
        self._simple_cmd(f"DELE {args}")

    def do_rename(self, args: str) -> None:
        parts = args.split()
        if len(parts) < 2:
            print("Usage: rename <old_name> <new_name>")
            return
        old, new = parts[0], parts[1]
        self.ctrl.send_command(f"RNFR {old}")
        code, msg = self.ctrl.recv_reply()
        print(f"{code} {msg}")
        if code != R350:
            return
        self.ctrl.send_command(f"RNTO {new}")
        code, msg = self.ctrl.recv_reply()
        print(f"{code} {msg}")

    def do_size(self, args: str) -> None:
        if not args:
            print("Usage: size <filename>")
            return
        self._simple_cmd(f"SIZE {args}")

    def do_mdtm(self, args: str) -> None:
        if not args:
            print("Usage: mdtm <filename>")
            return
        self._simple_cmd(f"MDTM {args}")

    def do_hash(self, args: str) -> None:
        if not args:
            print("Usage: hash <filename>")
            return
        self._simple_cmd(f"HASH {args}")

    def do_stat(self, args: str) -> None:
        cmd = f"STAT {args}".strip()
        self._simple_cmd(cmd)

    def do_type(self, args: str) -> None:
        if not args:
            print(f"Current transfer type: {self.transfer_type}")
            return
        t = args.upper().strip()
        if t in ("A", "I"):
            self.transfer_type = t
            self._simple_cmd(f"TYPE {t}")
        else:
            print("Usage: type a|i")

    def do_mode(self, args: str) -> None:
        m = args.upper().strip() if args else "S"
        self._simple_cmd(f"MODE {m}")

    def do_noop(self, _args: str) -> None:
        self._simple_cmd("NOOP")

    def do_abort(self, _args: str) -> None:
        self._simple_cmd("ABOR")

    def do_help(self, args: str) -> None:
        if args and self.connected:
            self._simple_cmd(f"HELP {args}")
            return
        print(
            "Available commands:\n"
            "  open host [port]     — Connect to FTP server\n"
            "  ls [path]            — List directory (detailed)\n"
            "  dir [path]           — List directory (names only)\n"
            "  pwd                  — Print working directory\n"
            "  cd <path>            — Change directory\n"
            "  cdup                 — Go to parent directory\n"
            "  mkdir <name>         — Create directory\n"
            "  rmdir <name>         — Remove directory\n"
            "  get <remote> [local] — Download file\n"
            "  put <local> [remote] — Upload file\n"
            "  append <local> [rem] — Append to remote file\n"
            "  stou                 — Upload with unique name\n"
            "  delete <file>        — Delete remote file\n"
            "  rename <old> <new>   — Rename remote file\n"
            "  size <file>          — Show file size\n"
            "  mdtm <file>          — Show last-modified time\n"
            "  hash <file>          — SHA-256 of remote file\n"
            "  stat [path]          — Server/file status\n"
            "  type [a|i]           — Set transfer type\n"
            "  mode [s]             — Set transfer mode\n"
            "  passive              — Toggle passive/active mode\n"
            "  noop                 — Keep-alive ping\n"
            "  abort                — Abort current transfer\n"
            "  help [cmd]           — Show help\n"
            "  quit / bye           — Disconnect and exit"
        )

    def do_passive(self, _args: str) -> None:
        self.passive_mode = not self.passive_mode
        mode = "Passive (PASV)" if self.passive_mode else "Active (PORT)"
        print(f"Data mode: {mode}")

    def do_quit(self, _args: str) -> None:
        if self.connected and self.ctrl:
            try:
                self.ctrl.send_command("QUIT")
                code, msg = self.ctrl.recv_reply()
                if code:
                    print(f"{code} {msg}")
            except OSError:
                pass
            self._disconnect()
            print("Disconnected.")
        self._quit_requested = True

    # ── Internal helpers ─────────────────────────────

    def _disconnect(self) -> None:
        if self.ctrl:
            try:
                self.ctrl.close()
            except OSError:
                pass
        self.ctrl = None
        self.connected = False
        self.logged_in = False


# ─────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────

if __name__ == "__main__":
    client = FTPClient()
    client.run()
