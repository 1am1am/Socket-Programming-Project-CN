"""
Multi-threaded Hybrid FTP Server.

TCP control channel  +  custom Reliable-UDP data channel.
One daemon thread per client; each session is fully isolated.
"""

from __future__ import annotations

import argparse
import os
import socket
import threading
import time
from pathlib import Path
from typing import Optional, Tuple

from rdt_udp import (
    RDTError,
    establish_udp,
    new_transfer_id,
    receive_bytes as rdt_receive_bytes,
    receive_file as rdt_receive_file,
    send_bytes as rdt_send_bytes,
    send_file as rdt_send_file,
    sha256_file,
    TransferProgress,
)
from utils import (
    COMMAND_HELP,
    ControlChannel,
    DEFAULT_CTRL_PORT,
    DEFAULT_HOST,
    R150,
    R200,
    R211,
    R213,
    R214,
    R220,
    R221,
    R226,
    R227,
    R230,
    R250,
    R257,
    R331,
    R350,
    R425,
    R426,
    R500,
    R501,
    R503,
    R530,
    R550,
    USERS,
    create_udp_socket,
    format_150,
    format_226,
    format_list_line,
    format_port_args,
    parse_port_args,
    safe_resolve,
    setup_logging,
    to_ftp_path,
)

log = setup_logging("ftp-server")

# Commands that do NOT require authentication
NO_AUTH_CMDS = {"USER", "PASS", "QUIT", "HELP", "NOOP"}


# ─────────────────────────────────────────────────────
#  FTP Server
# ─────────────────────────────────────────────────────

class FTPServer:
    """Accepts TCP connections and spawns one ClientSession thread per client."""

    def __init__(self, host: str, port: int, root: str) -> None:
        self.host = host
        self.port = port
        self.root = Path(root).resolve()
        if not self.root.is_dir():
            self.root.mkdir(parents=True, exist_ok=True)
            log.info("created server root: %s", self.root)

    def start(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.host, self.port))
        listener.listen(5)
        log.info(
            "Hybrid FTP Server listening on %s:%d  root=%s",
            self.host, self.port, self.root,
        )
        try:
            while True:
                conn, addr = listener.accept()
                log.info("new connection from %s:%d", *addr)
                t = threading.Thread(
                    target=self._handle_client,
                    args=(conn, addr),
                    name=f"client-{addr[0]}:{addr[1]}",
                    daemon=True,
                )
                t.start()
        except KeyboardInterrupt:
            log.info("server shutting down")
        finally:
            listener.close()

    def _handle_client(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        try:
            session = ClientSession(conn, self.host, self.root, addr)
            session.run()
        except Exception:
            log.exception("unhandled error for %s:%d", *addr)
        finally:
            try:
                conn.close()
            except OSError:
                pass
            log.info("connection closed: %s:%d", *addr)


# ─────────────────────────────────────────────────────
#  Per-Client Session
# ─────────────────────────────────────────────────────

class ClientSession:
    """
    Isolated per-client FTP session with its own working directory,
    authentication state, and data-channel configuration.
    """

    def __init__(
        self,
        conn: socket.socket,
        server_host: str,
        root: Path,
        client_addr: Tuple[str, int],
    ) -> None:
        self.ctrl = ControlChannel(conn)
        self.server_host = server_host
        self.root = root
        self.cwd = root
        self.client_addr = client_addr

        # auth state
        self.username: Optional[str] = None
        self.authenticated = False

        # transfer settings
        self.transfer_type = "I"       # I = binary, A = ASCII
        self.data_mode = "PASV"        # PASV or PORT
        self.port_addr: Optional[Tuple[str, int]] = None
        self.pasv_udp_sock: Optional[socket.socket] = None

        # rename state machine
        self.rename_from: Optional[Path] = None

        # abort signaling for in-progress UDP transfers
        self.abort_event = threading.Event()

        self.running = True

    # ── Main command loop ────────────────────────────

    def run(self) -> None:
        self.ctrl.send_reply(R220, "Hybrid FTP Server ready.")
        while self.running:
            line = self.ctrl.recv_line()
            if line is None:
                break
            log.info("[%s:%d] >>> %s", *self.client_addr, line)
            self._dispatch(line)

    def _dispatch(self, line: str) -> None:
        parts = line.split(None, 1)
        if not parts:
            return
        cmd = parts[0].upper()
        args = parts[1].strip() if len(parts) > 1 else ""

        if not self.authenticated and cmd not in NO_AUTH_CMDS:
            self.ctrl.send_reply(R530, "Not logged in.")
            return

        handler = getattr(self, f"cmd_{cmd}", None)
        if handler is None:
            self.ctrl.send_reply(R500, f"Unknown command: {cmd}")
            return

        try:
            handler(args)
        except Exception:
            log.exception("error in cmd_%s", cmd)
            try:
                self.ctrl.send_reply(R451, "Local error in processing.")
            except OSError:
                self.running = False

        # Clear rename state after every command except RNFR
        if cmd != "RNFR":
            self.rename_from = None

    # ── Authentication ───────────────────────────────

    def cmd_USER(self, args: str) -> None:
        if self.authenticated:
            self.ctrl.send_reply(R230, "Already logged in.")
            return
        if not args:
            self.ctrl.send_reply(R501, "USER requires a username.")
            return

        self.username = args
        self.authenticated = False

        if args not in USERS:
            self.ctrl.send_reply(R530, "User unknown.")
            self.username = None
            return

        if args == "anonymous":
            self.ctrl.send_reply(R331, "Anonymous login, send email as password.")
        else:
            self.ctrl.send_reply(R331, f"Password required for {args}.")

    def cmd_PASS(self, args: str) -> None:
        if self.authenticated:
            self.ctrl.send_reply(R230, "Already logged in.")
            return
        if self.username is None:
            self.ctrl.send_reply(R503, "Login with USER first.")
            return

        expected = USERS.get(self.username, None)
        if expected is None:
            self.ctrl.send_reply(R530, "Login incorrect.")
            self.username = None
            return

        # anonymous accepts any password
        if expected != "" and args != expected:
            self.ctrl.send_reply(R530, "Login incorrect.")
            self.username = None
            return

        self.authenticated = True
        log.info("[%s:%d] user '%s' logged in", *self.client_addr, self.username)
        self.ctrl.send_reply(R230, "Login successful.")

    # ── Directory navigation ─────────────────────────

    def cmd_PWD(self, _args: str) -> None:
        ftp = to_ftp_path(self.root, self.cwd)
        self.ctrl.send_reply(R257, f'"{ftp}" is the current directory.')

    def cmd_CWD(self, args: str) -> None:
        try:
            target = safe_resolve(self.root, self.cwd, args if args else "/")
        except ValueError as e:
            self.ctrl.send_reply(R550, str(e))
            return
        if not target.is_dir():
            self.ctrl.send_reply(R550, "Not a directory.")
            return
        self.cwd = target
        ftp = to_ftp_path(self.root, self.cwd)
        self.ctrl.send_reply(R250, f"Directory changed to {ftp}.")

    def cmd_CDUP(self, _args: str) -> None:
        self.cmd_CWD("..")

    def cmd_MKD(self, args: str) -> None:
        if not args:
            self.ctrl.send_reply(R501, "MKD requires a directory name.")
            return
        try:
            target = safe_resolve(self.root, self.cwd, args)
        except ValueError as e:
            self.ctrl.send_reply(R550, str(e))
            return
        try:
            target.mkdir(parents=False, exist_ok=False)
        except FileExistsError:
            self.ctrl.send_reply(R550, "Directory already exists.")
            return
        except OSError as e:
            self.ctrl.send_reply(R550, str(e))
            return
        ftp = to_ftp_path(self.root, target)
        self.ctrl.send_reply(R257, f'"{ftp}" created.')

    def cmd_RMD(self, args: str) -> None:
        if not args:
            self.ctrl.send_reply(R501, "RMD requires a directory name.")
            return
        try:
            target = safe_resolve(self.root, self.cwd, args)
        except ValueError as e:
            self.ctrl.send_reply(R550, str(e))
            return
        if not target.is_dir():
            self.ctrl.send_reply(R550, "Not a directory.")
            return
        if target == self.root:
            self.ctrl.send_reply(R550, "Cannot remove root directory.")
            return
        try:
            target.rmdir()
        except OSError as e:
            self.ctrl.send_reply(R550, f"Cannot remove directory: {e}")
            return
        self.ctrl.send_reply(R250, "Directory removed.")

    # ── File info (no data channel) ──────────────────

    def cmd_SIZE(self, args: str) -> None:
        if not args:
            self.ctrl.send_reply(R501, "SIZE requires a filename.")
            return
        try:
            target = safe_resolve(self.root, self.cwd, args)
        except ValueError as e:
            self.ctrl.send_reply(R550, str(e))
            return
        if not target.is_file():
            self.ctrl.send_reply(R550, "Not a regular file.")
            return
        self.ctrl.send_reply(R213, str(target.stat().st_size))

    def cmd_MDTM(self, args: str) -> None:
        if not args:
            self.ctrl.send_reply(R501, "MDTM requires a filename.")
            return
        try:
            target = safe_resolve(self.root, self.cwd, args)
        except ValueError as e:
            self.ctrl.send_reply(R550, str(e))
            return
        if not target.is_file():
            self.ctrl.send_reply(R550, "Not a regular file.")
            return
        mtime = time.gmtime(target.stat().st_mtime)
        self.ctrl.send_reply(R213, time.strftime("%Y%m%d%H%M%S", mtime))

    def cmd_STAT(self, args: str) -> None:
        if not args:
            ftp = to_ftp_path(self.root, self.cwd)
            info = (
                f"Connected to {self.client_addr[0]}:{self.client_addr[1]} "
                f"User={self.username} Type={self.transfer_type} "
                f"Mode={self.data_mode} CWD={ftp}"
            )
            self.ctrl.send_reply(R211, info)
            return
        try:
            target = safe_resolve(self.root, self.cwd, args)
        except ValueError as e:
            self.ctrl.send_reply(R550, str(e))
            return
        if not target.exists():
            self.ctrl.send_reply(R550, "Path not found.")
            return
        if target.is_file():
            st = target.stat()
            info = f"{target.name}: size={st.st_size} mtime={time.ctime(st.st_mtime)}"
            self.ctrl.send_reply(R213, info)
        elif target.is_dir():
            lines = [format_list_line(e) for e in sorted(target.iterdir())]
            self.ctrl.send_reply(R211, "\r\n".join(lines) if lines else "(empty)")

    def cmd_HASH(self, args: str) -> None:
        if not args:
            self.ctrl.send_reply(R501, "HASH requires a filename.")
            return
        try:
            target = safe_resolve(self.root, self.cwd, args)
        except ValueError as e:
            self.ctrl.send_reply(R550, str(e))
            return
        if not target.is_file():
            self.ctrl.send_reply(R550, "Not a regular file.")
            return
        try:
            size, digest = sha256_file(target)
        except OSError as e:
            self.ctrl.send_reply(R550, str(e))
            return
        self.ctrl.send_reply(R213, f"SHA-256 {digest.hex()} {size}")

    # ── Data connection modes ────────────────────────

    def cmd_PORT(self, args: str) -> None:
        if not args:
            self.ctrl.send_reply(R501, "PORT requires h1,h2,h3,h4,p1,p2.")
            return
        try:
            host, port = parse_port_args(args)
        except ValueError as e:
            self.ctrl.send_reply(R501, str(e))
            return
        self._close_pasv_sock()
        self.port_addr = (host, port)
        self.data_mode = "PORT"
        log.info("[%s:%d] PORT -> %s:%d", *self.client_addr, host, port)
        self.ctrl.send_reply(R200, "PORT command successful.")

    def cmd_PASV(self, _args: str) -> None:
        self._close_pasv_sock()
        try:
            self.pasv_udp_sock = create_udp_socket(self.server_host, 0)
            bound_port = self.pasv_udp_sock.getsockname()[1]
        except OSError as e:
            self.ctrl.send_reply(R425, f"Cannot open passive port: {e}")
            return
        self.data_mode = "PASV"
        self.port_addr = None
        pa = format_port_args(self.server_host, bound_port)
        log.info("[%s:%d] PASV -> UDP port %d", *self.client_addr, bound_port)
        self.ctrl.send_reply(R227, f"Entering Passive Mode ({pa}).")

    def cmd_TYPE(self, args: str) -> None:
        t = args.upper().strip()
        if t in ("A", "I"):
            self.transfer_type = t
            label = "ASCII" if t == "A" else "Binary"
            self.ctrl.send_reply(R200, f"Type set to {label}.")
        else:
            self.ctrl.send_reply(R501, "TYPE must be A or I.")

    def cmd_MODE(self, args: str) -> None:
        m = args.upper().strip()
        if m == "S":
            self.ctrl.send_reply(R200, "Mode set to Stream.")
        else:
            self.ctrl.send_reply(R501, "Only Stream mode (S) is supported.")

    # ── Data transfer commands ───────────────────────

    def cmd_LIST(self, args: str) -> None:
        try:
            target = safe_resolve(self.root, self.cwd, args) if args else self.cwd
        except ValueError as e:
            self.ctrl.send_reply(R550, str(e))
            return
        if not target.is_dir():
            self.ctrl.send_reply(R550, "Not a directory.")
            return
        lines = []
        for entry in sorted(target.iterdir()):
            line = format_list_line(entry)
            if line:
                lines.append(line)
        data = ("\r\n".join(lines) + "\r\n").encode("utf-8") if lines else b""
        self._do_send_data(data)

    def cmd_NLST(self, args: str) -> None:
        try:
            target = safe_resolve(self.root, self.cwd, args) if args else self.cwd
        except ValueError as e:
            self.ctrl.send_reply(R550, str(e))
            return
        if not target.is_dir():
            self.ctrl.send_reply(R550, "Not a directory.")
            return
        names = [e.name for e in sorted(target.iterdir())]
        data = ("\r\n".join(names) + "\r\n").encode("utf-8") if names else b""
        self._do_send_data(data)

    def cmd_RETR(self, args: str) -> None:
        if not args:
            self.ctrl.send_reply(R501, "RETR requires a filename.")
            return
        try:
            target = safe_resolve(self.root, self.cwd, args)
        except ValueError as e:
            self.ctrl.send_reply(R550, str(e))
            return
        if not target.is_file():
            self.ctrl.send_reply(R550, "File not found.")
            return
        self._do_send_file(target)

    def cmd_STOR(self, args: str) -> None:
        if not args:
            self.ctrl.send_reply(R501, "STOR requires a filename.")
            return
        try:
            target = safe_resolve(self.root, self.cwd, args)
        except ValueError as e:
            self.ctrl.send_reply(R550, str(e))
            return
        self._do_receive_file(target)

    def cmd_STOU(self, _args: str) -> None:
        # Generate a unique filename in the current directory
        base = "upload"
        ext = ".dat"
        counter = 0
        while True:
            name = f"{base}_{counter:04d}{ext}" if counter else f"{base}{ext}"
            target = self.cwd / name
            if not target.exists():
                break
            counter += 1
        self._do_receive_file(target, stou_name=target.name)

    def cmd_APPE(self, args: str) -> None:
        if not args:
            self.ctrl.send_reply(R501, "APPE requires a filename.")
            return
        try:
            target = safe_resolve(self.root, self.cwd, args)
        except ValueError as e:
            self.ctrl.send_reply(R550, str(e))
            return
        self._do_receive_file(target, append=True)

    # ── File management ──────────────────────────────

    def cmd_DELE(self, args: str) -> None:
        if not args:
            self.ctrl.send_reply(R501, "DELE requires a filename.")
            return
        try:
            target = safe_resolve(self.root, self.cwd, args)
        except ValueError as e:
            self.ctrl.send_reply(R550, str(e))
            return
        if not target.is_file():
            self.ctrl.send_reply(R550, "File not found.")
            return
        try:
            target.unlink()
        except OSError as e:
            self.ctrl.send_reply(R550, str(e))
            return
        self.ctrl.send_reply(R250, "File deleted.")

    def cmd_RNFR(self, args: str) -> None:
        if not args:
            self.ctrl.send_reply(R501, "RNFR requires a path.")
            return
        try:
            target = safe_resolve(self.root, self.cwd, args)
        except ValueError as e:
            self.ctrl.send_reply(R550, str(e))
            return
        if not target.exists():
            self.ctrl.send_reply(R550, "Path not found.")
            return
        self.rename_from = target
        self.ctrl.send_reply(R350, "Ready for RNTO.")

    def cmd_RNTO(self, args: str) -> None:
        if self.rename_from is None:
            self.ctrl.send_reply(R503, "RNFR required before RNTO.")
            return
        if not args:
            self.ctrl.send_reply(R501, "RNTO requires a new name.")
            return
        try:
            target = safe_resolve(self.root, self.cwd, args)
        except ValueError as e:
            self.ctrl.send_reply(R550, str(e))
            return
        try:
            os.rename(self.rename_from, target)
        except OSError as e:
            self.ctrl.send_reply(R550, f"Rename failed: {e}")
            return
        self.ctrl.send_reply(R250, "Rename successful.")
        self.rename_from = None

    # ── Miscellaneous ────────────────────────────────

    def cmd_NOOP(self, _args: str) -> None:
        self.ctrl.send_reply(R200, "OK.")

    def cmd_QUIT(self, _args: str) -> None:
        self.ctrl.send_reply(R221, "Goodbye.")
        self.running = False

    def cmd_ABOR(self, _args: str) -> None:
        self.abort_event.set()
        self.ctrl.send_reply(R226, "ABOR command successful.")
        # Reset for the next transfer
        self.abort_event = threading.Event()

    def cmd_HELP(self, args: str) -> None:
        if args:
            key = args.upper().strip()
            text = COMMAND_HELP.get(key, f"No help available for {key}.")
            self.ctrl.send_reply(R214, text)
        else:
            cmds = " ".join(sorted(COMMAND_HELP.keys()))
            self.ctrl.send_reply(R214, f"Available commands: {cmds}")

    # ── Data transfer helpers ────────────────────────

    def _open_data_channel(self) -> Optional[Tuple[socket.socket, bool]]:
        """
        Prepare UDP socket for a data transfer.
        Returns (udp_sock, server_is_initiator) or None on failure.

        PASV: server already has a bound socket, server is RESPONDER
        PORT: server creates a new socket, server is INITIATOR
        """
        if self.data_mode == "PASV":
            if self.pasv_udp_sock is None:
                self.ctrl.send_reply(R425, "Use PASV first.")
                return None
            return self.pasv_udp_sock, False

        elif self.data_mode == "PORT":
            if self.port_addr is None:
                self.ctrl.send_reply(R425, "Use PORT first.")
                return None
            try:
                sock = create_udp_socket(self.server_host, 0)
            except OSError as e:
                self.ctrl.send_reply(R425, f"Cannot create data socket: {e}")
                return None
            return sock, True

        self.ctrl.send_reply(R425, "No data connection mode set.")
        return None

    def _cleanup_data_channel(self, sock: socket.socket) -> None:
        """Close and clear the UDP socket after a transfer."""
        try:
            sock.close()
        except OSError:
            pass
        if sock is self.pasv_udp_sock:
            self.pasv_udp_sock = None

    def _do_send_data(self, data: bytes) -> None:
        """Send arbitrary bytes (LIST/NLST output) over the data channel."""
        channel = self._open_data_channel()
        if channel is None:
            return
        udp_sock, is_initiator = channel
        tid = new_transfer_id()
        self.ctrl.send_reply(R150, format_150(tid))

        try:
            if is_initiator:
                session = establish_udp(
                    udp_sock, tid, initiator=True, peer=self.port_addr,
                    abort_event=self.abort_event,
                )
            else:
                session = establish_udp(
                    udp_sock, tid, initiator=False,
                    expected_peer=(self.client_addr[0], 0),
                    abort_event=self.abort_event,
                )
            result = rdt_send_bytes(session, data, abort_event=self.abort_event)
            self.ctrl.send_reply(R226, format_226(result.sha256, result.bytes_transferred))
        except RDTError as e:
            log.error("data transfer failed: %s", e)
            self.ctrl.send_reply(R426, f"Transfer aborted: {e}")
        finally:
            self._cleanup_data_channel(udp_sock)

    def _do_send_file(self, path: Path) -> None:
        """Send a file over the data channel (RETR)."""
        channel = self._open_data_channel()
        if channel is None:
            return
        udp_sock, is_initiator = channel
        tid = new_transfer_id()
        self.ctrl.send_reply(R150, format_150(tid))

        try:
            if is_initiator:
                session = establish_udp(
                    udp_sock, tid, initiator=True, peer=self.port_addr,
                    abort_event=self.abort_event,
                )
            else:
                session = establish_udp(
                    udp_sock, tid, initiator=False,
                    expected_peer=(self.client_addr[0], 0),
                    abort_event=self.abort_event,
                )
            result = rdt_send_file(session, path, abort_event=self.abort_event)
            log.info(
                "RETR %s -> %d bytes, SHA256=%s, %.1fs",
                path.name, result.bytes_transferred, result.sha256, result.duration,
            )
            self.ctrl.send_reply(R226, format_226(result.sha256, result.bytes_transferred))
        except RDTError as e:
            log.error("RETR failed: %s", e)
            self.ctrl.send_reply(R426, f"Transfer aborted: {e}")
        finally:
            self._cleanup_data_channel(udp_sock)

    def _do_receive_file(
        self,
        path: Path,
        append: bool = False,
        stou_name: Optional[str] = None,
    ) -> None:
        """Receive a file over the data channel (STOR/STOU/APPE)."""
        channel = self._open_data_channel()
        if channel is None:
            return
        udp_sock, is_initiator = channel
        tid = new_transfer_id()

        msg = format_150(tid)
        if stou_name:
            msg += f" FILE={stou_name}"
        self.ctrl.send_reply(R150, msg)

        try:
            if is_initiator:
                session = establish_udp(
                    udp_sock, tid, initiator=True, peer=self.port_addr,
                    abort_event=self.abort_event,
                )
            else:
                session = establish_udp(
                    udp_sock, tid, initiator=False,
                    expected_peer=(self.client_addr[0], 0),
                    abort_event=self.abort_event,
                )

            if append and path.is_file():
                # APPE: receive into memory then append to existing file
                data, result = rdt_receive_bytes(session, abort_event=self.abort_event)
                with open(path, "ab") as f:
                    f.write(data)
            else:
                result = rdt_receive_file(
                    session, path, overwrite=True, abort_event=self.abort_event,
                )

            log.info(
                "STOR/APPE %s <- %d bytes, SHA256=%s, %.1fs",
                path.name, result.bytes_transferred, result.sha256, result.duration,
            )
            self.ctrl.send_reply(R226, format_226(result.sha256, result.bytes_transferred))
        except RDTError as e:
            log.error("STOR/APPE failed: %s", e)
            self.ctrl.send_reply(R426, f"Transfer aborted: {e}")
        finally:
            self._cleanup_data_channel(udp_sock)

    def _close_pasv_sock(self) -> None:
        if self.pasv_udp_sock is not None:
            try:
                self.pasv_udp_sock.close()
            except OSError:
                pass
            self.pasv_udp_sock = None


# ─────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hybrid FTP Server")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Bind address")
    parser.add_argument("--port", type=int, default=DEFAULT_CTRL_PORT, help="TCP control port")
    parser.add_argument("--root", default="./ftp_root", help="Server root directory")
    args = parser.parse_args()
    server = FTPServer(args.host, args.port, args.root)
    server.start()
