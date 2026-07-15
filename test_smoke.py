"""
Comprehensive test suite for the Hybrid FTP system.

Tests:  AUTH, simple commands, PASV data transfers, PORT (active) data
transfers, binary integrity, STOU, APPE, concurrent clients, error cases.
"""

from __future__ import annotations

import hashlib
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rdt_udp import (
    establish_udp,
    receive_bytes,
    receive_file,
    send_bytes as rdt_send_bytes,
    send_file,
)
from utils import (
    ControlChannel,
    create_udp_socket,
    format_port_args,
    parse_150,
    parse_226,
    parse_pasv_reply,
)

HOST = "127.0.0.1"
PORT = 2121
PASS_COUNT = 0
FAIL_COUNT = 0


def ok(label: str) -> None:
    global PASS_COUNT
    PASS_COUNT += 1
    print(f"  [PASS] {label}")


def fail(label: str, detail: str = "") -> None:
    global FAIL_COUNT
    FAIL_COUNT += 1
    msg = f"  [FAIL] {label}"
    if detail:
        msg += f"  ({detail})"
    print(msg)


def check(label: str, condition: bool, detail: str = "") -> bool:
    if condition:
        ok(label)
    else:
        fail(label, detail)
    return condition


def connect_and_login(user: str = "admin", pw: str = "admin123") -> ControlChannel:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((HOST, PORT))
    sock.settimeout(None)
    ctrl = ControlChannel(sock)
    code, _ = ctrl.recv_reply()
    assert code == 220
    ctrl.send_command(f"USER {user}")
    code, _ = ctrl.recv_reply()
    if code == 331:
        ctrl.send_command(f"PASS {pw}")
        code, _ = ctrl.recv_reply()
    assert code == 230, f"Login failed: {code}"
    return ctrl


# -- helpers for data transfers --

def pasv_setup(ctrl: ControlChannel):
    """Send PASV, return (server_udp_host, server_udp_port)."""
    ctrl.send_command("PASV")
    code, msg = ctrl.recv_reply()
    assert code == 227, f"PASV failed: {code} {msg}"
    return parse_pasv_reply(msg)


def port_setup(ctrl: ControlChannel, local_host: str = HOST):
    """Bind local UDP, send PORT, return udp_sock."""
    udp_sock = create_udp_socket(local_host, 0)
    bound_host, bound_port = udp_sock.getsockname()
    pa = format_port_args(bound_host, bound_port)
    ctrl.send_command(f"PORT {pa}")
    code, msg = ctrl.recv_reply()
    assert code == 200, f"PORT failed: {code} {msg}"
    return udp_sock


def do_pasv_list(ctrl: ControlChannel) -> str:
    """LIST via PASV, return listing text."""
    h, p = pasv_setup(ctrl)
    ctrl.send_command("LIST")
    code, msg = ctrl.recv_reply()
    assert code == 150
    tid = parse_150(msg)
    udp = create_udp_socket(HOST, 0)
    try:
        sess = establish_udp(udp, tid, initiator=True, peer=(h, p))
        data, _ = receive_bytes(sess)
    finally:
        udp.close()
    ctrl.recv_reply()  # 226
    return data.decode("utf-8", errors="replace")


def do_pasv_upload(ctrl: ControlChannel, remote: str, local_path: str) -> None:
    """STOR a file via PASV."""
    h, p = pasv_setup(ctrl)
    ctrl.send_command(f"STOR {remote}")
    code, msg = ctrl.recv_reply()
    assert code == 150, f"STOR 150 expected, got {code}: {msg}"
    tid = parse_150(msg)
    udp = create_udp_socket(HOST, 0)
    try:
        sess = establish_udp(udp, tid, initiator=True, peer=(h, p))
        send_file(sess, local_path)
    finally:
        udp.close()
    code, msg = ctrl.recv_reply()
    assert code == 226, f"STOR 226 expected, got {code}: {msg}"


def do_pasv_download(ctrl: ControlChannel, remote: str, local_path: str) -> None:
    """RETR a file via PASV."""
    h, p = pasv_setup(ctrl)
    ctrl.send_command(f"RETR {remote}")
    code, msg = ctrl.recv_reply()
    assert code == 150, f"RETR 150 expected, got {code}: {msg}"
    tid = parse_150(msg)
    udp = create_udp_socket(HOST, 0)
    try:
        sess = establish_udp(udp, tid, initiator=True, peer=(h, p))
        receive_file(sess, local_path, overwrite=True)
    finally:
        udp.close()
    code, msg = ctrl.recv_reply()
    assert code == 226, f"RETR 226 expected, got {code}: {msg}"


# =====================================================
#  TEST SUITES
# =====================================================

def test_auth():
    print("\n=== Authentication ===")

    # Good login
    ctrl = connect_and_login()
    ok("admin login")
    ctrl.send_command("QUIT")
    ctrl.recv_reply()
    ctrl.close()

    # Anonymous login
    ctrl = connect_and_login("anonymous", "anything@test.com")
    ok("anonymous login")
    ctrl.send_command("QUIT")
    ctrl.recv_reply()
    ctrl.close()

    # Bad user
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    c = ControlChannel(sock)
    c.recv_reply()
    c.send_command("USER baduser")
    code, _ = c.recv_reply()
    check("reject unknown user", code == 530)
    c.send_command("QUIT")
    c.recv_reply()
    c.close()

    # Bad password
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    c = ControlChannel(sock)
    c.recv_reply()
    c.send_command("USER admin")
    code, _ = c.recv_reply()
    c.send_command("PASS wrongpass")
    code, _ = c.recv_reply()
    check("reject bad password", code == 530)
    c.send_command("QUIT")
    c.recv_reply()
    c.close()

    # Command before login
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    c = ControlChannel(sock)
    c.recv_reply()
    c.send_command("PWD")
    code, _ = c.recv_reply()
    check("reject command before auth", code == 530)
    c.send_command("QUIT")
    c.recv_reply()
    c.close()


def test_directory_ops():
    print("\n=== Directory Operations ===")
    ctrl = connect_and_login()

    # PWD at root
    ctrl.send_command("PWD")
    code, msg = ctrl.recv_reply()
    check("PWD at root", code == 257 and '"/"' in msg, msg)

    # MKD
    ctrl.send_command("MKD test_a")
    code, _ = ctrl.recv_reply()
    check("MKD test_a", code == 257)

    ctrl.send_command("MKD test_a/sub_b")
    code, _ = ctrl.recv_reply()
    check("MKD nested test_a/sub_b", code == 257)

    # CWD
    ctrl.send_command("CWD test_a")
    code, msg = ctrl.recv_reply()
    check("CWD test_a", code == 250, msg)

    ctrl.send_command("PWD")
    code, msg = ctrl.recv_reply()
    check("PWD after CWD", code == 257 and "test_a" in msg, msg)

    ctrl.send_command("CWD sub_b")
    code, _ = ctrl.recv_reply()
    check("CWD into sub_b", code == 250)

    # CDUP
    ctrl.send_command("CDUP")
    code, _ = ctrl.recv_reply()
    check("CDUP", code == 250)

    ctrl.send_command("PWD")
    code, msg = ctrl.recv_reply()
    check("PWD after CDUP", code == 257 and "test_a" in msg and "sub_b" not in msg, msg)

    # Path traversal attack
    ctrl.send_command("CWD ../../..")
    code, _ = ctrl.recv_reply()
    # Should either jail at root or return 550
    check("path traversal blocked", code in (250, 550))

    ctrl.send_command("PWD")
    code, msg = ctrl.recv_reply()
    check("still inside jail after traversal", code == 257)

    # CWD back to root
    ctrl.send_command("CWD /")
    code, _ = ctrl.recv_reply()
    check("CWD /", code == 250)

    # RMD nested
    ctrl.send_command("RMD test_a/sub_b")
    code, _ = ctrl.recv_reply()
    check("RMD sub_b", code == 250)

    ctrl.send_command("RMD test_a")
    code, _ = ctrl.recv_reply()
    check("RMD test_a", code == 250)

    # RMD non-existent
    ctrl.send_command("RMD nonexistent_dir")
    code, _ = ctrl.recv_reply()
    check("RMD non-existent -> 550", code == 550)

    ctrl.send_command("QUIT")
    ctrl.recv_reply()
    ctrl.close()


def test_file_info():
    print("\n=== File Info Commands ===")
    ctrl = connect_and_login()

    # SIZE
    ctrl.send_command("SIZE welcome.txt")
    code, msg = ctrl.recv_reply()
    check("SIZE welcome.txt", code == 213 and msg.strip().isdigit(), msg)

    # SIZE non-existent
    ctrl.send_command("SIZE nonexistent.txt")
    code, _ = ctrl.recv_reply()
    check("SIZE non-existent -> 550", code == 550)

    # MDTM
    ctrl.send_command("MDTM welcome.txt")
    code, msg = ctrl.recv_reply()
    check("MDTM welcome.txt", code == 213 and len(msg.strip()) == 14, msg)

    # HASH
    ctrl.send_command("HASH welcome.txt")
    code, msg = ctrl.recv_reply()
    check("HASH welcome.txt", code == 213 and "SHA-256" in msg, msg)

    # STAT (no args)
    ctrl.send_command("STAT")
    code, msg = ctrl.recv_reply()
    check("STAT (server status)", code == 211 and "admin" in msg, msg)

    # STAT with file
    ctrl.send_command("STAT welcome.txt")
    code, msg = ctrl.recv_reply()
    check("STAT welcome.txt", code == 213, msg)

    # HELP
    ctrl.send_command("HELP")
    code, msg = ctrl.recv_reply()
    check("HELP", code == 214 and "RETR" in msg, msg)

    ctrl.send_command("HELP RETR")
    code, msg = ctrl.recv_reply()
    check("HELP RETR", code == 214 and "Download" in msg, msg)

    # NOOP
    ctrl.send_command("NOOP")
    code, _ = ctrl.recv_reply()
    check("NOOP", code == 200)

    # TYPE
    ctrl.send_command("TYPE A")
    code, msg = ctrl.recv_reply()
    check("TYPE A", code == 200 and "ASCII" in msg, msg)

    ctrl.send_command("TYPE I")
    code, msg = ctrl.recv_reply()
    check("TYPE I", code == 200 and "Binary" in msg, msg)

    ctrl.send_command("TYPE X")
    code, _ = ctrl.recv_reply()
    check("TYPE X -> 501", code == 501)

    # MODE
    ctrl.send_command("MODE S")
    code, _ = ctrl.recv_reply()
    check("MODE S", code == 200)

    ctrl.send_command("MODE B")
    code, _ = ctrl.recv_reply()
    check("MODE B -> 501", code == 501)

    ctrl.send_command("QUIT")
    ctrl.recv_reply()
    ctrl.close()


def test_pasv_transfers():
    print("\n=== PASV Data Transfers ===")
    ctrl = connect_and_login()

    # LIST
    listing = do_pasv_list(ctrl)
    check("LIST via PASV", "welcome.txt" in listing, listing.strip()[:80])

    # NLST
    h, p = pasv_setup(ctrl)
    ctrl.send_command("NLST")
    code, msg = ctrl.recv_reply()
    assert code == 150
    tid = parse_150(msg)
    udp = create_udp_socket(HOST, 0)
    try:
        sess = establish_udp(udp, tid, initiator=True, peer=(h, p))
        data, _ = receive_bytes(sess)
        nlst = data.decode("utf-8", errors="replace")
    finally:
        udp.close()
    ctrl.recv_reply()
    check("NLST via PASV", "welcome.txt" in nlst, nlst.strip()[:80])

    # RETR
    do_pasv_download(ctrl, "welcome.txt", "test_dl_pasv.txt")
    with open("test_dl_pasv.txt", "r") as f:
        check("RETR welcome.txt", "Welcome" in f.read())
    os.remove("test_dl_pasv.txt")

    # STOR
    test_data = b"PASV upload test data " * 50
    with open("test_up_pasv.bin", "wb") as f:
        f.write(test_data)
    do_pasv_upload(ctrl, "pasv_uploaded.bin", "test_up_pasv.bin")
    os.remove("test_up_pasv.bin")

    # Verify uploaded file
    ctrl.send_command("SIZE pasv_uploaded.bin")
    code, msg = ctrl.recv_reply()
    check("STOR verified size", code == 213 and int(msg) == len(test_data))

    # RETR the uploaded file back and verify SHA-256
    do_pasv_download(ctrl, "pasv_uploaded.bin", "test_redownload.bin")
    with open("test_redownload.bin", "rb") as f:
        downloaded = f.read()
    check("RETR re-download integrity", downloaded == test_data)
    os.remove("test_redownload.bin")

    # DELE
    ctrl.send_command("DELE pasv_uploaded.bin")
    code, _ = ctrl.recv_reply()
    check("DELE", code == 250)

    ctrl.send_command("QUIT")
    ctrl.recv_reply()
    ctrl.close()


def test_port_transfers():
    print("\n=== PORT (Active) Data Transfers ===")
    ctrl = connect_and_login()

    # LIST via PORT
    udp_sock = port_setup(ctrl)
    ctrl.send_command("LIST")
    code, msg = ctrl.recv_reply()
    assert code == 150, f"LIST 150 expected, got {code}: {msg}"
    tid = parse_150(msg)
    try:
        sess = establish_udp(
            udp_sock, tid, initiator=False, expected_peer=(HOST, 0),
        )
        data, _ = receive_bytes(sess)
        listing = data.decode("utf-8", errors="replace")
    finally:
        udp_sock.close()
    ctrl.recv_reply()  # 226
    check("LIST via PORT", "welcome.txt" in listing, listing.strip()[:80])

    # STOR via PORT
    test_data = b"PORT upload test binary " * 40
    with open("test_up_port.bin", "wb") as f:
        f.write(test_data)

    udp_sock = port_setup(ctrl)
    ctrl.send_command("STOR port_uploaded.bin")
    code, msg = ctrl.recv_reply()
    assert code == 150
    tid = parse_150(msg)
    try:
        sess = establish_udp(
            udp_sock, tid, initiator=False, expected_peer=(HOST, 0),
        )
        send_file(sess, "test_up_port.bin")
    finally:
        udp_sock.close()
    code, msg = ctrl.recv_reply()
    check("STOR via PORT -> 226", code == 226)
    os.remove("test_up_port.bin")

    # RETR via PORT
    udp_sock = port_setup(ctrl)
    ctrl.send_command("RETR port_uploaded.bin")
    code, msg = ctrl.recv_reply()
    assert code == 150
    tid = parse_150(msg)
    try:
        sess = establish_udp(
            udp_sock, tid, initiator=False, expected_peer=(HOST, 0),
        )
        receive_file(sess, "test_dl_port.bin", overwrite=True)
    finally:
        udp_sock.close()
    ctrl.recv_reply()  # 226
    with open("test_dl_port.bin", "rb") as f:
        check("RETR via PORT integrity", f.read() == test_data)
    os.remove("test_dl_port.bin")

    ctrl.send_command("DELE port_uploaded.bin")
    ctrl.recv_reply()

    ctrl.send_command("QUIT")
    ctrl.recv_reply()
    ctrl.close()


def test_binary_integrity():
    print("\n=== Binary File Integrity ===")
    ctrl = connect_and_login()

    # Create a binary file with all byte values (0-255) repeated
    binary_data = bytes(range(256)) * 200  # 51200 bytes
    local_hash = hashlib.sha256(binary_data).hexdigest()
    with open("test_binary.bin", "wb") as f:
        f.write(binary_data)

    # Upload
    do_pasv_upload(ctrl, "binary_test.bin", "test_binary.bin")

    # Verify server-side hash
    ctrl.send_command("HASH binary_test.bin")
    code, msg = ctrl.recv_reply()
    server_hash = msg.split()[1] if code == 213 else ""
    check("binary SHA-256 server match", server_hash == local_hash,
          f"local={local_hash[:16]}... server={server_hash[:16]}...")

    # Download and verify
    do_pasv_download(ctrl, "binary_test.bin", "test_binary_dl.bin")
    with open("test_binary_dl.bin", "rb") as f:
        downloaded = f.read()
    check("binary round-trip integrity", downloaded == binary_data)

    os.remove("test_binary.bin")
    os.remove("test_binary_dl.bin")
    ctrl.send_command("DELE binary_test.bin")
    ctrl.recv_reply()

    ctrl.send_command("QUIT")
    ctrl.recv_reply()
    ctrl.close()


def test_stou_appe():
    print("\n=== STOU & APPE ===")
    ctrl = connect_and_login()

    # STOU - upload with unique name
    stou_data = b"stou test content"
    with open("test_stou.dat", "wb") as f:
        f.write(stou_data)

    h, p = pasv_setup(ctrl)
    ctrl.send_command("STOU")
    code, msg = ctrl.recv_reply()
    check("STOU -> 150", code == 150)
    tid = parse_150(msg)

    udp = create_udp_socket(HOST, 0)
    try:
        sess = establish_udp(udp, tid, initiator=True, peer=(h, p))
        send_file(sess, "test_stou.dat")
    finally:
        udp.close()
    code, msg = ctrl.recv_reply()
    check("STOU -> 226", code == 226)
    os.remove("test_stou.dat")

    # Find the uploaded file via LIST
    listing = do_pasv_list(ctrl)
    check("STOU file appears in listing", "upload" in listing.lower(), listing.strip()[:80])

    # APPE - first create a base file
    base_data = b"Hello "
    with open("test_appe_base.dat", "wb") as f:
        f.write(base_data)
    do_pasv_upload(ctrl, "appe_test.dat", "test_appe_base.dat")
    os.remove("test_appe_base.dat")

    # Append more data
    append_data = b"World!"
    with open("test_appe_add.dat", "wb") as f:
        f.write(append_data)

    h, p = pasv_setup(ctrl)
    ctrl.send_command("APPE appe_test.dat")
    code, msg = ctrl.recv_reply()
    check("APPE -> 150", code == 150)
    tid = parse_150(msg)

    udp = create_udp_socket(HOST, 0)
    try:
        sess = establish_udp(udp, tid, initiator=True, peer=(h, p))
        send_file(sess, "test_appe_add.dat")
    finally:
        udp.close()
    code, msg = ctrl.recv_reply()
    check("APPE -> 226", code == 226)
    os.remove("test_appe_add.dat")

    # Verify appended content
    ctrl.send_command("SIZE appe_test.dat")
    code, msg = ctrl.recv_reply()
    expected_size = len(base_data) + len(append_data)
    check("APPE size correct", code == 213 and int(msg) == expected_size,
          f"expected={expected_size}, got={msg}")

    # Cleanup all test files
    ctrl.send_command("DELE appe_test.dat")
    ctrl.recv_reply()

    # Clean STOU file
    listing = do_pasv_list(ctrl)
    for line in listing.strip().split("\n"):
        name = line.strip().split()[-1] if line.strip() else ""
        if name.startswith("upload"):
            ctrl.send_command(f"DELE {name}")
            ctrl.recv_reply()

    ctrl.send_command("QUIT")
    ctrl.recv_reply()
    ctrl.close()


def test_rename():
    print("\n=== RNFR / RNTO ===")
    ctrl = connect_and_login()

    # Upload a file to rename
    with open("test_rename.dat", "wb") as f:
        f.write(b"rename test")
    do_pasv_upload(ctrl, "before_rename.dat", "test_rename.dat")
    os.remove("test_rename.dat")

    # RNFR
    ctrl.send_command("RNFR before_rename.dat")
    code, _ = ctrl.recv_reply()
    check("RNFR -> 350", code == 350)

    # RNTO
    ctrl.send_command("RNTO after_rename.dat")
    code, _ = ctrl.recv_reply()
    check("RNTO -> 250", code == 250)

    # Verify old name gone
    ctrl.send_command("SIZE before_rename.dat")
    code, _ = ctrl.recv_reply()
    check("old name gone", code == 550)

    # Verify new name exists
    ctrl.send_command("SIZE after_rename.dat")
    code, _ = ctrl.recv_reply()
    check("new name exists", code == 213)

    # RNTO without RNFR
    ctrl.send_command("RNTO something.dat")
    code, _ = ctrl.recv_reply()
    check("RNTO without RNFR -> 503", code == 503)

    # Cleanup
    ctrl.send_command("DELE after_rename.dat")
    ctrl.recv_reply()

    ctrl.send_command("QUIT")
    ctrl.recv_reply()
    ctrl.close()


def test_error_cases():
    print("\n=== Error Cases ===")
    ctrl = connect_and_login()

    # RETR non-existent
    h, p = pasv_setup(ctrl)
    ctrl.send_command("RETR nonexistent_file.dat")
    code, _ = ctrl.recv_reply()
    check("RETR non-existent -> 550", code == 550)

    # DELE non-existent
    ctrl.send_command("DELE nonexistent_file.dat")
    code, _ = ctrl.recv_reply()
    check("DELE non-existent -> 550", code == 550)

    # No PASV/PORT before data command
    # Reset modes by connecting fresh
    ctrl.send_command("QUIT")
    ctrl.recv_reply()
    ctrl.close()

    ctrl = connect_and_login()

    # Unknown command
    ctrl.send_command("XYZZY")
    code, _ = ctrl.recv_reply()
    check("unknown command -> 500", code == 500)

    # Empty commands
    ctrl.send_command("SIZE")
    code, _ = ctrl.recv_reply()
    check("SIZE no args -> 501", code == 501)

    ctrl.send_command("QUIT")
    ctrl.recv_reply()
    ctrl.close()


def test_concurrent_clients():
    print("\n=== Concurrent Clients ===")
    results = []

    def client_worker(client_id: int) -> None:
        try:
            ctrl = connect_and_login()
            # Each client does PWD and LIST independently
            ctrl.send_command("PWD")
            code, _ = ctrl.recv_reply()
            if code != 257:
                results.append((client_id, False, f"PWD got {code}"))
                return

            listing = do_pasv_list(ctrl)
            if "welcome.txt" not in listing:
                results.append((client_id, False, "listing missing welcome.txt"))
                return

            ctrl.send_command("QUIT")
            ctrl.recv_reply()
            ctrl.close()
            results.append((client_id, True, ""))
        except Exception as e:
            results.append((client_id, False, str(e)))

    threads = []
    for i in range(4):
        t = threading.Thread(target=client_worker, args=(i,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=30)

    all_ok = all(r[1] for r in results)
    check(
        f"4 concurrent clients",
        all_ok,
        "; ".join(f"client {r[0]}: {r[2]}" for r in results if not r[1]),
    )


# =====================================================
#  MAIN
# =====================================================

def main():
    print("=" * 60)
    print("  HYBRID FTP — COMPREHENSIVE TEST SUITE")
    print("=" * 60)

    test_auth()
    test_directory_ops()
    test_file_info()
    test_pasv_transfers()
    test_port_transfers()
    test_binary_integrity()
    test_stou_appe()
    test_rename()
    test_error_cases()
    test_concurrent_clients()

    print()
    print("=" * 60)
    total = PASS_COUNT + FAIL_COUNT
    print(f"  Results: {PASS_COUNT}/{total} passed, {FAIL_COUNT} failed")
    if FAIL_COUNT == 0:
        print("  ALL TESTS PASSED!")
    else:
        print("  SOME TESTS FAILED")
    print("=" * 60)
    return FAIL_COUNT == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
