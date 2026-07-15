"""
Custom Selective-Repeat reliable data transfer over UDP.

The TCP FTP control channel owns authentication, commands, and endpoint
negotiation. It creates one UDP socket per data transfer, supplies a fresh
transfer ID, and then calls establish_udp() followed by a send_* or receive_*
function in this module.
"""

from __future__ import annotations

import hashlib
import io
import os
import secrets
import socket
import struct
import threading
import time
import zlib
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum, IntFlag
from pathlib import Path
from typing import BinaryIO, Callable, Dict, Optional, Tuple, Union


SocketAddress = Tuple[str, int]
ProgressCallback = Callable[["TransferProgress"], None]

MAGIC = b"RDT1"
PROTOCOL_VERSION = 1

# ! means network byte order and standard sizes with no implicit padding.
# magic, version, flags, transfer_id, sequence, acknowledgment, rwnd,
# payload_length, checksum
HEADER = struct.Struct("!4sBBQIIHHI")
HEADER_SIZE = HEADER.size  # 30 bytes

FIN_METADATA = struct.Struct("!Q32s")  # sender byte count, sender SHA-256
FIN_RESULT = struct.Struct("!BQ32s")  # status, receiver byte count, SHA-256

MAX_PAYLOAD_SIZE = 1200
MAX_DATAGRAM_SIZE = HEADER_SIZE + MAX_PAYLOAD_SIZE
NO_ACK = 0xFFFFFFFF
HANDSHAKE_SEQUENCE = 0
FIRST_DATA_SEQUENCE = 1
MAX_TRANSFER_ID = (1 << 64) - 1
CANCELLATION_POLL_INTERVAL = 0.20


class PacketFlag(IntFlag):
    SYN = 0x01
    ACK = 0x02
    DATA = 0x04
    FIN = 0x08
    ABORT = 0x10
    RESULT = 0x20
    PROBE = 0x40


ALL_FLAGS = int(
    PacketFlag.SYN
    | PacketFlag.ACK
    | PacketFlag.DATA
    | PacketFlag.FIN
    | PacketFlag.ABORT
    | PacketFlag.RESULT
    | PacketFlag.PROBE
)
SYN_ACK_FLAGS = PacketFlag.SYN | PacketFlag.ACK
FIN_RESULT_FLAGS = PacketFlag.FIN | PacketFlag.ACK | PacketFlag.RESULT
RESULT_CONFIRM_FLAGS = PacketFlag.ACK | PacketFlag.RESULT


class TransferState(str, Enum):
    CLOSED = "CLOSED"
    SYN_SENT = "SYN_SENT"
    SYN_RECEIVED = "SYN_RECEIVED"
    ESTABLISHED = "ESTABLISHED"
    SENDING = "SENDING"
    FIN_WAIT = "FIN_WAIT"
    RECEIVING = "RECEIVING"
    LINGER = "LINGER"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"
    ABORTED = "ABORTED"


class RDTError(Exception):
    """Base exception for errors raised by the RDT layer."""


class RDTProtocolError(RDTError):
    """A peer sent a valid but protocol-invalid packet."""


class RDTTimeoutError(RDTError):
    """A peer did not respond before the retry budget was exhausted."""


class RDTIntegrityError(RDTError):
    """The sender and receiver byte count or SHA-256 digest differed."""


class RDTAborted(RDTError):
    """The local abort event or a peer ABORT packet stopped the transfer."""


@dataclass(frozen=True)
class RDTConfig:
    """Transport limits and timing values for one UDP transfer."""

    payload_size: int = MAX_PAYLOAD_SIZE
    receive_window: int = 64
    initial_cwnd: int = 1
    max_cwnd: int = 64
    initial_ssthresh: int = 16
    initial_rto: float = 0.40
    min_rto: float = 0.10
    max_rto: float = 3.00
    max_retries: int = 12
    idle_timeout: float = 30.0
    zero_window_probe_interval: float = 0.50
    final_linger: float = 10.0

    def __post_init__(self) -> None:
        if not 1 <= self.payload_size <= MAX_PAYLOAD_SIZE:
            raise ValueError(
                "payload_size must be between 1 and {}".format(MAX_PAYLOAD_SIZE)
            )
        if not 1 <= self.receive_window <= 0xFFFF:
            raise ValueError("receive_window must fit in an unsigned 16-bit field")
        if not 1 <= self.initial_cwnd <= self.max_cwnd <= 0xFFFF:
            raise ValueError("cwnd values must be ordered unsigned 16-bit values")
        if not 2 <= self.initial_ssthresh <= self.max_cwnd:
            raise ValueError("initial_ssthresh must be between 2 and max_cwnd")
        if not 0 < self.min_rto <= self.initial_rto <= self.max_rto:
            raise ValueError("RTO values must satisfy 0 < min <= initial <= max")
        if self.max_retries < 0:
            raise ValueError("max_retries cannot be negative")
        if self.idle_timeout <= 0:
            raise ValueError("idle_timeout must be positive")
        if self.zero_window_probe_interval <= 0:
            raise ValueError("zero_window_probe_interval must be positive")
        if self.final_linger < 0:
            raise ValueError("final_linger cannot be negative")


DEFAULT_CONFIG = RDTConfig()


@dataclass(frozen=True)
class TransferProgress:
    direction: str
    bytes_completed: int
    total_bytes: Optional[int]
    packets_in_flight: int
    retransmissions: int


@dataclass(frozen=True)
class TransferResult:
    transfer_id: int
    peer: SocketAddress
    bytes_transferred: int
    sha256: str
    packets_sent: int
    packets_received: int
    retransmissions: int
    duplicate_packets: int
    duration: float


@dataclass
class RDTSession:
    """
    An established, single-direction UDP transfer session.

    A session is intentionally owned by one FTP transfer worker and must not
    be shared by concurrent threads.
    """

    sock: socket.socket
    peer: SocketAddress
    transfer_id: int
    config: RDTConfig
    initiated: bool
    peer_window: int
    state: TransferState = TransferState.CLOSED
    packets_sent: int = 0
    packets_received: int = 0
    retransmissions: int = 0
    duplicate_packets: int = 0
    started_at: float = field(default_factory=time.monotonic)
    cwnd: float = field(init=False)
    ssthresh: float = field(init=False)
    _rto: float = field(init=False)
    _srtt: Optional[float] = field(default=None, init=False)
    _rttvar: Optional[float] = field(default=None, init=False)

    def __post_init__(self) -> None:
        _validate_transfer_id(self.transfer_id)
        self.peer_window = _clamp_window(self.peer_window, self.config)
        self.cwnd = float(self.config.initial_cwnd)
        self.ssthresh = float(self.config.initial_ssthresh)
        self._rto = self.config.initial_rto


@dataclass(frozen=True)
class _Packet:
    flags: PacketFlag
    transfer_id: int
    sequence: int
    acknowledgment: int
    receive_window: int
    payload: bytes


@dataclass
class _Outstanding:
    payload: bytes
    sent_at: float
    retries: int = 0
    retransmitted: bool = False


def new_transfer_id() -> int:
    """Return a non-zero, unpredictable ID for a TCP-negotiated UDP transfer."""

    return secrets.randbits(64) or 1


def sha256_file(
    path: Union[str, os.PathLike[str]], chunk_size: int = 1024 * 1024
) -> Tuple[int, bytes]:
    """Hash a regular file before a file transfer begins."""

    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")

    source = Path(path)
    if not source.is_file():
        raise FileNotFoundError("not a regular file: {}".format(source))

    digest = hashlib.sha256()
    total = 0
    with source.open("rb") as file_handle:
        while True:
            chunk = file_handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
    return total, digest.digest()


def establish_udp(
    sock: socket.socket,
    transfer_id: int,
    *,
    initiator: bool,
    peer: Optional[SocketAddress] = None,
    expected_peer: Optional[SocketAddress] = None,
    config: Optional[RDTConfig] = None,
    abort_event: Optional[threading.Event] = None,
) -> RDTSession:
    """
    Establish the lightweight RDT handshake on an already-bound UDP socket.

    An initiator needs an exact peer endpoint. A responder waits for a SYN and
    can use an expected peer with port 0 to match only the peer IP address.
    The two-message SYN / SYN|ACK exchange is retransmitted because UDP has no
    connection setup of its own.
    """

    _validate_transfer_id(transfer_id)
    active_config = config or DEFAULT_CONFIG

    if initiator:
        if peer is None:
            raise ValueError("an initiating endpoint requires peer=(host, port)")
        session = RDTSession(
            sock=sock,
            peer=peer,
            transfer_id=transfer_id,
            config=active_config,
            initiated=True,
            peer_window=active_config.receive_window,
            state=TransferState.SYN_SENT,
        )
        with _preserve_socket_timeout(sock):
            for attempt in range(active_config.max_retries + 1):
                _check_local_abort(session, abort_event)
                _send_packet(
                    session,
                    PacketFlag.SYN,
                    sequence=HANDSHAKE_SEQUENCE,
                    acknowledgment=NO_ACK,
                    retransmission=attempt > 0,
                )
                deadline = time.monotonic() + session._rto
                while True:
                    received = _receive_for_session(session, deadline, abort_event)
                    if received is None:
                        break
                    packet, _ = received
                    _raise_if_peer_aborted(session, packet)
                    if _is_syn_ack(packet):
                        session.peer_window = _clamp_window(
                            packet.receive_window, active_config
                        )
                        session.state = TransferState.ESTABLISHED
                        return session
                session._rto = min(active_config.max_rto, session._rto * 2)

        session.state = TransferState.FAILED
        _send_abort(session, "SYN retry budget exhausted")
        raise RDTTimeoutError("timed out waiting for SYN|ACK")

    with _preserve_socket_timeout(sock):
        deadline = time.monotonic() + active_config.idle_timeout
        while True:
            if abort_event is not None and abort_event.is_set():
                raise RDTAborted("transfer aborted before UDP handshake")
            candidate = _receive_candidate_until(sock, deadline)
            if candidate is None:
                if time.monotonic() >= deadline:
                    raise RDTTimeoutError("timed out waiting for SYN")
                continue

            packet, address = candidate
            if packet.transfer_id != transfer_id:
                continue
            if not _matches_peer(address, expected_peer):
                continue
            if packet.flags & PacketFlag.ABORT:
                raise RDTAborted(_abort_reason(packet))
            if not _is_syn(packet):
                continue

            session = RDTSession(
                sock=sock,
                peer=address,
                transfer_id=transfer_id,
                config=active_config,
                initiated=False,
                peer_window=packet.receive_window,
                state=TransferState.SYN_RECEIVED,
                packets_received=1,
            )
            _send_syn_ack(session)
            session.state = TransferState.ESTABLISHED
            return session


def send_file(
    session: RDTSession,
    path: Union[str, os.PathLike[str]],
    *,
    progress: Optional[ProgressCallback] = None,
    abort_event: Optional[threading.Event] = None,
) -> TransferResult:
    """
    Send a file in binary mode after calculating a pre-transfer SHA-256 digest.

    The stream is hashed again while it is read for transmission. A changed
    source file is detected before FIN is sent instead of silently certifying
    a different version than the one pre-hashed.
    """

    source = Path(path)
    try:
        expected_size, expected_digest = sha256_file(source)
        with source.open("rb") as file_handle:
            return send_stream(
                session,
                file_handle,
                total_size=expected_size,
                expected_sha256=expected_digest,
                progress=progress,
                abort_event=abort_event,
            )
    except Exception:
        if session.state not in (TransferState.COMPLETE, TransferState.ABORTED):
            session.state = TransferState.FAILED
            _send_abort(session, "source file could not be transferred")
        raise


def send_bytes(
    session: RDTSession,
    payload: Union[bytes, bytearray, memoryview],
    *,
    progress: Optional[ProgressCallback] = None,
    abort_event: Optional[threading.Event] = None,
) -> TransferResult:
    """Send generated binary data, for example a LIST or NLST response."""

    data = bytes(payload)
    return send_stream(
        session,
        io.BytesIO(data),
        total_size=len(data),
        expected_sha256=hashlib.sha256(data).digest(),
        progress=progress,
        abort_event=abort_event,
    )


def send_stream(
    session: RDTSession,
    source: BinaryIO,
    *,
    total_size: Optional[int] = None,
    expected_sha256: Optional[bytes] = None,
    progress: Optional[ProgressCallback] = None,
    abort_event: Optional[threading.Event] = None,
) -> TransferResult:
    """
    Reliably send a binary stream with Selective Repeat retransmissions.

    total_size and expected_sha256 are optional for generated streams.
    Supplying both provides the same pre/post source validation as send_file.
    """

    _require_established(session)
    if total_size is not None and total_size < 0:
        raise ValueError("total_size cannot be negative")
    if expected_sha256 is not None and len(expected_sha256) != hashlib.sha256().digest_size:
        raise ValueError("expected_sha256 must be a 32-byte SHA-256 digest")

    session.state = TransferState.SENDING
    digest = hashlib.sha256()
    outstanding: Dict[int, _Outstanding] = {}
    next_sequence = FIRST_DATA_SEQUENCE
    source_exhausted = False
    bytes_read = 0
    bytes_acked = 0
    next_probe = time.monotonic()

    with _preserve_socket_timeout(session.sock):
        try:
            while not source_exhausted or outstanding:
                _check_local_abort(session, abort_event)
                window = _effective_send_window(session)

                while (
                    not source_exhausted
                    and session.peer_window > 0
                    and len(outstanding) < window
                ):
                    if next_sequence >= NO_ACK - 1:
                        _send_abort(session, "sequence number space exhausted")
                        session.state = TransferState.FAILED
                        raise RDTProtocolError("file exceeds the supported sequence space")

                    payload = source.read(session.config.payload_size)
                    if not isinstance(payload, (bytes, bytearray, memoryview)):
                        raise TypeError("source.read() must return binary bytes")
                    payload = bytes(payload)
                    if not payload:
                        source_exhausted = True
                        break

                    digest.update(payload)
                    bytes_read += len(payload)
                    outstanding[next_sequence] = _Outstanding(
                        payload=payload,
                        sent_at=time.monotonic(),
                    )
                    _send_packet(
                        session,
                        PacketFlag.DATA,
                        sequence=next_sequence,
                        acknowledgment=NO_ACK,
                        payload=payload,
                    )
                    outstanding[next_sequence].sent_at = time.monotonic()
                    next_sequence += 1

                if source_exhausted and not outstanding:
                    break

                now = time.monotonic()
                deadlines = [
                    packet.sent_at + session._rto for packet in outstanding.values()
                ]
                if session.peer_window == 0:
                    deadlines.append(next_probe)
                deadline = min(deadlines) if deadlines else now + session._rto

                received = _receive_for_session(session, deadline, abort_event)
                if received is not None:
                    packet, _ = received
                    _raise_if_peer_aborted(session, packet)
                    if _handle_duplicate_syn(session, packet):
                        continue
                    if packet.flags == PacketFlag.ACK:
                        if packet.sequence != HANDSHAKE_SEQUENCE or packet.payload:
                            continue
                        session.peer_window = _clamp_window(
                            packet.receive_window, session.config
                        )
                        acknowledged = outstanding.pop(packet.acknowledgment, None)
                        if acknowledged is None:
                            session.duplicate_packets += 1
                            continue

                        bytes_acked += len(acknowledged.payload)
                        if not acknowledged.retransmitted:
                            _update_rto(
                                session, max(0.000001, time.monotonic() - acknowledged.sent_at)
                            )
                        _increase_congestion_window(session)
                        _report_progress(
                            progress,
                            TransferProgress(
                                direction="send",
                                bytes_completed=bytes_acked,
                                total_bytes=total_size,
                                packets_in_flight=len(outstanding),
                                retransmissions=session.retransmissions,
                            ),
                        )
                    continue

                now = time.monotonic()
                expired = [
                    sequence
                    for sequence, packet in outstanding.items()
                    if now - packet.sent_at >= session._rto
                ]
                if expired:
                    _decrease_congestion_window(session)
                    session._rto = min(
                        session.config.max_rto, max(session.config.min_rto, session._rto * 2)
                    )
                    for sequence in expired:
                        packet = outstanding[sequence]
                        if packet.retries >= session.config.max_retries:
                            session.state = TransferState.FAILED
                            _send_abort(session, "DATA retry budget exhausted")
                            raise RDTTimeoutError(
                                "timed out waiting for ACK of sequence {}".format(sequence)
                            )
                        packet.retries += 1
                        packet.retransmitted = True
                        _send_packet(
                            session,
                            PacketFlag.DATA,
                            sequence=sequence,
                            acknowledgment=NO_ACK,
                            payload=packet.payload,
                            retransmission=True,
                        )
                        packet.sent_at = time.monotonic()

                if session.peer_window == 0 and now >= next_probe:
                    _send_packet(
                        session,
                        PacketFlag.PROBE,
                        sequence=HANDSHAKE_SEQUENCE,
                        acknowledgment=NO_ACK,
                    )
                    next_probe = now + session.config.zero_window_probe_interval

            sender_digest = digest.digest()
            if total_size is not None and bytes_read != total_size:
                session.state = TransferState.FAILED
                _send_abort(session, "source size changed during transfer")
                raise RDTIntegrityError("source size changed during transfer")
            if expected_sha256 is not None and sender_digest != expected_sha256:
                session.state = TransferState.FAILED
                _send_abort(session, "source digest changed during transfer")
                raise RDTIntegrityError("source digest changed during transfer")

            return _finish_send(
                session,
                fin_sequence=next_sequence,
                byte_count=bytes_read,
                digest=sender_digest,
                progress=progress,
                abort_event=abort_event,
            )
        except RDTError:
            raise
        except Exception:
            session.state = TransferState.FAILED
            _send_abort(session, "sender failed unexpectedly")
            raise


def receive_file(
    session: RDTSession,
    path: Union[str, os.PathLike[str]],
    *,
    overwrite: bool = True,
    progress: Optional[ProgressCallback] = None,
    abort_event: Optional[threading.Event] = None,
) -> TransferResult:
    """
    Receive into a transfer-specific temporary file and atomically replace path.

    The receiver sends its successful final result only after the temporary
    file is flushed, closed, and moved into place.
    """

    committed = False
    file_handle: Optional[BinaryIO] = None
    temporary: Optional[Path] = None

    try:
        destination = Path(path)
        if not destination.parent.is_dir():
            raise FileNotFoundError(
                "destination directory does not exist: {}".format(destination.parent)
            )
        if not overwrite and destination.exists():
            raise FileExistsError("destination already exists: {}".format(destination))

        temporary = destination.with_name(
            ".{}.rdt-{:016x}.part".format(destination.name, session.transfer_id)
        )
        if temporary.exists():
            raise FileExistsError("stale temporary file exists: {}".format(temporary))

        file_handle = temporary.open("xb")

        def commit() -> None:
            nonlocal committed
            assert file_handle is not None
            if not file_handle.closed:
                file_handle.close()
            os.replace(temporary, destination)
            committed = True

        return receive_stream(
            session,
            file_handle,
            progress=progress,
            abort_event=abort_event,
            finalize_sink=commit,
        )
    except Exception:
        if session.state not in (TransferState.COMPLETE, TransferState.ABORTED):
            session.state = TransferState.FAILED
            _send_abort(session, "destination file could not be prepared")
        raise
    finally:
        if file_handle is not None and not file_handle.closed:
            file_handle.close()
        if temporary is not None and not committed:
            try:
                temporary.unlink()
            except OSError:
                pass


def receive_bytes(
    session: RDTSession,
    *,
    progress: Optional[ProgressCallback] = None,
    abort_event: Optional[threading.Event] = None,
) -> Tuple[bytes, TransferResult]:
    """Receive generated data such as a directory listing into memory."""

    target = io.BytesIO()
    result = receive_stream(
        session,
        target,
        progress=progress,
        abort_event=abort_event,
    )
    return target.getvalue(), result


def receive_stream(
    session: RDTSession,
    sink: BinaryIO,
    *,
    progress: Optional[ProgressCallback] = None,
    abort_event: Optional[threading.Event] = None,
    finalize_sink: Optional[Callable[[], None]] = None,
) -> TransferResult:
    """
    Reliably receive a binary stream, buffer out-of-order packets, and verify FIN.

    finalize_sink, if provided, runs after hash verification but before the
    success result is returned to the sender. receive_file uses it for os.replace.
    """

    _require_established(session)
    session.state = TransferState.RECEIVING
    expected_sequence = FIRST_DATA_SEQUENCE
    reorder_buffer: Dict[int, bytes] = {}
    pending_fin: Optional[_Packet] = None
    digest = hashlib.sha256()
    bytes_written = 0

    with _preserve_socket_timeout(session.sock):
        try:
            deadline = time.monotonic() + session.config.idle_timeout
            while True:
                _check_local_abort(session, abort_event)
                received = _receive_for_session(session, deadline, abort_event)
                if received is None:
                    session.state = TransferState.FAILED
                    _send_abort(session, "receiver idle timeout")
                    raise RDTTimeoutError("timed out waiting for DATA or FIN")

                packet, _ = received
                _raise_if_peer_aborted(session, packet)
                if _handle_duplicate_syn(session, packet):
                    deadline = time.monotonic() + session.config.idle_timeout
                    continue

                deadline = time.monotonic() + session.config.idle_timeout

                if packet.flags == PacketFlag.DATA:
                    if (
                        packet.sequence < FIRST_DATA_SEQUENCE
                        or packet.acknowledgment != NO_ACK
                    ):
                        session.state = TransferState.FAILED
                        _send_abort(session, "malformed DATA header")
                        raise RDTProtocolError("DATA packet has invalid control fields")
                    if not packet.payload:
                        session.state = TransferState.FAILED
                        _send_abort(session, "zero-length DATA packet")
                        raise RDTProtocolError("DATA packets must carry a payload")

                    if pending_fin is not None and packet.sequence >= pending_fin.sequence:
                        _send_ack(session, NO_ACK, _available_window(reorder_buffer, session))
                        continue

                    if packet.sequence < expected_sequence:
                        session.duplicate_packets += 1
                        _send_ack(
                            session,
                            packet.sequence,
                            _available_window(reorder_buffer, session),
                        )
                        continue

                    if packet.sequence >= expected_sequence + session.config.receive_window:
                        _send_ack(session, NO_ACK, _available_window(reorder_buffer, session))
                        continue

                    if packet.sequence in reorder_buffer:
                        session.duplicate_packets += 1
                    else:
                        reorder_buffer[packet.sequence] = packet.payload

                    while expected_sequence in reorder_buffer:
                        contiguous = reorder_buffer.pop(expected_sequence)
                        _write_all(sink, contiguous)
                        digest.update(contiguous)
                        bytes_written += len(contiguous)
                        expected_sequence += 1

                    _send_ack(
                        session,
                        packet.sequence,
                        _available_window(reorder_buffer, session),
                    )
                    _report_progress(
                        progress,
                        TransferProgress(
                            direction="receive",
                            bytes_completed=bytes_written,
                            total_bytes=None,
                            packets_in_flight=len(reorder_buffer),
                            retransmissions=session.retransmissions,
                        ),
                    )

                    if (
                        pending_fin is not None
                        and expected_sequence == pending_fin.sequence
                    ):
                        return _finish_receive(
                            session,
                            sink,
                            pending_fin,
                            bytes_written,
                            digest,
                            progress,
                            abort_event,
                            finalize_sink,
                        )
                    continue

                if packet.flags == PacketFlag.FIN:
                    if (
                        packet.sequence < FIRST_DATA_SEQUENCE
                        or packet.acknowledgment != NO_ACK
                    ):
                        session.state = TransferState.FAILED
                        _send_abort(session, "malformed FIN header")
                        raise RDTProtocolError("FIN packet has invalid control fields")
                    if len(packet.payload) != FIN_METADATA.size:
                        session.state = TransferState.FAILED
                        _send_abort(session, "malformed FIN metadata")
                        raise RDTProtocolError("FIN metadata has an invalid length")

                    if packet.sequence == expected_sequence:
                        return _finish_receive(
                            session,
                            sink,
                            packet,
                            bytes_written,
                            digest,
                            progress,
                            abort_event,
                            finalize_sink,
                        )

                    if packet.sequence > expected_sequence:
                        if pending_fin is None:
                            pending_fin = packet
                        elif (
                            pending_fin.sequence != packet.sequence
                            or pending_fin.payload != packet.payload
                        ):
                            session.state = TransferState.FAILED
                            _send_abort(session, "conflicting FIN packets")
                            raise RDTProtocolError("received conflicting FIN metadata")
                        _send_ack(session, NO_ACK, _available_window(reorder_buffer, session))
                        continue

                    _send_ack(session, NO_ACK, _available_window(reorder_buffer, session))
                    continue

                if (
                    packet.flags == PacketFlag.PROBE
                    and packet.sequence == HANDSHAKE_SEQUENCE
                    and packet.acknowledgment == NO_ACK
                    and not packet.payload
                ):
                    _send_ack(session, NO_ACK, _available_window(reorder_buffer, session))
        except RDTError:
            raise
        except Exception:
            session.state = TransferState.FAILED
            _send_abort(session, "receiver failed unexpectedly")
            raise


def _finish_send(
    session: RDTSession,
    *,
    fin_sequence: int,
    byte_count: int,
    digest: bytes,
    progress: Optional[ProgressCallback],
    abort_event: Optional[threading.Event],
) -> TransferResult:
    session.state = TransferState.FIN_WAIT
    fin_payload = FIN_METADATA.pack(byte_count, digest)

    for attempt in range(session.config.max_retries + 1):
        _check_local_abort(session, abort_event)
        _send_packet(
            session,
            PacketFlag.FIN,
            sequence=fin_sequence,
            acknowledgment=NO_ACK,
            payload=fin_payload,
            retransmission=attempt > 0,
        )
        deadline = time.monotonic() + session._rto

        while True:
            received = _receive_for_session(session, deadline, abort_event)
            if received is None:
                break
            packet, _ = received
            _raise_if_peer_aborted(session, packet)
            if _handle_duplicate_syn(session, packet):
                continue
            if packet.flags == PacketFlag.ACK:
                if packet.sequence != HANDSHAKE_SEQUENCE or packet.payload:
                    continue
                session.peer_window = _clamp_window(packet.receive_window, session.config)
                continue
            if (
                packet.flags != FIN_RESULT_FLAGS
                or packet.sequence != HANDSHAKE_SEQUENCE
                or packet.acknowledgment != fin_sequence
                or len(packet.payload) != FIN_RESULT.size
            ):
                continue

            status, receiver_bytes, receiver_digest = FIN_RESULT.unpack(packet.payload)
            if status not in (0, 1):
                continue

            _send_packet(
                session,
                RESULT_CONFIRM_FLAGS,
                sequence=HANDSHAKE_SEQUENCE,
                acknowledgment=fin_sequence,
            )

            if (
                status == 1
                and receiver_bytes == byte_count
                and receiver_digest == digest
            ):
                session.state = TransferState.COMPLETE
                _report_progress(
                    progress,
                    TransferProgress(
                        direction="send",
                        bytes_completed=byte_count,
                        total_bytes=byte_count,
                        packets_in_flight=0,
                        retransmissions=session.retransmissions,
                    ),
                )
                return _result(session, byte_count, digest)

            session.state = TransferState.FAILED
            raise RDTIntegrityError(
                "receiver rejected transfer: status={}, bytes={}, sha256={}".format(
                    status, receiver_bytes, receiver_digest.hex()
                )
            )

        session._rto = min(session.config.max_rto, session._rto * 2)

    session.state = TransferState.FAILED
    _send_abort(session, "FIN retry budget exhausted")
    raise RDTTimeoutError("timed out waiting for final integrity result")


def _finish_receive(
    session: RDTSession,
    sink: BinaryIO,
    fin: _Packet,
    bytes_written: int,
    digest: object,
    progress: Optional[ProgressCallback],
    abort_event: Optional[threading.Event],
    finalize_sink: Optional[Callable[[], None]],
) -> TransferResult:
    sender_bytes, sender_digest = FIN_METADATA.unpack(fin.payload)
    local_digest = digest.digest()  # hashlib objects share this small interface.
    verified = sender_bytes == bytes_written and sender_digest == local_digest

    try:
        _flush_sink(sink)
        if verified and finalize_sink is not None:
            finalize_sink()
    except Exception as error:
        session.state = TransferState.FAILED
        _send_abort(session, "receiver could not finalize destination")
        raise RDTError("receiver could not finalize destination") from error

    result_payload = FIN_RESULT.pack(
        1 if verified else 0,
        bytes_written,
        local_digest,
    )
    _send_packet(
        session,
        FIN_RESULT_FLAGS,
        sequence=HANDSHAKE_SEQUENCE,
        acknowledgment=fin.sequence,
        payload=result_payload,
    )

    session.state = TransferState.LINGER
    deadline = time.monotonic() + _final_result_linger(session)
    while True:
        _check_local_abort(session, abort_event)
        received = _receive_for_session(session, deadline, abort_event)
        if received is None:
            break
        packet, _ = received
        _raise_if_peer_aborted(session, packet)
        if _handle_duplicate_syn(session, packet):
            continue
        if (
            packet.flags == PacketFlag.FIN
            and packet.sequence == fin.sequence
            and packet.acknowledgment == NO_ACK
            and packet.payload == fin.payload
        ):
            _send_packet(
                session,
                FIN_RESULT_FLAGS,
                sequence=HANDSHAKE_SEQUENCE,
                acknowledgment=fin.sequence,
                payload=result_payload,
                retransmission=True,
            )
            continue
        if (
            packet.flags == RESULT_CONFIRM_FLAGS
            and packet.sequence == HANDSHAKE_SEQUENCE
            and packet.acknowledgment == fin.sequence
            and not packet.payload
        ):
            break

    if not verified:
        session.state = TransferState.FAILED
        raise RDTIntegrityError(
            "SHA-256 or byte count mismatch: sender={} bytes, receiver={} bytes".format(
                sender_bytes, bytes_written
            )
        )

    session.state = TransferState.COMPLETE
    _report_progress(
        progress,
        TransferProgress(
            direction="receive",
            bytes_completed=bytes_written,
            total_bytes=bytes_written,
            packets_in_flight=0,
            retransmissions=session.retransmissions,
        ),
    )
    return _result(session, bytes_written, local_digest)


def _encode_packet(
    flags: PacketFlag,
    transfer_id: int,
    sequence: int,
    acknowledgment: int,
    receive_window: int,
    payload: Union[bytes, bytearray, memoryview],
) -> bytes:
    _validate_transfer_id(transfer_id)
    _validate_u32(sequence, "sequence")
    _validate_u32(acknowledgment, "acknowledgment")
    if not 0 <= receive_window <= 0xFFFF:
        raise ValueError("receive_window must fit in an unsigned 16-bit field")

    raw_flags = int(flags)
    if raw_flags == 0 or raw_flags & ~ALL_FLAGS:
        raise ValueError("packet flags are invalid")

    binary_payload = bytes(payload)
    if len(binary_payload) > MAX_PAYLOAD_SIZE:
        raise ValueError(
            "payload exceeds maximum UDP payload size of {}".format(MAX_PAYLOAD_SIZE)
        )

    zeroed_header = HEADER.pack(
        MAGIC,
        PROTOCOL_VERSION,
        raw_flags,
        transfer_id,
        sequence,
        acknowledgment,
        receive_window,
        len(binary_payload),
        0,
    )
    checksum = zlib.crc32(zeroed_header + binary_payload) & 0xFFFFFFFF
    header = HEADER.pack(
        MAGIC,
        PROTOCOL_VERSION,
        raw_flags,
        transfer_id,
        sequence,
        acknowledgment,
        receive_window,
        len(binary_payload),
        checksum,
    )
    return header + binary_payload


def _decode_packet(datagram: bytes) -> Optional[_Packet]:
    if len(datagram) < HEADER_SIZE:
        return None

    try:
        (
            magic,
            version,
            raw_flags,
            transfer_id,
            sequence,
            acknowledgment,
            receive_window,
            payload_length,
            checksum,
        ) = HEADER.unpack_from(datagram)
    except struct.error:
        return None

    if magic != MAGIC or version != PROTOCOL_VERSION:
        return None
    if raw_flags == 0 or raw_flags & ~ALL_FLAGS:
        return None
    if payload_length > MAX_PAYLOAD_SIZE:
        return None
    if len(datagram) != HEADER_SIZE + payload_length:
        return None

    payload = datagram[HEADER_SIZE:]
    zeroed_header = HEADER.pack(
        magic,
        version,
        raw_flags,
        transfer_id,
        sequence,
        acknowledgment,
        receive_window,
        payload_length,
        0,
    )
    calculated = zlib.crc32(zeroed_header + payload) & 0xFFFFFFFF
    if calculated != checksum:
        return None

    return _Packet(
        flags=PacketFlag(raw_flags),
        transfer_id=transfer_id,
        sequence=sequence,
        acknowledgment=acknowledgment,
        receive_window=receive_window,
        payload=payload,
    )


def _send_packet(
    session: RDTSession,
    flags: PacketFlag,
    *,
    sequence: int,
    acknowledgment: int,
    payload: bytes = b"",
    receive_window: Optional[int] = None,
    retransmission: bool = False,
) -> None:
    advertised_window = (
        session.config.receive_window if receive_window is None else receive_window
    )
    encoded = _encode_packet(
        flags,
        session.transfer_id,
        sequence,
        acknowledgment,
        advertised_window,
        payload,
    )
    sent = session.sock.sendto(encoded, session.peer)
    if sent != len(encoded):
        raise OSError("UDP socket sent an incomplete datagram")
    session.packets_sent += 1
    if retransmission:
        session.retransmissions += 1


def _send_syn_ack(session: RDTSession) -> None:
    _send_packet(
        session,
        SYN_ACK_FLAGS,
        sequence=HANDSHAKE_SEQUENCE,
        acknowledgment=HANDSHAKE_SEQUENCE,
    )


def _send_ack(session: RDTSession, acknowledgment: int, receive_window: int) -> None:
    _send_packet(
        session,
        PacketFlag.ACK,
        sequence=HANDSHAKE_SEQUENCE,
        acknowledgment=acknowledgment,
        receive_window=receive_window,
    )


def _send_abort(session: RDTSession, reason: str) -> None:
    payload = reason.encode("utf-8", "replace")[:MAX_PAYLOAD_SIZE]
    try:
        _send_packet(
            session,
            PacketFlag.ABORT,
            sequence=HANDSHAKE_SEQUENCE,
            acknowledgment=NO_ACK,
            payload=payload,
        )
    except OSError:
        pass


def _receive_for_session(
    session: RDTSession,
    deadline: float,
    abort_event: Optional[threading.Event] = None,
) -> Optional[Tuple[_Packet, SocketAddress]]:
    while True:
        _check_local_abort(session, abort_event)
        candidate = _receive_candidate_until(session.sock, deadline)
        if candidate is None:
            if time.monotonic() >= deadline:
                return None
            continue
        packet, address = candidate
        if packet.transfer_id != session.transfer_id:
            continue
        if not _matches_peer(address, session.peer):
            continue
        session.packets_received += 1
        return packet, address


def _receive_candidate_until(
    sock: socket.socket, deadline: float
) -> Optional[Tuple[_Packet, SocketAddress]]:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    sock.settimeout(min(remaining, CANCELLATION_POLL_INTERVAL))
    try:
        datagram, address = sock.recvfrom(MAX_DATAGRAM_SIZE + 1)
    except socket.timeout:
        return None
    except InterruptedError:
        return None

    packet = _decode_packet(datagram)
    if packet is None:
        return None
    return packet, address


def _handle_duplicate_syn(session: RDTSession, packet: _Packet) -> bool:
    if not _is_syn(packet):
        return False
    if not session.initiated:
        _send_syn_ack(session)
    return True


def _is_syn(packet: _Packet) -> bool:
    return (
        packet.flags == PacketFlag.SYN
        and packet.sequence == HANDSHAKE_SEQUENCE
        and packet.acknowledgment == NO_ACK
        and not packet.payload
    )


def _is_syn_ack(packet: _Packet) -> bool:
    return (
        packet.flags == SYN_ACK_FLAGS
        and packet.sequence == HANDSHAKE_SEQUENCE
        and packet.acknowledgment == HANDSHAKE_SEQUENCE
        and not packet.payload
    )


def _raise_if_peer_aborted(session: RDTSession, packet: _Packet) -> None:
    if packet.flags & PacketFlag.ABORT:
        session.state = TransferState.ABORTED
        raise RDTAborted(_abort_reason(packet))


def _check_local_abort(
    session: RDTSession, abort_event: Optional[threading.Event]
) -> None:
    if abort_event is not None and abort_event.is_set():
        session.state = TransferState.ABORTED
        _send_abort(session, "local transfer aborted")
        raise RDTAborted("local transfer aborted")


def _abort_reason(packet: _Packet) -> str:
    if not packet.payload:
        return "peer aborted transfer"
    return packet.payload.decode("utf-8", "replace")


def _effective_send_window(session: RDTSession) -> int:
    if session.peer_window == 0:
        return 0
    return min(
        max(1, int(session.cwnd)),
        session.peer_window,
        session.config.max_cwnd,
    )


def _increase_congestion_window(session: RDTSession) -> None:
    if session.cwnd < session.ssthresh:
        session.cwnd = min(float(session.config.max_cwnd), session.cwnd + 1.0)
    else:
        session.cwnd = min(
            float(session.config.max_cwnd),
            session.cwnd + (1.0 / max(session.cwnd, 1.0)),
        )


def _decrease_congestion_window(session: RDTSession) -> None:
    session.ssthresh = max(2.0, session.cwnd / 2.0)
    session.cwnd = 1.0


def _update_rto(session: RDTSession, sample_rtt: float) -> None:
    if session._srtt is None or session._rttvar is None:
        session._srtt = sample_rtt
        session._rttvar = sample_rtt / 2.0
    else:
        session._rttvar = 0.75 * session._rttvar + 0.25 * abs(
            session._srtt - sample_rtt
        )
        session._srtt = 0.875 * session._srtt + 0.125 * sample_rtt

    session._rto = min(
        session.config.max_rto,
        max(
            session.config.min_rto,
            session._srtt + max(0.010, 4.0 * session._rttvar),
        ),
    )


def _available_window(
    reorder_buffer: Dict[int, bytes], session: RDTSession
) -> int:
    return max(0, session.config.receive_window - len(reorder_buffer))


def _final_result_linger(session: RDTSession) -> float:
    return max(
        session.config.final_linger,
        session.config.max_rto * (session.config.max_retries + 1),
    )


def _write_all(sink: BinaryIO, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = sink.write(view)
        if written is None:
            raise OSError("destination stream would block")
        if written <= 0:
            raise OSError("destination stream accepted no data")
        view = view[written:]


def _flush_sink(sink: BinaryIO) -> None:
    sink.flush()
    try:
        descriptor = sink.fileno()
    except (AttributeError, io.UnsupportedOperation):
        return
    os.fsync(descriptor)


def _result(session: RDTSession, byte_count: int, digest: bytes) -> TransferResult:
    return TransferResult(
        transfer_id=session.transfer_id,
        peer=session.peer,
        bytes_transferred=byte_count,
        sha256=digest.hex(),
        packets_sent=session.packets_sent,
        packets_received=session.packets_received,
        retransmissions=session.retransmissions,
        duplicate_packets=session.duplicate_packets,
        duration=time.monotonic() - session.started_at,
    )


def _report_progress(
    callback: Optional[ProgressCallback], progress: TransferProgress
) -> None:
    if callback is None:
        return
    try:
        callback(progress)
    except Exception:
        # Progress display errors must not corrupt the binary transport.
        pass


def _matches_peer(
    actual: SocketAddress, expected: Optional[SocketAddress]
) -> bool:
    if expected is None:
        return True
    if actual[0] != expected[0]:
        return False
    return expected[1] in (0, actual[1])


def _clamp_window(window: int, config: RDTConfig) -> int:
    return max(0, min(window, config.max_cwnd))


def _validate_transfer_id(transfer_id: int) -> None:
    if not isinstance(transfer_id, int) or not 1 <= transfer_id <= MAX_TRANSFER_ID:
        raise ValueError("transfer_id must be a non-zero unsigned 64-bit integer")


def _validate_u32(value: int, name: str) -> None:
    if not isinstance(value, int) or not 0 <= value <= NO_ACK:
        raise ValueError("{} must fit in an unsigned 32-bit field".format(name))


def _require_established(session: RDTSession) -> None:
    if session.state != TransferState.ESTABLISHED:
        raise RDTProtocolError(
            "session must be ESTABLISHED before transfer, not {}".format(session.state)
        )


@contextmanager
def _preserve_socket_timeout(sock: socket.socket):
    previous_timeout = sock.gettimeout()
    try:
        yield
    finally:
        sock.settimeout(previous_timeout)


__all__ = [
    "DEFAULT_CONFIG",
    "FIN_METADATA",
    "FIN_RESULT",
    "HEADER",
    "HEADER_SIZE",
    "MAGIC",
    "MAX_PAYLOAD_SIZE",
    "NO_ACK",
    "PacketFlag",
    "RDTAborted",
    "RDTConfig",
    "RDTError",
    "RDTIntegrityError",
    "RDTProtocolError",
    "RDTSession",
    "RDTTimeoutError",
    "TransferProgress",
    "TransferResult",
    "TransferState",
    "establish_udp",
    "new_transfer_id",
    "receive_bytes",
    "receive_file",
    "receive_stream",
    "send_bytes",
    "send_file",
    "send_stream",
    "sha256_file",
]
