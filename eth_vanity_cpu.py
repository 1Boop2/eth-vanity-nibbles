#!/usr/bin/env python3
"""
Ethereum vanity wallet generator (CPU only).

Генерирует случайные приватные ключи, считает публичные ключи через
libsecp256k1 (coincurve), хеширует Keccak-256 на CPU и ищет адреса
с длинными сериями нулевых нибблов в начале и в конце.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import signal
import sys
import threading
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from dataclasses import dataclass
from typing import List, Sequence, Tuple

import numpy as np
from coincurve import PrivateKey, PublicKey

try:
    from eth_hash.auto import keccak as eth_keccak  # type: ignore[attr-defined]
except ImportError as exc:  # pragma: no cover - we fail fast with a hint
    raise SystemExit(
        "Missing dependency 'eth-hash'. Install it via 'pip install \"eth-hash[pycryptodome]\"'."
    ) from exc


# ---------------------------------------------------------------------------
# Default CLI options.
# ---------------------------------------------------------------------------
DEFAULT_CLI = {
    "batch_size": 2048,
    "min_leading": 6,          # по умолчанию 6 слева
    "min_trailing": 6,         # по умолчанию 6 справа
    "min_total_zero_nibbles": 0,
    "target": 0,
    "status_every": 5.0,
    "log_file": None,
    "best_file": "best_wallets.jsonl",
    "workers": 1,
    "prefetch_batches": 1,
    "worker_mode": "process",  # process | thread
    "just_zeros": False,
}

CURVE_ORDER = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
)
GENERATOR_POINT = PrivateKey((1).to_bytes(32, "big")).public_key


@dataclass
class CliConfig:
    batch_size: int
    min_leading: int
    min_trailing: int
    min_total_zero_nibbles: int
    target_matches: int
    status_interval: float
    log_file: str | None
    best_file: str | None
    workers: int
    prefetch_batches: int
    worker_mode: str
    just_zeros: bool


@dataclass
class VanityHit:
    address: str
    leading: int
    trailing: int
    total_zero: int
    private_key_hex: str


def count_leading_zero_nibbles(data: bytes) -> int:
    """Count 4-bit zero chunks from the start of the address."""
    total = 0
    for byte in data:
        high = byte >> 4
        if high == 0:
            total += 1
        else:
            return total
        low = byte & 0x0F
        if low == 0:
            total += 1
        else:
            return total
    return total


def count_trailing_zero_nibbles(data: bytes) -> int:
    """Count 4-bit zero chunks from the end of the address."""
    total = 0
    for byte in reversed(data):
        low = byte & 0x0F
        if low == 0:
            total += 1
        else:
            return total
        high = byte >> 4
        if high == 0:
            total += 1
        else:
            return total
    return total


def keccak_bytes(data: bytes) -> bytes:
    return bytes(eth_keccak(data))


def checksum_address(addr_bytes: bytes) -> str:
    """Return the EIP-55 checksum representation."""
    hex_body = addr_bytes.hex()
    digest = keccak_bytes(hex_body.encode("ascii")).hex()
    checksum_chars = ["0", "x"]
    for idx, char in enumerate(hex_body):
        if char.isdigit():
            checksum_chars.append(char)
            continue
        checksum_chars.append(char.upper() if int(digest[idx], 16) >= 8 else char)
    return "".join(checksum_chars)


def count_total_zero_nibbles(data: bytes) -> int:
    total = 0
    for byte in data:
        if (byte >> 4) == 0:
            total += 1
        if (byte & 0x0F) == 0:
            total += 1
    return total


def _generate_chunk_impl(count: int) -> Tuple[List[bytes], np.ndarray]:
    privs: List[bytes] = []
    pubs = np.empty((count, 64), dtype=np.uint8)
    if count == 0:
        return privs, pubs
    priv_int = 0
    while priv_int == 0:
        priv_int = int.from_bytes(os.urandom(32), "big") % CURVE_ORDER
    priv_bytes = priv_int.to_bytes(32, "big")
    while True:
        try:
            current_pub = PrivateKey(priv_bytes).public_key
            break
        except Exception:
            priv_int = (priv_int + 1) % CURVE_ORDER or 1
            priv_bytes = priv_int.to_bytes(32, "big")
    generator = GENERATOR_POINT
    for idx in range(count):
        priv_bytes = priv_int.to_bytes(32, "big")
        privs.append(priv_bytes)
        pubs[idx] = np.frombuffer(current_pub.format(False)[1:], dtype=np.uint8)
        priv_int = (priv_int + 1) % CURVE_ORDER or 1
        try:
            current_pub = PublicKey.combine_keys([current_pub, generator])
        except Exception:
            priv_int = 0
            while priv_int == 0:
                priv_int = int.from_bytes(os.urandom(32), "big") % CURVE_ORDER
            priv_bytes = priv_int.to_bytes(32, "big")
            current_pub = PrivateKey(priv_bytes).public_key
    return privs, pubs


class CPUHasher:
    """Hashing implementation (Keccak-256) on CPU."""

    def hash(self, pubkeys: np.ndarray) -> np.ndarray:
        out = np.empty((pubkeys.shape[0], 32), dtype=np.uint8)
        for idx, row in enumerate(pubkeys):
            digest = keccak_bytes(row.tobytes())
            out[idx] = np.frombuffer(digest, dtype=np.uint8)
        return out


class KeyBatchGenerator:
    """Generates random private/public keypairs, optionally in parallel."""

    def __init__(self, workers: int, mode: str):
        self.workers = max(1, workers)
        self.mode = mode
        self._executor = None
        if self.workers > 1:
            if mode == "process":
                self._executor = ProcessPoolExecutor(max_workers=self.workers)
            else:
                self._executor = ThreadPoolExecutor(max_workers=self.workers)

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        if self._executor is not None:
            self._executor.shutdown(wait=True)
            self._executor = None

    def next_batch(self, size: int) -> Tuple[List[bytes], np.ndarray]:
        if size <= 0:
            return [], np.empty((0, 64), dtype=np.uint8)
        if self.workers == 1 or self._executor is None:
            return _generate_chunk_impl(size)

        chunk = size // self.workers
        remainder = size % self.workers
        futures = []
        for worker_idx in range(self.workers):
            portion = chunk + (1 if worker_idx < remainder else 0)
            if portion == 0:
                continue
            futures.append(self._executor.submit(_generate_chunk_impl, portion))

        privs: List[bytes] = []
        pub_chunks: List[np.ndarray] = []
        for future in futures:
            part_privs, part_pubs = future.result()
            privs.extend(part_privs)
            pub_chunks.append(part_pubs)
        pubs = np.vstack(pub_chunks) if pub_chunks else np.empty((0, 64), dtype=np.uint8)
        return privs, pubs


def compute_pair_score(leading: int, trailing: int) -> int:
    """
    Метрика "лучшего" адреса для режима по краям.

    1) Максимизируем min(leading, trailing) — баланс нулей с каждой стороны.
    2) При равном min — максимизируем (leading + trailing).

    Пример:
      (2, 8): min=2, total=10  -> score=2*100 + 10 = 210
      (3, 6): min=3, total=9   -> score=3*100 + 9  = 309  => лучше
    """
    balanced = min(leading, trailing)
    total = leading + trailing
    return balanced * 100 + total


def parse_args(argv: Sequence[str]) -> CliConfig:
    parser = argparse.ArgumentParser(
        description="CPU-only Ethereum vanity wallet generator"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_CLI["batch_size"],
        help="keys per iteration",
    )
    parser.add_argument(
        "--min-leading",
        type=int,
        default=DEFAULT_CLI["min_leading"],
        help="minimum leading zero nibbles (4 bits) required to log a hit",
    )
    parser.add_argument(
        "--min-trailing",
        type=int,
        default=DEFAULT_CLI["min_trailing"],
        help="minimum trailing zero nibbles required to log a hit",
    )
    parser.add_argument(
        "--min-total-zeros",
        type=int,
        default=DEFAULT_CLI["min_total_zero_nibbles"],
        help="minimum total zero nibbles anywhere in the address to log a hit",
    )
    parser.add_argument(
        "--target",
        type=int,
        default=DEFAULT_CLI["target"],
        help="stop after this many matches (<=0 keeps running)",
    )
    parser.add_argument(
        "--status-every",
        type=float,
        default=DEFAULT_CLI["status_every"],
        help="seconds between status updates",
    )
    parser.add_argument(
        "--log-file",
        type=str,
        default=DEFAULT_CLI["log_file"],
        help="optional JSONL file to append every hit",
    )
    parser.add_argument(
        "--best-file",
        type=str,
        default=DEFAULT_CLI["best_file"],
        help="JSONL path that records every time a new best lead+trail score is discovered",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_CLI["workers"],
        help="CPU threads for key generation (default: all cores)",
    )
    parser.add_argument(
        "--prefetch-batches",
        type=int,
        default=DEFAULT_CLI["prefetch_batches"],
        help="How many prepared batches to keep queued (set to 1 to disable prefetch).",
    )
    parser.add_argument(
        "--worker-mode",
        choices=("thread", "process"),
        default=DEFAULT_CLI["worker_mode"],
        help="Parallelization strategy for key generation workers.",
    )
    parser.add_argument(
        "--justzeros",
        action="store_true",
        default=DEFAULT_CLI["just_zeros"],
        help="Evaluate only the total number of zero nibbles (ignore leading/trailing thresholds).",
    )

    args = parser.parse_args(argv)
    if args.batch_size <= 0:
        parser.error("batch-size must be positive")
    if args.min_leading < 0 or args.min_trailing < 0:
        parser.error("zero requirements must be >= 0")
    if args.workers <= 0:
        parser.error("workers must be >= 1")

    return CliConfig(
        batch_size=args.batch_size,
        min_leading=args.min_leading,
        min_trailing=args.min_trailing,
        min_total_zero_nibbles=max(0, args.min_total_zeros),
        target_matches=args.target,
        status_interval=args.status_every,
        log_file=args.log_file,
        best_file=args.best_file if args.best_file else None,
        workers=args.workers,
        prefetch_batches=max(1, args.prefetch_batches),
        worker_mode=args.worker_mode,
        just_zeros=args.justzeros,
    )


def log_hit(hit: VanityHit, log_file: str | None) -> None:
    line = (
        f"[{time.strftime('%H:%M:%S')}] {hit.address} "
        f"(lead={hit.leading}, trail={hit.trailing}, total={hit.total_zero})"
    )
    print(line)
    print(f"  priv: {hit.private_key_hex}")
    if log_file:
        payload = {
            "address": hit.address,
            "leading_zero_nibbles": hit.leading,
            "trailing_zero_nibbles": hit.trailing,
            "total_zero_nibbles": hit.total_zero,
            "private_key_hex": hit.private_key_hex,
            "timestamp": time.time(),
        }
        with open(log_file, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload) + "\n")


def record_best(
    best_file: str | None,
    hit: VanityHit,
    score: int,
) -> None:
    if not best_file:
        return
    payload = {
        "address": hit.address,
        "private_key_hex": hit.private_key_hex,
        "leading_zero_nibbles": hit.leading,
        "trailing_zero_nibbles": hit.trailing,
        "total_zero_nibbles": hit.total_zero,
        "score": score,
        "timestamp": time.time(),
    }
    with open(best_file, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload) + "\n")


def load_previous_best(
    best_file: str | None, just_zeros: bool
) -> Tuple[int, Tuple[int, int], int, VanityHit | None]:
    if not best_file or not os.path.exists(best_file):
        return 0, (0, 0), 0, None

    best_score = 0
    best_pair = (0, 0)
    best_total = 0
    best_wallet: VanityHit | None = None

    try:
        with open(best_file, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                leading = int(data.get("leading_zero_nibbles", 0) or 0)
                trailing = int(data.get("trailing_zero_nibbles", 0) or 0)
                total_zero = data.get("total_zero_nibbles")
                if total_zero is None:
                    total_zero = leading + trailing
                total_zero = int(total_zero)

                if just_zeros:
                    score = total_zero
                else:
                    score = compute_pair_score(leading, trailing)

                if score > best_score:
                    best_score = score
                    best_pair = (leading, trailing)
                    best_total = total_zero
                    best_wallet = VanityHit(
                        address=data.get("address", ""),
                        leading=leading,
                        trailing=trailing,
                        total_zero=total_zero,
                        private_key_hex=data.get("private_key_hex", "")
                    )
    except OSError:
        return 0, (0, 0), 0, None

    return best_score, best_pair, best_total, best_wallet


def main(argv: Sequence[str] | None = None) -> int:
    config = parse_args(argv or sys.argv[1:])
    keygen = KeyBatchGenerator(config.workers, config.worker_mode)
    stop_event = threading.Event()

    def _graceful_stop(signum, frame):  # pragma: no cover - signal handler
        print(f"\nReceived signal {signum}, finishing current batch...")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, _graceful_stop)

    hasher = CPUHasher()
    print("Using CPU hashing only.")

    matches = 0
    (
        best_score,
        best_pair,
        best_total,
        best_wallet,
    ) = load_previous_best(config.best_file, config.just_zeros)
    if best_score > 0 and config.best_file:
        if config.just_zeros:
            print(
                f"Resuming best_total={best_total} nibbles from {config.best_file}"
            )
        else:
            print(
                f"Resuming best={best_pair[0]}+{best_pair[1]} nibbles from {config.best_file}"
            )
    processed = 0
    start_time = time.time()
    last_status = start_time

    use_prefetch = config.prefetch_batches > 1
    sentinel = object()
    batch_queue: queue.SimpleQueue | None = None
    slot_sem: threading.Semaphore | None = None
    producer_thread: threading.Thread | None = None

    def release_slot() -> None:
        if slot_sem is not None:
            slot_sem.release()

    if use_prefetch:
        batch_queue = queue.SimpleQueue()
        slot_sem = threading.Semaphore(config.prefetch_batches)

        def producer() -> None:
            try:
                while not stop_event.is_set():
                    if not slot_sem.acquire(timeout=0.1):  # type: ignore[attr-defined]
                        continue
                    priv_batch, pub_batch = keygen.next_batch(config.batch_size)
                    if not priv_batch:
                        slot_sem.release()
                        continue
                    batch_queue.put((priv_batch, pub_batch))
            finally:
                batch_queue.put(sentinel)

        producer_thread = threading.Thread(target=producer, daemon=True)
        producer_thread.start()

    def fetch_batch() -> Tuple[List[bytes], np.ndarray] | None:
        if batch_queue is None:
            if stop_event.is_set():
                return None
            priv_batch, pub_batch = keygen.next_batch(config.batch_size)
            if not priv_batch:
                return None
            return priv_batch, pub_batch
        item = batch_queue.get()
        if item is sentinel:
            batch_queue.put(sentinel)
            return None
        return item

    try:
        while not stop_event.is_set():
            batch = fetch_batch()
            if batch is None:
                break
            priv_batch, pub_batch = batch
            try:
                digests = hasher.hash(pub_batch)
                for idx, digest in enumerate(digests):
                    address_bytes = bytes(digest[12:])  # take last 20 bytes
                    leading = count_leading_zero_nibbles(address_bytes)
                    trailing = count_trailing_zero_nibbles(address_bytes)
                    total_zero = count_total_zero_nibbles(address_bytes)

                    if config.just_zeros:
                        score = total_zero
                    else:
                        score = compute_pair_score(leading, trailing)

                    priv_bytes = priv_batch[idx]
                    if score > best_score:
                        best_score = score
                        best_pair = (leading, trailing)
                        best_total = total_zero
                        best_wallet = VanityHit(
                            address=checksum_address(address_bytes),
                            leading=leading,
                            trailing=trailing,
                            total_zero=total_zero,
                            private_key_hex=priv_bytes.hex(),
                        )
                        record_best(config.best_file, best_wallet, score)

                    if config.just_zeros:
                        threshold = config.min_total_zero_nibbles or 1
                        meets_total = total_zero >= threshold
                        meets_leading_trailing = False
                    else:
                        meets_total = (
                            config.min_total_zero_nibbles > 0
                            and total_zero >= config.min_total_zero_nibbles
                        )
                        meets_leading_trailing = (
                            leading >= config.min_leading
                            and trailing >= config.min_trailing
                        )

                    if meets_leading_trailing or meets_total:
                        hit = VanityHit(
                            address=checksum_address(address_bytes),
                            leading=leading,
                            trailing=trailing,
                            total_zero=total_zero,
                            private_key_hex=priv_bytes.hex(),
                        )
                        log_hit(hit, config.log_file)
                        matches += 1
                        if 0 < config.target_matches <= matches:
                            stop_event.set()
                            break

                processed += len(priv_batch)
                now = time.time()
                if now - last_status >= config.status_interval:
                    elapsed = now - start_time
                    rate = processed / elapsed if elapsed else 0.0
                    if config.just_zeros:
                        best_desc = f"best_total={best_total} nibbles"
                    else:
                        best_desc = (
                            f"best={best_pair[0]}+{best_pair[1]} nibbles"
                        )
                    print(
                        f"[{time.strftime('%H:%M:%S')}] scanned={processed:,} "
                        f"rate={rate:,.2f} keys/s {best_desc}"
                    )
                    last_status = now
            finally:
                release_slot()

    finally:
        stop_event.set()
        keygen.close()
        if producer_thread is not None:
            producer_thread.join()

    print(f"Done. Matches found: {matches}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
