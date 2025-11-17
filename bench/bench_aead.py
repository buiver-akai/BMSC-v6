# bench/bench_aead.py

import time, secrets
from pathlib import Path
import sys

# Import path setup (project root = one level up from this file)
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bmsc_v6_prod import bmsc_v6_encrypt, bmsc_v6_decrypt  # AEAD core

def bench_once(size_bytes: int, rounds: int = 5):
    """Return (enc_ms, dec_ms) average for random plaintext of size_bytes."""
    key = secrets.token_bytes(32)
    ctx = b"BMSCv6-IV00"
    aad = b""

    pt = secrets.token_bytes(size_bytes)

    # Warmup
    n, c, t = bmsc_v6_encrypt(pt, key, ctx, aad=aad)
    _ = bmsc_v6_decrypt(n, c, t, key, ctx, aad=aad)

    # Encrypt
    t0 = time.perf_counter()
    for _ in range(rounds):
        n, c, t = bmsc_v6_encrypt(pt, key, ctx, aad=aad)
    t1 = time.perf_counter()

    # Decrypt
    t2 = time.perf_counter()
    for _ in range(rounds):
        _ = bmsc_v6_decrypt(n, c, t, key, ctx, aad=aad)
    t3 = time.perf_counter()

    enc_ms = (t1 - t0) * 1000 / rounds
    dec_ms = (t3 - t2) * 1000 / rounds
    return enc_ms, dec_ms

def human_mib_per_s(size_bytes: int, ms: float) -> float:
    mib = size_bytes / (1024 * 1024)
    sec = ms / 1000.0
    return mib / sec if sec > 0 else float('inf')

def main():
    sizes = [1 * 1024 * 1024, 8 * 1024 * 1024]  # 1MiB, 8MiB
    rounds = 5
    print(f"Benchmark: XChaCha20-Poly1305 via bmsc_v6_prod (rounds={rounds})")
    for sz in sizes:
        enc_ms, dec_ms = bench_once(sz, rounds=rounds)
        enc_spd = human_mib_per_s(sz, enc_ms)
        dec_spd = human_mib_per_s(sz, dec_ms)
        print(
            f"- {sz//(1024*1024)} MiB: "
            f"enc {enc_ms:.2f} ms ({enc_spd:.1f} MiB/s), "
            f"dec {dec_ms:.2f} ms ({dec_spd:.1f} MiB/s)"
        )

if __name__ == "__main__":
    main()
