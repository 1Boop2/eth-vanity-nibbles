# Ethereum Vanity Address Generator (CPU-only, balanced zeros)

This tool brute-forces Ethereum addresses and looks for **long runs of zero nibbles at both the beginning and the end** of the address.

Unlike many vanity generators that only maximize the *total* number of leading/trailing zeros, this one is tuned to search for **balanced patterns** like:

- `0x000000ab...cd000000` (6+6)
- And treat `3+6` as **better** than `2+8`, even though `2+8` has more total zeros.

The generator is **CPU-only** and uses:

- [`coincurve`](https://github.com/ofek/coincurve) for secp256k1 keys
- [`eth-hash`](https://github.com/ethereum/eth-hash) for Keccak-256
- `numpy` for array handling


## How it works

For each batch of randomly generated private keys:

1. Derive the uncompressed public key (64 bytes: X || Y).
2. Compute `Keccak-256(pubkey)` (Ethereum-style, **no prefix**).
3. Take the last 20 bytes as the Ethereum address.
4. Count:
   - `leading_zero_nibbles` — how many 4-bit zero chunks from the **left**.
   - `trailing_zero_nibbles` — how many from the **right**.
   - `total_zero_nibbles`  — total zero nibbles anywhere in the address.
5. Evaluate a **score**:

   ```text
   balanced = min(leading, trailing)
   total    = leading + trailing
   score    = balanced * 100 + total
   ```

   So:

   - `(2, 8) → min = 2, total = 10 → score = 210`
   - `(3, 6) → min = 3, total = 9  → score = 309  (better)`

6. The best score is tracked across the run and can be resumed from a JSONL file.


## Features

- CPU-only, no GPU / CUDA / CuPy dependency.
- Customizable thresholds for:
  - Minimal leading/trailing zero nibbles.
  - Minimal total zero nibbles.
- Two scoring modes:
  - **Balanced edges** (default) — maximize `min(leading, trailing)` first.
  - **Total zeros only** – via `--justzeros`.
- Resumable “best so far” via `best_wallets.jsonl`.
- Optional logging of every hit into a JSONL log file.
- Batched generation with prefetching in a separate thread/process.


## Installation

```bash
git clone https://github.com/1Boop2/eth-vanity-nibbles.git
cd eth-vanity-nibbles

python3 -m venv .venv
source .venv/bin/activate  # on Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

Example `requirements.txt`:

```txt
coincurve
eth-hash[pycryptodome]
numpy
```

You also need Python 3.10+ (recommended).


## Usage

Assume the script file is called `vanity_gen_cpu.py`:

```bash
python3 vanity_gen_cpu.py
```

By default it:

- Uses a batch size of `2048` keys.
- Requires at least **6 leading** and **6 trailing** zero nibbles to log a hit.
- Writes “best so far” to `best_wallets.jsonl`.
- Prints status every 5 seconds.


### Example: search for at least 6+6 zeros on edges

```bash
python3 vanity_gen_cpu.py \
  --min-leading 6 \
  --min-trailing 6 \
  --target 3 \
  --log-file hits.jsonl
```

This will:

- Log every hit with `lead >= 6` **and** `trail >= 6`.
- Stop after 3 matches (`--target 3`).
- Append all hits to `hits.jsonl` in JSONL format.


### Example: search for addresses with many zeros anywhere

If you only care about the total number of zero nibbles (not necessarily aligned on edges):

```bash
python3 vanity_gen_cpu.py \
  --justzeros \
  --min-total-zeros 20 \
  --target 5 \
  --log-file hits_justzeros.jsonl
```

In this mode:

- Scoring is `score = total_zero_nibbles`.
- `--min-leading` / `--min-trailing` thresholds are ignored for logging.
- `--min-total-zeros` defines what is considered a hit.


## Command-line options

| Option              | Type    | Default             | Description |
|---------------------|---------|---------------------|-------------|
| `--batch-size`      | int     | `2048`              | Number of keys per iteration. Larger batches = fewer status updates / I/O. |
| `--min-leading`     | int     | `6`                 | Minimum number of leading zero nibbles required to log a hit (unless `--justzeros`). |
| `--min-trailing`    | int     | `6`                 | Minimum number of trailing zero nibbles required to log a hit (unless `--justzeros`). |
| `--min-total-zeros` | int     | `0`                 | Minimum total zero nibbles anywhere in the address to log a hit. |
| `--target`          | int     | `0`                 | Stop after this many matches (`<= 0` = run indefinitely). |
| `--status-every`    | float   | `5.0`               | Seconds between status prints. |
| `--log-file`        | str     | `None`              | Path to JSONL file where every hit is appended. |
| `--best-file`       | str     | `best_wallets.jsonl`| JSONL file that stores every time a new best score is found. Used to resume. |
| `--workers`         | int     | `1`                 | Number of CPU workers for key generation. |
| `--prefetch-batches`| int     | `1`                 | How many prepared batches to keep in a queue (`1` disables prefetching). |
| `--worker-mode`     | choice  | `process`           | Parallelization strategy for key generation: `process` or `thread`. |
| `--justzeros`       | flag    | `False`             | If set, only total zero nibbles are used for scoring and logging. |


## Output format

### Console

For every hit:

```text
[12:34:56] 0x000000ab...cd000000 (lead=6, trail=6, total=18)
  priv: 0123abcd...ef
```

- `lead` and `trail` are zero nibbles at the edges.
- `total` counts zero nibbles anywhere in the 20-byte address.


### Log file (`--log-file`)

Each line is a JSON object, for example:

```json
{
  "address": "0x000000ab...cd000000",
  "leading_zero_nibbles": 6,
  "trailing_zero_nibbles": 6,
  "total_zero_nibbles": 18,
  "private_key_hex": "0123abcd...ef",
  "timestamp": 1712345678.123
}
```


### Best file (`--best-file`)

`best_wallets.jsonl` keeps a history of incremental improvements of the best score:

```json
{
  "address": "0x000000ab...cd000000",
  "private_key_hex": "0123abcd...ef",
  "leading_zero_nibbles": 6,
  "trailing_zero_nibbles": 6,
  "total_zero_nibbles": 18,
  "score": 306,
  "timestamp": 1712345678.123
}
```

On startup, the script reads this file (if it exists) and resumes from the best score it finds.


## Performance tips

- Increase `--batch-size` for better throughput (at the cost of memory and latency).
- Use `--workers N` and `--worker-mode process` to generate keys in parallel on multi-core CPUs.
- `--prefetch-batches > 1` hides key-generation latency behind hashing.
- Avoid writing to log files on every single batch if you only need the best address; the `best_file` is much lighter.


## Disclaimer

This project is purely a **research / educational** tool around vanity address generation.  
Use at your own risk and always keep private keys secret and offline.
