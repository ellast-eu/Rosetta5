# Rosetta5

Rosetta5 is an automated decryption utility designed to analyze and decompose character strings subjected to multi-layer encryption. Unlike simple decoders, this script is capable of recursively detecting and reversing up to 5 levels of nested encoding, while managing a vast library of transformation algorithms.

```console
$ rosetta5 'GNSDGZBWG42WCMZQGRQTKNZWGU3DONBZGU4DMNBWMU2DENJTGU4TGMRUGI2TGNJZG44TINRVHA3DGMZSGU3DIOBUHE3GINLBGQ4DIOJXHA2TMNTEGU4TOMJVME3GINLBG42TIZJUG42DSNZZGU3DGMZVGI======'
5 layers peeled off:
  [1] Base32           → 3d3d675a304a5765674958646e4253593242535979465863325648496d5a484…
  [2] Hexadecimal      → ==gZ0JWegIXdnBSY2BSYyFXc2VHImZHIxVmYqZmZuNGIyV3R
  [3] Reversed string  → R3VyIGNuZmZqYmVxIHZmIHV2cXFyYSB2YSBndXIgeWJ0Zg==
  [4] Base64           → Gur cnffjbeq vf uvqqra va gur ybtf
  [5] ROT13            → The password is hidden in the logs

Result:
The password is hidden in the logs
```

## Install

One file, standard library only, Python 3.9+.

```sh
git clone https://github.com/ellast-eu/Rosetta5.git
cd Rosetta5
chmod +x rosetta5.py
ln -s "$PWD/rosetta5.py" ~/.local/bin/rosetta5     # optional
```

## Usage

```sh
rosetta5 'aGVsbG8gd29ybGQ='          # string as argument
echo 'aGVsbG8gd29ybGQ=' | rosetta5   # or on stdin
rosetta5 -f challenge.txt            # or from a file (text or binary)
```

| Option | Effect |
| --- | --- |
| `-d N`, `--depth N` | maximum number of layers (default 5, max 8) |
| `-n N`, `--top N` | show the N best candidates instead of one |
| `-k KEY`, `--key KEY` | key to try for Vigenère and repeating-key XOR; text or `0xHEX`; repeatable |
| `--flag REGEX` | shape of the expected plaintext, e.g. `--flag 'HTB\{.*\}'` |
| `--only LIST` / `--exclude LIST` | restrict or disable transformations (names from `--list`) |
| `-e CHAIN`, `--encode CHAIN` | encode instead of decoding, e.g. `-e 'rot13,base64,hex'` |
| `-q`, `--quiet` | print only the plaintext (for pipes) |
| `-v`, `--verbose` | do not truncate intermediate values |
| `--json` | machine-readable output |
| `-l`, `--list` | list the supported transformations |
| `--timeout S` | search time budget in seconds (default 20) |

Exit status: `0` at least one layer was removed, `1` nothing to decode, `2` error.

## Supported transformations

**Encodings** — Base64, Base64 URL-safe, Base32, Base32hex, hexadecimal (plain, spaced, `0x..`, `\x..`), binary (8 or 7 bits), octal, decimal, Ascii85, Base85 (RFC 1924), Z85, Base58, Base62, Base45, basE91, URL encoding, HTML entities, quoted-printable, Unicode escapes (`\uXXXX`, `%uXXXX`, `U+XXXX`), uuencode.

**Symbol alphabets** — Morse, Bacon, A1Z26, Polybius square, NATO phonetic alphabet, multi-tap phone keypad, Braille.

**Binary layers** — gzip, zlib, raw DEFLATE, bzip2, XZ/LZMA, UTF-16.

**Ciphers** — Caesar / ROT-N (all 25 shifts, ROT13 included), ROT47, Atbash, reversed string, rail fence (2 to 5 rails), single-byte XOR (brute force), Vigenère and repeating-key XOR (with `-k`).

## How it works

1. **Breadth-first search.** Every transformation is tried on the input, then on every result, down to the depth limit. Decoders are strict: Base64 must be canonical, hex must have an even length, and so on, which keeps the tree small.
2. **Scoring.** Each readable result gets a score: a small English/French language model (letter pairs and common words, embedded in the script) plus the evidence gathered along the path. A strict decoding that succeeds earns credit; every cipher guess costs some, in proportion to the number of alternatives tried. The best score wins.
3. **No false heroics.** If the input already is the most plausible text, Rosetta5 says so instead of "decoding" `password` into noise.

Limits worth knowing:

- Plaintext is recognised as English, French or a CTF-style flag (`flag{...}`, `HTB{...}`, …). For anything else, give the shape with `--flag`.
- Without a recognisable plaintext, ciphers cannot be told apart: a random token wrapped in ROT13 then Base64 comes back as the ROT13 text.
- Single-byte XOR is searched as the innermost layer, right under a byte-level encoding (Base64, hex, …) or on binary input.
- Morse, Bacon, A1Z26, Polybius, NATO and multi-tap lose case; Bacon also loses spaces.
- Modern encryption (AES, RSA, …) and hashes are out of scope: a hash is returned as is.

## As a library

```python
import rosetta5

result = rosetta5.decode("NjE3NDc0NjE2MzZiMjA2MTc0MjA2NDYxNzc2ZQ==")
print(result.best.text)                              # attack at dawn
print([step.label for step in result.best.chain()])  # ['Base64', 'Hexadecimal']
```

## Tests

```sh
python3 -m unittest -v
```

The suite checks every codec, hand-written multi-layer cases, 120 random chains of 1 to 5 layers, and that plain text and random tokens are left alone.

## License

GPL-3.0, see [LICENSE](LICENSE).
