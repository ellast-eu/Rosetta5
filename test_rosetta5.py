#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Test suite for Rosetta5.

Run with:  python3 -m unittest -v        (or: pytest)
"""
import io
import json
import random
import unittest
from contextlib import redirect_stdout

import rosetta5 as r

SENTENCES = [
    "The password is hidden in the logs",
    "meet me at midnight near the old bridge",
    "Bonjour tout le monde, voici le message secret",
    "flag{n3st3d_l4y3rs_4r3_fun}",
    "HTB{r0s3tt4_st0n3_d3c0d3d}",
    "attack at dawn and bring the documents with you",
    "Le mot de passe du serveur est dans le fichier de configuration",
    "congratulations, you have successfully decoded the message",
]

# Encoders that accept and produce anything a later layer can swallow.
BYTE_SAFE = ["base64", "base64url", "base32", "base32hex", "hex", "binary",
             "octal", "ascii85", "base85", "base58", "base62", "base45",
             "base91", "url", "qp", "uuencode"]
TEXT_ONLY = ["decimal", "html", "unicode"]
COMPRESSION = ["gzip", "zlib", "deflate", "bzip2", "xz"]     # binary output
CIPHERS = {"sub": ["rot13", "caesar:{n}", "rot47", "atbash"],
           "reverse": ["reverse"], "rail": ["railfence:{r}"]}
LOSSY = ["morse", "bacon", "a1z26", "polybius", "nato", "multitap"]


def normalise(text):
    return " ".join((text or "").split()).casefold()


def random_chain(rng, depth):
    """Build a chain that Rosetta5 is designed to reverse."""
    chain, run, binary = [], set(), False
    for _ in range(depth):
        if binary:                              # must become text again
            choice, run, binary = rng.choice(BYTE_SAFE), set(), False
        else:
            kinds = ["safe"] * 5 + ["text"] + ["zip"] + ["cipher"] * 3
            kind = rng.choice(kinds)
            groups = [g for g in CIPHERS if g not in run]
            if kind == "cipher" and groups:
                group = rng.choice(groups)
                choice = rng.choice(CIPHERS[group]).format(
                    n=rng.choice([1, 3, 5, 7, 11, 17, 21, 25]), r=rng.randint(2, 5))
                run.add(group)
            elif kind == "zip":
                choice, run, binary = rng.choice(COMPRESSION), set(), True
            elif kind == "text":
                choice, run = rng.choice(TEXT_ONLY), set()
            else:
                choice, run = rng.choice(BYTE_SAFE), set()
        chain.append(choice)
    if binary:                                  # never end on raw bytes
        chain[-1] = rng.choice(BYTE_SAFE)
    return ",".join(chain)


class RoundTrip(unittest.TestCase):
    """Every codec must reverse what its own encoder produces."""

    def check(self, spec, plain, **options):
        encoded = r.encode_chain(plain.encode(), spec)
        result = r.decode(encoded, **options)
        self.assertEqual(normalise(result.best.text), normalise(plain),
                         f"{spec}: got {result.best.text!r} via "
                         f"{[n.label for n in result.best.chain()]}")
        return result

    def test_single_layer_encodings(self):
        plain = "The quick brown fox jumps over the lazy dog"
        for name in BYTE_SAFE + TEXT_ONLY + ["braille"]:
            with self.subTest(codec=name):
                result = self.check(name, plain)
                self.assertEqual(len(result.best.chain()), 1)
                # Without '-' or '_' a URL-safe Base64 string is plain Base64.
                expected = {"base64url": "base64"}.get(name, name)
                self.assertEqual(result.best.chain()[0].codec, expected)

    def test_z85(self):
        self.check("z85", "exactly thirty two bytes of text")

    def test_compression_inside_base64(self):
        for name in COMPRESSION:
            with self.subTest(codec=name):
                result = self.check(f"{name},base64", "compressed payload, then encoded")
                self.assertEqual([n.codec for n in result.best.chain()],
                                 ["base64", name])

    def test_utf16_powershell_style(self):
        self.check("utf16,base64", "Write-Host 'hello from an encoded command'")

    def test_lossy_alphabets(self):
        plain = "hello world this is a secret message"
        for name in LOSSY:
            with self.subTest(codec=name):
                if name == "bacon":             # Bacon has no word separator
                    encoded = r.encode_chain(plain.encode(), name)
                    self.assertEqual(r.decode(encoded).best.text,
                                     plain.replace(" ", "").upper())
                else:
                    self.check(name, plain)

    def test_ciphers(self):
        plain = "we are discovered, flee at once before they find the secret"
        for spec in ["rot13", "caesar:3", "caesar:19", "rot47", "atbash",
                     "reverse", "railfence:2", "railfence:3", "railfence:5"]:
            with self.subTest(cipher=spec):
                self.check(spec, plain)

    def test_cipher_combinations(self):
        plain = "the answer is written somewhere in the logs"
        for spec in ["reverse,rot13", "rot13,reverse", "railfence:3,caesar:5",
                     "caesar:5,railfence:3,reverse"]:
            with self.subTest(chain=spec):
                self.check(spec, plain)

    def test_single_byte_xor(self):
        self.check("xor:0x2a,base64", "this is the secret message you were looking for")
        self.check("xor:0x5f,hex", "flag{x0r_1s_fun}")
        self.check("xor:0x13,base32", "single byte xor is not encryption")

    def test_keys(self):
        self.check("vigenere:lemon,base64", "attack at dawn with everything we have",
                   keys=["lemon"])
        self.check("xor:s3cr3t,hex", "repeating key xor needs the key to be given",
                   keys=["s3cr3t"])
        self.check("xor:0xdeadbeef,base64", "the key can also be given as hex bytes",
                   keys=["0xdeadbeef"])

    def test_hex_variants(self):
        for encoded in ["68 65 6c 6c 6f 20 77 6f 72 6c 64",
                        "68:65:6c:6c:6f:20:77:6f:72:6c:64",
                        "0x68 0x65 0x6c 0x6c 0x6f 0x20 0x77 0x6f 0x72 0x6c 0x64",
                        "\\x68\\x65\\x6c\\x6c\\x6f\\x20\\x77\\x6f\\x72\\x6c\\x64",
                        "0x68656c6c6f20776f726c64", "68656C6C6F20776F726C64"]:
            with self.subTest(encoded=encoded):
                self.assertEqual(r.decode(encoded).best.text, "hello world")

    def test_other_notations(self):
        cases = {
            "0110100001100101011011000110110001101111": "hello",
            "1101000 1100101 1101100 1101100 1101111": "hello",
            "\\150\\145\\154\\154\\157 ": "hello",
            "<~BOu!rD]j7BEbo7~>": "hello world",
            "hello%20world%21": "hello world!",
            "caf&eacute; &amp; cr&egrave;me": "café & crème",
            "U+0068 U+0065 U+006C U+006C U+006F": "hello",
            "aGVsbG8gd29ybGQ": "hello world",                  # missing padding
            "aGVsbG8g\nd29ybGQ=": "hello world",               # wrapped
            ".... . .-.. .-.. --- / .-- --- .-. .-.. -..": "HELLO WORLD",
        }
        for encoded, plain in cases.items():
            with self.subTest(encoded=encoded):
                self.assertEqual(r.decode(encoded).best.text, plain)


class Layers(unittest.TestCase):
    def test_five_layers(self):
        spec = "base64,base64,base64,base64,base64"
        encoded = r.encode_chain(b"flag{f1v3_l4y3rs_d33p}", spec)
        best = r.decode(encoded).best
        self.assertEqual(best.text, "flag{f1v3_l4y3rs_d33p}")
        self.assertEqual(best.depth, 5)

    def test_mixed_five_layers(self):
        spec = "hex,reverse,base64,rot13,base32"
        encoded = r.encode_chain(b"The password is hidden in the logs", spec)
        best = r.decode(encoded).best
        self.assertEqual(best.text, "The password is hidden in the logs")
        self.assertEqual([n.codec for n in best.chain()],
                         ["base32", "caesar", "base64", "reverse", "hex"])

    def test_depth_limit_is_respected(self):
        encoded = r.encode_chain(b"too deep for a shallow search", "hex,hex,hex")
        self.assertEqual(r.decode(encoded, max_depth=3).best.text,
                         "too deep for a shallow search")
        self.assertNotEqual(r.decode(encoded, max_depth=2).best.text,
                            "too deep for a shallow search")

    def test_random_chains(self):
        rng = random.Random(5)
        failures = []
        total = 120
        for i in range(total):
            plain = rng.choice(SENTENCES)
            spec = random_chain(rng, rng.randint(1, 5))
            encoded = r.encode_chain(plain.encode(), spec)
            if len(encoded) > 20000:
                continue
            best = r.decode(encoded).best
            if normalise(best.text) != normalise(plain):
                failures.append((spec, plain, best.text))
        self.assertFalse(failures, f"{len(failures)}/{total} failed: {failures[:5]}")


class NoFalsePositive(unittest.TestCase):
    """Plain input must be returned untouched."""

    PLAIN = [
        "Hello world", "password", "test", "admin", "root", "hunter2",
        "The quick brown fox", "Bonjour à tous", "HELLO WORLD", "deadbeef",
        "P@ssw0rd!", "azerty123", "こんにちは世界", "Привет мир",
        "SELECT * FROM users WHERE id=1", "https://www.example.org/blog?id=3",
        "192.168.1.1", "2026-11-13", "e=mc2", "I", "ok",
        "Rendez-vous demain à 14h30 devant la gare",
        "ssh root@10.0.0.5 -p 2222", "C:\\Windows\\System32\\cmd.exe",
        "5d41402abc4b2a76b9719d911017c592",                # an MD5 is an end state
    ]

    def test_plain_text_is_left_alone(self):
        for text in self.PLAIN:
            with self.subTest(text=text):
                best = r.decode(text).best
                self.assertEqual(best.depth, 0,
                                 f"decoded to {best.text!r} via "
                                 f"{[n.label for n in best.chain()]}")

    def test_random_tokens_are_left_alone(self):
        rng = random.Random(7)
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        wrong = 0
        for _ in range(150):
            token = "".join(rng.choice(alphabet) for _ in range(rng.randint(6, 14)))
            wrong += r.decode(token).best.depth != 0
        self.assertLessEqual(wrong, 3, "too many random tokens were 'decoded'")


class Options(unittest.TestCase):
    def test_only_and_exclude(self):
        encoded = r.encode_chain(b"selective decoding works as expected", "rot13,base64")
        self.assertEqual(r.decode(encoded, only=["base64", "caesar"]).best.depth, 2)
        self.assertNotEqual(r.decode(encoded, exclude=["base64"]).best.text,
                            "selective decoding works as expected")
        with self.assertRaises(ValueError):
            r.decode(encoded, only=["nope"])

    def test_flag_pattern_guides_the_search(self):
        encoded = r.encode_chain(b"ZZ9{qwpvx}", "caesar:4,base64")
        best = r.decode(encoded, flag=r"ZZ9\{\w+\}").best
        self.assertEqual(best.text, "ZZ9{qwpvx}")

    def test_binary_input(self):
        import gzip
        best = r.decode(gzip.compress(b"binary input straight from a file")).best
        self.assertEqual(best.text, "binary input straight from a file")


class CommandLine(unittest.TestCase):
    def run_cli(self, *argv):
        out = io.StringIO()
        with redirect_stdout(out):
            code = r.main(list(argv))
        return code, out.getvalue()

    def test_quiet(self):
        code, out = self.run_cli("-q", "aGVsbG8gd29ybGQ=")
        self.assertEqual((code, out), (0, "hello world\n"))

    def test_report(self):
        code, out = self.run_cli("--no-color", "NjE3NDc0NjE2MzZiMjA2MTc0MjA2NDYxNzc2ZQ==")
        self.assertEqual(code, 0)
        self.assertIn("2 layers peeled off", out)
        self.assertIn("attack at dawn", out)

    def test_nothing_to_decode(self):
        code, out = self.run_cli("--no-color", "nothing to see here")
        self.assertEqual(code, 1)
        self.assertIn("No encoding detected", out)

    def test_json(self):
        code, out = self.run_cli("--json", "-n", "2", "aGVsbG8gd29ybGQ=")
        data = json.loads(out)
        self.assertEqual(data["candidates"][0]["plaintext"], "hello world")
        self.assertEqual(data["candidates"][0]["layers"][0]["codec"], "base64")

    def test_list(self):
        code, out = self.run_cli("--no-color", "--list")
        self.assertEqual(code, 0)
        for name in ("base64", "morse", "caesar", "gzip", "xor"):
            self.assertIn(name, out)


if __name__ == "__main__":
    unittest.main()
