#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Rosetta5 - automated multi-layer decoder.

Rosetta5 analyses a character string that went through several nested
encodings / classical ciphers and peels the layers off automatically.
It explores up to 5 levels of nesting (configurable), tries every
transformation of its library at each level, and ranks the candidates
with a small English/French language model so that the most plausible
plaintext comes out first.

Standard library only. Python 3.9+.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import bz2
import gzip
import html
import json
import lzma
import math
import os
import quopri
import re
import sys
import time
import unicodedata
import urllib.parse
import zlib
from collections import Counter, deque
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Tuple

__version__ = "2.0.0"

MAX_DEPTH_DEFAULT = 5
MAX_DEPTH_LIMIT = 8
MAX_NODES_DEFAULT = 200_000
TIMEOUT_DEFAULT = 20.0
MAX_DECOMPRESSED = 8 * 1024 * 1024
BIGINT_MAX_LEN = 32768         # base58 / base62 are quadratic: cap the input
SCORE_WINDOW = 400             # characters looked at by the language model

# Scores are log-evidence in nats. Every hypothesis has a price that roughly
# matches the number of alternatives tried (25 Caesar shifts, 255 XOR keys,
# ~30 decoders...), so that a lucky hit on a short string does not win.
COST_STRUCTURAL = 8.0
COST_ESCAPES = 2.0             # URL/HTML/... escapes are unambiguous
COST_REVERSE = 3.0
COST_RAIL = 5.0
COST_CIPHER = 7.0
COST_XOR = 8.0
COST_KEYED = 1.0
EVIDENCE_CAP = 64.0            # one layer never outweighs a long readable text

Output = Tuple[str, bytes]     # (human readable label, decoded bytes)


# ════════════════════════════════════════════════════════════════════════
#  Text helpers
# ════════════════════════════════════════════════════════════════════════

_PRINTABLE_ASCII = bytes(range(32, 127)) + b"\n\r\t"


def as_text(data: bytes) -> Optional[str]:
    """Return ``data`` as a string if it is clean, printable UTF-8 text."""
    if data.isascii():
        if data.translate(None, _PRINTABLE_ASCII) or not data.strip():
            return None
        return data.decode("ascii")
    try:
        s = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not s.strip():
        return None
    for ch in s:
        if ch in "\n\r\t":
            continue
        if not ch.isprintable():
            return None
    return s


def _unwrap(s: str) -> str:
    """Strip the string and remove line wrapping (newlines only)."""
    return re.sub(r"[\r\n]+", "", s.strip())


# ════════════════════════════════════════════════════════════════════════
#  Language model (bigram log-likelihood ratio, English + French)
# ════════════════════════════════════════════════════════════════════════

_CORPUS = """
the quick brown fox jumps over the lazy dog while the people of the town
are sleeping. this is a simple message that was written to test whether a
piece of text looks like a natural language or not. when you read these
words you will know that the secret has been found and that the hidden
flag is yours. there is nothing more satisfying than watching several
layers of encoding fall away one after the other until the original
sentence appears on the screen. it was the best of plans and it was the
worst of plans, but in the end everything worked out as expected. please
remember that your password should never be shared with anyone, and that
a good key must be long, random and unique. we would like to thank all
the people who have helped us during this project. they have been working
very hard for many years and their knowledge of computer security, network
administration and cryptography is impressive. if you can read this then
you have successfully decoded the message, congratulations and well done.
what do you want to know about the system? which user has access to the
server and from where did the attacker connect? the answer is usually
written somewhere in the logs, between an error and a warning. my name is
not important but my address could be useful to you: just ask me before
you go. some would say that information wants to be free, others think it
should stay private. each of them is right in their own way, because each
situation is different. hello world, welcome to the challenge, enjoy your
stay and have fun. first you take the string, then you look at its shape,
after that you make a guess and try again. because every question has an
answer, because every lock has a key, we keep searching. meet me at
midnight near the old bridge and bring the documents with you. do not
trust the man in the grey coat, he works for the other side. the weather
was quite nice yesterday so we went out for a walk through the forest and
came back home just before dark. she said that her brother would arrive
on monday morning with the new equipment. over the next few days we will
send you more details about the mission. being able to think clearly under
pressure is something that only comes with practice and experience.

le petit chat noir dort sur le canapé pendant que les enfants jouent dans
le jardin. ceci est un message simple qui a été écrit pour vérifier si un
texte ressemble à une langue naturelle ou non. quand vous lirez ces mots,
vous saurez que le secret a été trouvé et que le drapeau caché est à vous.
il n'y a rien de plus satisfaisant que de voir plusieurs couches
d'encodage tomber les unes après les autres jusqu'à ce que la phrase
d'origine apparaisse à l'écran. bonjour tout le monde, bienvenue dans ce
défi, amusez-vous bien. votre mot de passe ne doit jamais être partagé
avec quelqu'un d'autre, et une bonne clé doit être longue, aléatoire et
unique. nous voudrions remercier toutes les personnes qui nous ont aidés
pendant ce projet. elles travaillent depuis de nombreuses années et leur
connaissance de la sécurité informatique, des réseaux et de la
cryptographie est remarquable. si vous pouvez lire ceci, alors vous avez
réussi à décoder le message, félicitations et bravo. que voulez-vous
savoir sur le système ? quel utilisateur a accès au serveur et d'où
l'attaquant s'est-il connecté ? la réponse se trouve souvent quelque part
dans les journaux, entre une erreur et un avertissement. rendez-vous à
minuit près du vieux pont et apportez les documents avec vous. il faut
toujours chercher plus loin parce que chaque question possède une réponse
et chaque serrure possède une clé. hier il faisait très beau, alors nous
sommes allés nous promener dans la forêt et nous sommes rentrés à la
maison juste avant la nuit. elle a dit que son frère arriverait lundi
matin avec le nouveau matériel. dans les prochains jours, nous vous
enverrons davantage de détails sur la mission. je pense donc je suis,
mais cela ne suffit pas toujours pour comprendre ce qui se passe autour
de nous. c'est en forgeant qu'on devient forgeron, comme le dit le
proverbe, et c'est aussi vrai pour celui qui apprend à déchiffrer.
early in the morning the fishing boats leave the harbour while the city is
still quiet. eighty five percent of the crew have never seen such heavy
weather, yet nobody thinks of giving up. a physicist, a journalist and a
judge walked into the laboratory and asked which machine had produced the
strange signal. the technician shrugged, switched off the light and opened
the heavy steel door. behind it, thousands of magnetic tapes were stored in
dusty cardboard boxes, each one labelled with a number, a date and a short
description. zero, one, two, three, four, five, six, seven, eight, nine,
ten, eleven, twelve, twenty, thirty, forty, fifty, sixty, seventy, eighty,
ninety, hundred, thousand. monday, tuesday, wednesday, thursday, friday,
saturday, sunday. january, february, march, april, june, july, august,
september, october, november, december. the ascii table, the unicode
standard and the binary system are things every engineer should know. just
type the command, press enter and watch the output scroll by. a quick
analysis of the packet capture showed an unusual amount of traffic towards
an unknown host. the firewall blocked most of it, but a few requests
slipped through and reached the database. always check the hash of a file
you download, verify the signature and keep your software up to date. the
exploit abused a buffer overflow in the kernel driver, giving the intruder
full privileges within seconds. she quietly copied the encrypted archive
onto a small device, slipped it into her jacket and left through the
kitchen. nobody noticed anything unusual until the following afternoon.
children enjoy puzzles: jigsaw, crossword, riddle or maze, it does not
matter. knowledge grows when it is shared, and curiosity is the engine of
every discovery. bright yellow flowers covered the valley, and a gentle
breeze carried the smell of fresh bread from the village. objects in the
mirror are closer than they appear. practice makes perfect, as everybody
says, though few people actually enjoy practising.

tôt le matin, les bateaux de pêche quittent le port alors que la ville est
encore silencieuse. quatre-vingt-cinq pour cent de l'équipage n'a jamais vu
un temps pareil, pourtant personne ne songe à abandonner. un physicien, une
journaliste et un juge sont entrés dans le laboratoire et ont demandé
quelle machine avait produit ce signal étrange. le technicien a haussé les
épaules, éteint la lumière et ouvert la lourde porte en acier. derrière,
des milliers de bandes magnétiques étaient rangées dans des cartons
poussiéreux, chacun portant un numéro, une date et une courte description.
zéro, un, deux, trois, quatre, cinq, six, sept, huit, neuf, dix, onze,
douze, vingt, trente, quarante, cinquante, soixante, cent, mille. lundi,
mardi, mercredi, jeudi, vendredi, samedi, dimanche. janvier, février, mars,
avril, mai, juin, juillet, août, septembre, octobre, novembre, décembre.
tapez simplement la commande, appuyez sur entrée et regardez le résultat
défiler. une analyse rapide de la capture réseau a montré un volume
inhabituel de trafic vers un hôte inconnu. le pare-feu en a bloqué la
majeure partie, mais quelques requêtes sont passées et ont atteint la base
de données. vérifiez toujours l'empreinte d'un fichier téléchargé,
contrôlez la signature et gardez vos logiciels à jour. elle a copié
discrètement l'archive chiffrée sur une petite clé, l'a glissée dans sa
veste et est sortie par la cuisine. personne n'a rien remarqué avant le
lendemain après-midi. le savoir grandit quand on le partage, et la
curiosité est le moteur de toute découverte. des fleurs jaunes couvraient
la vallée, et une brise légère apportait l'odeur du pain frais depuis le
village. il vaut mieux prévenir que guérir, comme chacun sait, et rien ne
sert de courir, il faut partir à point. le courant passe dans le câble
jusqu'au poste de transformation, puis il est distribué aux habitants du
quartier.
"""

_EXTRA_WORDS = """
flag ctf key secret password passwd admin root user login token hash
cipher crypto encode decode encoded decoded encryption decryption base
hello world test example message data file text string value hidden
congratulations congrats success solved challenge answer solution here
server client network system access account email address name code
attack defend dawn dusk midnight noon enemy agent mission target safe

a about above after again against all almost alone along already also
although always am among an and another any anyone anything are around as
ask at away back be became because become been before began behind being
below best better between big both bring but by call came can cannot come
could day did different do does done down during each early end enough
even ever every few find first follow for found four from full gave get
give go goes going gone good got great had hand hard has have he head help
her here high him his home house how however if important in into is it
its just keep kind knew know large last later least left less let life
like line little long look made make man many may me mean men might more
most much must my near need never new next night no not nothing now
number of off often old on once one only open or other our out over own
part people place put read right room said same saw say see seem set she
should show side since small so some something soon still such take tell
than that the their them then there these they thing think this those
though thought three through time to today together told too took toward
turn two under until up upon us use used very want was water way we week
well went were what when where whether which while white who whole why
will with within without word work world would write year yes yet you
young your

bonjour monde mot passe clef cle secret drapeau bravo reussi solution
serveur reseau systeme compte adresse nom code fichier texte donnees
ai aie ainsi alors apres au aucun aussi autre autres aux avant avec avez
avoir avons beaucoup bien bon ca car ce cela ces cet cette ceux chaque
chez chose comme comment contre dans de deja demain depuis des deux
devant dire dit doit donc dont du elle elles en encore entre es est et
ete etait etre eu eux faire fait faut fois font grand haut heure hier
homme ici il ils jamais je jour jusque la le les leur leurs lui ma main
mais mal me meme mes mieux moi moins mon ne ni non nos notre nous
nouveau nuit on ont ou oui par parce pas pendant petit peu peut plus
pour pourquoi premier prendre pres puis quand que quel quelle quelque
qui quoi rien sa sans se sera ses si soir soit son sont sous suis sur ta
tant te temps tes toi ton toujours tous tout toute toutes tres trop tu
un une va vers veut vie voici voila voir vont vos votre vous vrai
"""


def _fold(s: str) -> str:
    """Lower-case and strip accents (é -> e)."""
    s = s.lower()
    if s.isascii():
        return s
    s = unicodedata.normalize("NFD", s)
    return "".join(c for c in s if unicodedata.category(c) != "Mn")


_ALPHABET = "abcdefghijklmnopqrstuvwxyz "


def _build_model() -> Tuple[Dict[str, float], frozenset]:
    text = re.sub(r"[^a-z]+", " ", _fold(_CORPUS)).strip()
    counts: Dict[str, int] = {}
    for a, b in zip(text, text[1:]):
        counts[a + b] = counts.get(a + b, 0) + 1
    total = sum(counts.values())
    n = len(_ALPHABET) ** 2
    uniform = 1.0 / n
    smooth = 0.3
    table: Dict[str, float] = {}
    for a in _ALPHABET:
        for b in _ALPHABET:
            if a == " " and b == " ":
                continue
            p = (counts.get(a + b, 0) + smooth) / (total + smooth * n)
            table[a + b] = max(-2.5, min(3.0, math.log(p / uniform)))
    vocab = set(re.findall(r"[a-z]{2,}", text))
    vocab.update(re.findall(r"[a-z]{2,}", _fold(_EXTRA_WORDS)))
    return table, frozenset(vocab)


_BIGRAM, _VOCAB = _build_model()

_RE_DIGIT = re.compile(r"[0-9]")
_RE_CAMEL = re.compile(r"[a-z][A-Z]")
_RE_ODD = re.compile(r"[^0-9A-Za-z\s.,;:!?'\"()\-_{}/@\u00C0-\u024F]")
_RE_WORD = re.compile(r"[a-z]{2,}")
_RE_NOT_LETTER = re.compile(r"[^a-z]")
_RE_LONE_CR = re.compile(r"\r(?!\n)")
_RE_SINGLE = re.compile(r"(?<![a-z0-9'_])[b-hj-xz](?![a-z0-9'_])")
_RE_KNOWN_FLAG = re.compile(
    r"(?i)\b(?:flag|ctf|htb|thm|pico(?:ctf)?|fcsc|ecsc|404ctf|dghack|"
    r"root[-_]?me|hackthebox|key|secret)\w{0,8}\{[ -~]{2,}\}")
_RE_GENERIC_FLAG = re.compile(r"\s*[A-Za-z0-9_]{2,12}\{[^{}\s]{3,}\}\s*")


_CJK = {"CJK", "HIRAGANA", "KATAKANA", "KATAKANA-HIRAGANA", "IDEOGRAPHIC",
        "FULLWIDTH", "HALFWIDTH", "HANGUL"}


_TYPOGRAPHY = "\u2018\u2019\u201c\u201d\u2013\u2014\u2026\u20ac\u2022\u3000\u3001\u3002"


def _script_penalty(window: str) -> float:
    """Text written in another script is fine; a few stray exotic characters
    or a mix of unrelated scripts is what garbage decodes look like."""
    scripts: Dict[str, int] = {}
    for ch in window:
        if ch.isascii() or "\u00A0" <= ch <= "\u024F" or ch in _TYPOGRAPHY:
            continue
        family = unicodedata.name(ch, "UNKNOWN").split(" ")[0]
        family = "CJK" if family in _CJK else family
        scripts[family] = scripts.get(family, 0) + 1
    if not scripts:
        return 0.0
    total = sum(scripts.values())
    if len(scripts) == 1 and total >= 3:
        return 0.0
    return 4.0 * total


def language_score(text: str, flag_re: Optional[re.Pattern] = None) -> float:
    """Log-evidence (in nats) that ``text`` is readable plaintext.

    Positive values mean "looks like English/French prose or a flag".
    Everything that does not look like language scores 0: the model cannot
    rank one random-looking token against another, and pretending it can
    is how false positives are made.
    """
    window = text[:SCORE_WINDOW]
    folded = re.sub(r"\s+", " ", _fold(window))
    # Each distinct bigram counts 8 times at most: endless repetition of the
    # same few letters is not language, however plausible each pair looks.
    pairs = Counter(map("".join, zip(folded, folded[1:])))
    score = sum(_BIGRAM.get(pair, 0.0) * min(count, 8)
                for pair, count in pairs.items())
    if score > 0:
        # A handful of letters repeated over and over (what a wrong cipher
        # applied to binary or Bacon text gives) is not language.
        letters = _RE_NOT_LETTER.sub("", folded)
        expected = min(10, len(letters) // 2 + 1)
        score *= min(1.0, len(set(letters)) / expected)
    # Dictionary words are strong evidence (each one counted 3 times at most),
    # and pronounceable gibberish without a single known word is discounted.
    seen: Dict[str, int] = {}
    known = total = bonus = 0
    for word in _RE_WORD.findall(folded):
        total += len(word)
        if word in _VOCAB:
            known += len(word)
            seen[word] = seen.get(word, 0) + 1
            if seen[word] <= 3:
                bonus += len(word)
    if score > 0 and total:
        score *= 0.4 + 0.6 * known / total
    score += 0.6 * bonus
    # Things that are rare in prose and frequent in encoded material.
    score -= 2.0 * len(_RE_SINGLE.findall(folded))
    score -= 0.3 * len(_RE_DIGIT.findall(window))
    score -= 1.0 * len(_RE_CAMEL.findall(window))
    score -= 1.0 * len(_RE_ODD.findall(window))
    score = max(score, 0.0)
    if flag_re is not None and flag_re.search(text):
        score += 25.0
    elif _RE_KNOWN_FLAG.search(text):
        score += 22.0          # ~odds of a known prefix + braces by chance
    elif _RE_GENERIC_FLAG.fullmatch(text):
        score += 3.0
    # Below the floor: what garbage decodes look like.
    score -= 3.0 * len(_RE_LONE_CR.findall(window)) + 1.5 * window.count("\t")
    if not window.isascii():
        score -= _script_penalty(window)
    return score


# ════════════════════════════════════════════════════════════════════════
#  Codec implementations (decoders are strict: they refuse on any doubt)
# ════════════════════════════════════════════════════════════════════════

# ── Base64 family ───────────────────────────────────────────────────────

_RE_B64 = re.compile(r"[A-Za-z0-9+/]+={0,2}")
_RE_B64URL = re.compile(r"[A-Za-z0-9_\-]+={0,2}")


def _b64_core(c: str) -> Optional[bytes]:
    body = c.rstrip("=")
    pad = len(c) - len(body)
    if len(body) < 2 or len(body) % 4 == 1:
        return None
    if pad and len(c) % 4:
        return None
    try:
        out = base64.b64decode(body + "=" * (-len(body) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    # Canonical form only: unused trailing bits must be zero.
    if base64.b64encode(out).decode().rstrip("=") != body:
        return None
    return out


def dec_base64(s: str) -> Iterator[Output]:
    c = _unwrap(s)
    if len(c) >= 4 and _RE_B64.fullmatch(c):
        out = _b64_core(c)
        if out:
            yield "Base64", out


def dec_base64url(s: str) -> Iterator[Output]:
    c = _unwrap(s)
    if len(c) >= 4 and ("-" in c or "_" in c) and _RE_B64URL.fullmatch(c):
        out = _b64_core(c.replace("-", "+").replace("_", "/"))
        if out:
            yield "Base64 (URL-safe)", out


def _b32_generic(c: str, charset: str, decoder, encoder) -> Optional[bytes]:
    if c != c.upper():
        if c != c.lower():
            return None
        c = c.upper()
    if not re.fullmatch(charset + r"+=*", c):
        return None
    body = c.rstrip("=")
    pad = len(c) - len(body)
    if len(body) % 8 not in (0, 2, 4, 5, 7):
        return None
    if pad and len(c) % 8:
        return None
    try:
        out = decoder(body + "=" * (-len(body) % 8))
    except (binascii.Error, ValueError):
        return None
    if encoder(out).decode().rstrip("=") != body:
        return None
    return out


def dec_base32(s: str) -> Iterator[Output]:
    c = _unwrap(s)
    if len(c) >= 4:
        out = _b32_generic(c, "[A-Z2-7]", base64.b32decode, base64.b32encode)
        if out:
            yield "Base32", out


def dec_base32hex(s: str) -> Iterator[Output]:
    if not hasattr(base64, "b32hexdecode"):
        return
    c = _unwrap(s)
    if len(c) >= 4:
        out = _b32_generic(c, "[0-9A-V]", base64.b32hexdecode,
                           base64.b32hexencode)
        if out:
            yield "Base32 (hex alphabet)", out


# ── Numeric representations ─────────────────────────────────────────────

_RE_HEX_TOKEN = re.compile(r"(?:0x|\\x)?([0-9a-fA-F]{2})")


def dec_hex(s: str) -> Iterator[Output]:
    t = s.strip()
    tokens = [k for k in re.split(r"[\s,:;\-]+", t) if k]
    if len(tokens) > 1:
        digits = []
        for k in tokens:
            m = _RE_HEX_TOKEN.fullmatch(k)
            if not m:
                return
            digits.append(m.group(1))
        compact = "".join(digits)
    else:
        if re.fullmatch(r"(?:\\x[0-9a-fA-F]{2})+", t):
            compact = t.replace("\\x", "")
        elif re.fullmatch(r"(?:0x[0-9a-fA-F]{2}){2,}", t):
            compact = t.replace("0x", "")
        else:
            compact = t[2:] if t[:2] in ("0x", "0X") else t
    if len(compact) < 4 or len(compact) % 2:
        return
    if not re.fullmatch(r"[0-9a-fA-F]+", compact):
        return
    yield "Hexadecimal", bytes.fromhex(compact)


def dec_binary(s: str) -> Iterator[Output]:
    tokens = [k for k in re.split(r"[\s,]+", s.strip()) if k]
    if not tokens or not all(re.fullmatch(r"[01]+", k) for k in tokens):
        return
    if len(tokens) > 1 and all(len(k) == 7 for k in tokens):
        yield "Binary (7-bit)", bytes(int(k, 2) for k in tokens)
        return
    bits = "".join(tokens)
    if len(bits) < 8 or len(bits) % 8:
        return
    if len(tokens) > 1 and any(len(k) % 8 for k in tokens):
        return
    yield "Binary", bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


def dec_octal(s: str) -> Iterator[Output]:
    t = s.strip()
    if re.fullmatch(r"(?:\\[0-7]{1,3}){2,}", t):
        tokens = t.split("\\")[1:]
    else:
        tokens = [k for k in re.split(r"[\s,]+", t) if k]
    if len(tokens) < 2:
        return
    values = []
    for k in tokens:
        if not re.fullmatch(r"[0-7]{1,3}", k):
            return
        v = int(k, 8)
        if v > 255:
            return
        values.append(v)
    yield "Octal", bytes(values)


def dec_decimal(s: str) -> Iterator[Output]:
    tokens = [k for k in re.split(r"[\s,;]+", s.strip()) if k]
    if len(tokens) < 2:
        return
    values = []
    for k in tokens:
        if not re.fullmatch(r"[0-9]{1,7}", k):
            return
        values.append(int(k))
    if max(values) < 256:
        yield "Decimal (byte values)", bytes(values)
        return
    try:
        if any(0xD800 <= v <= 0xDFFF for v in values):
            return
        yield "Decimal (code points)", "".join(map(chr, values)).encode()
    except (ValueError, OverflowError):
        return


# ── Base85 family ───────────────────────────────────────────────────────

_RE_A85 = re.compile(r"[!-uz]+")
_RE_B85 = re.compile(r"[0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~]+")
_Z85_ALPHABET = ("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                 ".-:+=^!/*?&<>()[]{}@%$#")
_Z85_INDEX = {c: i for i, c in enumerate(_Z85_ALPHABET)}


def dec_ascii85(s: str) -> Iterator[Output]:
    t = s.strip()
    if t.startswith("<~") and t.endswith("~>") and len(t) > 4:
        try:
            out = base64.a85decode(t, adobe=True)
        except ValueError:
            return
        if out:
            yield "Ascii85 (Adobe)", out
        return
    c = _unwrap(t)
    if len(c) < 5 or not _RE_A85.fullmatch(c):
        return
    try:
        out = base64.a85decode(c)
    except ValueError:
        return
    if out and base64.a85encode(out).decode() == c:
        yield "Ascii85", out


def dec_base85(s: str) -> Iterator[Output]:
    c = _unwrap(s)
    if len(c) < 5 or not _RE_B85.fullmatch(c):
        return
    try:
        out = base64.b85decode(c)
    except ValueError:
        return
    if out and base64.b85encode(out).decode() == c:
        yield "Base85 (RFC 1924)", out


def dec_z85(s: str) -> Iterator[Output]:
    c = _unwrap(s)
    if len(c) < 5 or len(c) % 5 or any(ch not in _Z85_INDEX for ch in c):
        return
    out = bytearray()
    for i in range(0, len(c), 5):
        v = 0
        for ch in c[i:i + 5]:
            v = v * 85 + _Z85_INDEX[ch]
        if v > 0xFFFFFFFF:
            return
        out += v.to_bytes(4, "big")
    yield "Z85 (ZeroMQ)", bytes(out)


def enc_z85(data: bytes) -> bytes:
    if len(data) % 4:
        raise ValueError("z85 needs a length that is a multiple of 4 bytes")
    out = []
    for i in range(0, len(data), 4):
        v = int.from_bytes(data[i:i + 4], "big")
        chunk = ""
        for _ in range(5):
            v, r = divmod(v, 85)
            chunk = _Z85_ALPHABET[r] + chunk
        out.append(chunk)
    return "".join(out).encode()


# ── Big-integer bases ───────────────────────────────────────────────────

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B62_A = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_B62_B = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _bigint_decode(c: str, alphabet: str) -> Optional[bytes]:
    index = {ch: i for i, ch in enumerate(alphabet)}
    base = len(alphabet)
    try:
        digits = [index[ch] for ch in c]
    except KeyError:
        return None
    # Fold the digits 8 at a time: far fewer big-integer operations.
    n = 0
    for i in range(0, len(digits), 8):
        chunk = 0
        for d in digits[i:i + 8]:
            chunk = chunk * base + d
        n = n * base ** len(digits[i:i + 8]) + chunk
    zeros = len(c) - len(c.lstrip(alphabet[0]))
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * zeros + body


def _bigint_encode(data: bytes, alphabet: str) -> bytes:
    zeros = len(data) - len(data.lstrip(b"\x00"))
    n = int.from_bytes(data, "big")
    base = len(alphabet)
    out = ""
    while n:
        n, r = divmod(n, base)
        out = alphabet[r] + out
    return (alphabet[0] * zeros + out).encode()


def dec_base58(s: str) -> Iterator[Output]:
    c = s.strip()
    if 4 <= len(c) <= BIGINT_MAX_LEN:
        out = _bigint_decode(c, _B58)
        if out:
            yield "Base58", out


def dec_base62(s: str) -> Iterator[Output]:
    c = s.strip()
    if not (4 <= len(c) <= BIGINT_MAX_LEN) or not c.isascii() or not c.isalnum():
        return
    seen = set()
    for label, alphabet in (("Base62", _B62_A), ("Base62 (0-9a-zA-Z)", _B62_B)):
        out = _bigint_decode(c, alphabet)
        if out and out not in seen:
            seen.add(out)
            yield label, out


_B45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
_B45_INDEX = {c: i for i, c in enumerate(_B45)}


def dec_base45(s: str) -> Iterator[Output]:
    c = s.strip("\r\n")
    if len(c) % 3 == 1:
        c += " "                     # a trailing space is easily lost
    if len(c) < 3 or any(ch not in _B45_INDEX for ch in c):
        return
    out = bytearray()
    for i in range(0, len(c), 3):
        chunk = [_B45_INDEX[ch] for ch in c[i:i + 3]]
        if len(chunk) == 3:
            v = chunk[0] + chunk[1] * 45 + chunk[2] * 2025
            if v > 0xFFFF:
                return
            out += v.to_bytes(2, "big")
        else:
            v = chunk[0] + chunk[1] * 45
            if v > 0xFF:
                return
            out.append(v)
    yield "Base45", bytes(out)


def enc_base45(data: bytes) -> bytes:
    out = []
    for i in range(0, len(data), 2):
        chunk = data[i:i + 2]
        if len(chunk) == 2:
            v = int.from_bytes(chunk, "big")
            e, v = divmod(v, 2025)
            d, c = divmod(v, 45)
            out.append(_B45[c] + _B45[d] + _B45[e])
        else:
            d, c = divmod(chunk[0], 45)
            out.append(_B45[c] + _B45[d])
    return "".join(out).encode()


_B91 = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        "!#$%&()*+,./:;<=>?@[]^_`{|}~\"")
_B91_INDEX = {c: i for i, c in enumerate(_B91)}


def dec_base91(s: str) -> Iterator[Output]:
    c = _unwrap(s)
    if len(c) < 4 or any(ch not in _B91_INDEX for ch in c):
        return
    v, b, n = -1, 0, 0
    out = bytearray()
    for ch in c:
        d = _B91_INDEX[ch]
        if v < 0:
            v = d
            continue
        v += d * 91
        b |= v << n
        n += 13 if (v & 8191) > 88 else 14
        while n > 7:
            out.append(b & 255)
            b >>= 8
            n -= 8
        v = -1
    if v >= 0:
        out.append((b | v << n) & 255)
    data = bytes(out)
    if data and enc_base91(data).decode() == c:
        yield "Base91", data


def enc_base91(data: bytes) -> bytes:
    b, n = 0, 0
    out = []
    for byte in data:
        b |= byte << n
        n += 8
        if n > 13:
            v = b & 8191
            if v > 88:
                b >>= 13
                n -= 13
            else:
                v = b & 16383
                b >>= 14
                n -= 14
            out.append(_B91[v % 91] + _B91[v // 91])
    if n:
        out.append(_B91[b % 91])
        if n > 7 or b > 90:
            out.append(_B91[b // 91])
    return "".join(out).encode()


# ── Escapes and transport encodings ─────────────────────────────────────

def dec_url(s: str) -> Iterator[Output]:
    t = s.strip()
    if not re.search(r"%[0-9A-Fa-f]{2}", t):
        return
    if re.search(r"%(?![0-9A-Fa-f]{2})", t):
        return                       # a stray '%': this is not URL-encoded
    out = urllib.parse.unquote_to_bytes(t)
    yield "URL encoding", out
    if "+" in t and " " not in t:
        yield ("URL encoding (form, + as space)",
               urllib.parse.unquote_to_bytes(t.replace("+", " ")))


_RE_ENTITY = re.compile(
    r"&(?:#[0-9]{1,7}|#[xX][0-9a-fA-F]{1,6}|[A-Za-z][A-Za-z0-9]{1,30});")


def dec_html(s: str) -> Iterator[Output]:
    if not _RE_ENTITY.search(s):
        return
    if "&" in _RE_ENTITY.sub("", s):
        return                       # a stray '&': this is not HTML-escaped
    out = html.unescape(s)
    if out != s:
        yield "HTML entities", out.encode("utf-8", "surrogatepass")


def dec_quoted_printable(s: str) -> Iterator[Output]:
    if not re.search(r"=[0-9A-F]{2}|=\r?\n", s):
        return
    if re.search(r"=(?![0-9A-F]{2}|\r?\n)", s):
        return                       # a lone '=' is not valid quoted-printable
    try:
        raw = s.encode("utf-8")
        out = quopri.decodestring(raw)
    except (ValueError, binascii.Error):
        return
    if out != raw:
        yield "Quoted-printable", out


_RE_UNI = re.compile(
    r"\\u([0-9a-fA-F]{4})|\\U([0-9a-fA-F]{8})|\\x([0-9a-fA-F]{2})"
    r"|%u([0-9a-fA-F]{4})|\\u\{([0-9a-fA-F]{1,6})\}")
_RE_UPLUS = re.compile(r"U\+([0-9a-fA-F]{4,6})")


def dec_unicode_escape(s: str) -> Iterator[Output]:
    t = s.strip()
    tokens = t.split()
    try:
        if tokens and all(_RE_UPLUS.fullmatch(k) for k in tokens):
            out = "".join(chr(int(k[2:], 16)) for k in tokens)
        elif _RE_UNI.search(t):
            out = _RE_UNI.sub(
                lambda m: chr(int(next(g for g in m.groups() if g), 16)), t)
        else:
            return
        # Recombine UTF-16 surrogate pairs (\ud83d\ude00 -> one code point).
        out = out.encode("utf-16", "surrogatepass").decode("utf-16")
        yield "Unicode escapes", out.encode("utf-8")
    except (ValueError, OverflowError, UnicodeError):
        return


def dec_uuencode(s: str) -> Iterator[Output]:
    lines = s.strip().splitlines()
    if len(lines) < 3 or not re.fullmatch(r"begin [0-7]{3,4} \S.*", lines[0]):
        return
    out = bytearray()
    try:
        for line in lines[1:]:
            if line.strip() == "end":
                break
            if line.strip() in ("`", ""):
                continue
            out += binascii.a2b_uu(line)
    except binascii.Error:
        return
    if out:
        yield "Uuencode", bytes(out)


def enc_uuencode(data: bytes) -> bytes:
    lines = ["begin 644 data"]
    for i in range(0, len(data), 45):
        lines.append(binascii.b2a_uu(data[i:i + 45]).decode().rstrip("\n"))
    lines += ["`", "end"]
    return "\n".join(lines).encode()


# ── Symbol alphabets ────────────────────────────────────────────────────

_MORSE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.",
    "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..",
    "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
    "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
    "Y": "-.--", "Z": "--..", "0": "-----", "1": ".----", "2": "..---",
    "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...",
    "8": "---..", "9": "----.", ".": ".-.-.-", ",": "--..--", "?": "..--..",
    "'": ".----.", "!": "-.-.--", "/": "-..-.", "(": "-.--.", ")": "-.--.-",
    "&": ".-...", ":": "---...", ";": "-.-.-.", "=": "-...-", "+": ".-.-.",
    "-": "-....-", "_": "..--.-", '"': ".-..-.", "$": "...-..-", "@": ".--.-.",
    "{": "-.--.", "}": "-.--.-",
}
_MORSE_DEC = {}
for _k, _v in _MORSE.items():
    _MORSE_DEC.setdefault(_v, _k)      # '(' / ')' win over '{' / '}'


def dec_morse(s: str) -> Iterator[Output]:
    t = s.strip().translate(str.maketrans("·•−–—_", "..----"))
    if not t or any(ch not in ".- /|\n\r\t" for ch in t):
        return
    if "." not in t and "-" not in t:
        return
    words = [w for w in re.split(r"\s*[/|\n]\s*|\s{3,}", t) if w.strip()]
    decoded = []
    count = 0
    for word in words:
        letters = []
        for sym in word.split():
            if sym not in _MORSE_DEC:
                return
            letters.append(_MORSE_DEC[sym])
            count += 1
        decoded.append("".join(letters))
    if count >= 2:
        yield "Morse code", " ".join(decoded).encode()


def enc_morse(data: bytes) -> bytes:
    words = data.decode("utf-8").upper().split()
    try:
        return " / ".join(" ".join(_MORSE[c] for c in w) for w in words).encode()
    except KeyError as exc:
        raise ValueError(f"morse cannot encode {exc.args[0]!r}") from None


_BACON26 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_BACON24 = "ABCDEFGHIKLMNOPQRSTUWXYZ"


def dec_bacon(s: str) -> Iterator[Output]:
    c = re.sub(r"\s+", "", s).upper()
    if len(c) < 10 or len(c) % 5 or set(c) - {"A", "B"} or len(set(c)) < 2:
        return
    values = [int(c[i:i + 5].replace("A", "0").replace("B", "1"), 2)
              for i in range(0, len(c), 5)]
    if max(values) < 26:
        yield "Bacon cipher (26 letters)", "".join(_BACON26[v] for v in values).encode()
    if max(values) < 24:
        yield "Bacon cipher (24 letters)", "".join(_BACON24[v] for v in values).encode()


def enc_bacon(data: bytes) -> bytes:
    letters = [c for c in data.decode("utf-8").upper() if c in _BACON26]
    return " ".join(format(_BACON26.index(c), "05b").replace("0", "A").replace("1", "B")
                    for c in letters).encode()


def dec_a1z26(s: str) -> Iterator[Output]:
    t = s.strip()
    if not re.fullmatch(r"[0-9\s,.\-/|]+", t):
        return
    words = [w for w in re.split(r"\s*[/|]\s*|\s{2,}", t) if w.strip()]
    decoded = []
    count = 0
    for word in words:
        letters = []
        for k in re.split(r"[\s,.\-]+", word.strip()):
            if not k:
                continue
            if not re.fullmatch(r"[0-9]{1,2}", k) or not 1 <= int(k) <= 26:
                return
            letters.append(chr(64 + int(k)))
            count += 1
        decoded.append("".join(letters))
    if count >= 3:
        yield "A1Z26 (letter numbers)", " ".join(decoded).encode()


def enc_a1z26(data: bytes) -> bytes:
    words = data.decode("utf-8").upper().split()
    return " / ".join("-".join(str(ord(c) - 64) for c in w if "A" <= c <= "Z")
                      for w in words).encode()


_POLYBIUS = "ABCDEFGHIKLMNOPQRSTUVWXYZ"


def dec_polybius(s: str) -> Iterator[Output]:
    t = s.strip()
    if not re.fullmatch(r"[1-5\s/|]+", t):
        return
    words = [w for w in re.split(r"\s*[/|]\s*|\s{2,}", t) if w.strip()]
    decoded = []
    count = 0
    for word in words:
        tokens = word.split()
        if len(tokens) > 1 and any(len(k) != 2 for k in tokens):
            return
        digits = "".join(tokens)
        if len(digits) % 2:
            return
        decoded.append("".join(
            _POLYBIUS[(int(digits[i]) - 1) * 5 + int(digits[i + 1]) - 1]
            for i in range(0, len(digits), 2)))
        count += len(digits) // 2
    if count >= 3:
        yield "Polybius square", " ".join(decoded).encode()


def enc_polybius(data: bytes) -> bytes:
    words = data.decode("utf-8").upper().replace("J", "I").split()
    out = []
    for w in words:
        cells = []
        for c in w:
            if c in _POLYBIUS:
                i = _POLYBIUS.index(c)
                cells.append(f"{i // 5 + 1}{i % 5 + 1}")
        out.append(" ".join(cells))
    return " / ".join(out).encode()


_NATO = {
    "alpha": "A", "alfa": "A", "bravo": "B", "charlie": "C", "delta": "D",
    "echo": "E", "foxtrot": "F", "golf": "G", "hotel": "H", "india": "I",
    "juliet": "J", "juliett": "J", "kilo": "K", "lima": "L", "mike": "M",
    "november": "N", "oscar": "O", "papa": "P", "quebec": "Q", "romeo": "R",
    "sierra": "S", "tango": "T", "uniform": "U", "victor": "V",
    "whiskey": "W", "whisky": "W", "xray": "X", "x-ray": "X", "yankee": "Y",
    "zulu": "Z", "zero": "0", "one": "1", "two": "2", "three": "3",
    "four": "4", "five": "5", "six": "6", "seven": "7", "eight": "8",
    "nine": "9", "niner": "9",
}
_NATO_ENC = {
    "A": "Alpha", "B": "Bravo", "C": "Charlie", "D": "Delta", "E": "Echo",
    "F": "Foxtrot", "G": "Golf", "H": "Hotel", "I": "India", "J": "Juliett",
    "K": "Kilo", "L": "Lima", "M": "Mike", "N": "November", "O": "Oscar",
    "P": "Papa", "Q": "Quebec", "R": "Romeo", "S": "Sierra", "T": "Tango",
    "U": "Uniform", "V": "Victor", "W": "Whiskey", "X": "Xray", "Y": "Yankee",
    "Z": "Zulu", "0": "Zero", "1": "One", "2": "Two", "3": "Three",
    "4": "Four", "5": "Five", "6": "Six", "7": "Seven", "8": "Eight",
    "9": "Nine",
}


def dec_nato(s: str) -> Iterator[Output]:
    words = [w for w in re.split(r"\s*[/|]\s*|\s{2,}", s.strip()) if w.strip()]
    decoded = []
    count = 0
    for word in words:
        letters = []
        for k in re.split(r"[\s,]+", word.strip()):
            if not k:
                continue
            if k.lower() not in _NATO:
                return
            letters.append(_NATO[k.lower()])
            count += 1
        decoded.append("".join(letters))
    if count >= 2:
        yield "NATO phonetic alphabet", " ".join(decoded).encode()


def enc_nato(data: bytes) -> bytes:
    words = data.decode("utf-8").upper().split()
    return " / ".join(" ".join(_NATO_ENC[c] for c in w if c in _NATO_ENC)
                      for w in words).encode()


_KEYPAD = {"2": "ABC", "3": "DEF", "4": "GHI", "5": "JKL", "6": "MNO",
           "7": "PQRS", "8": "TUV", "9": "WXYZ"}


def dec_multitap(s: str) -> Iterator[Output]:
    tokens = s.strip().split()
    if len(tokens) < 3:
        return
    out = []
    for k in tokens:
        if k == "0":
            out.append(" ")
            continue
        if len(set(k)) != 1 or k[0] not in _KEYPAD or len(k) > len(_KEYPAD[k[0]]):
            return
        out.append(_KEYPAD[k[0]][len(k) - 1])
    yield "Multi-tap phone keypad", "".join(out).encode()


def enc_multitap(data: bytes) -> bytes:
    out = []
    for c in data.decode("utf-8").upper():
        if c == " ":
            out.append("0")
            continue
        for digit, letters in _KEYPAD.items():
            if c in letters:
                out.append(digit * (letters.index(c) + 1))
    return " ".join(out).encode()


_BRAILLE_LETTERS = "⠁⠃⠉⠙⠑⠋⠛⠓⠊⠚⠅⠇⠍⠝⠕⠏⠟⠗⠎⠞⠥⠧⠺⠭⠽⠵"
_BRAILLE_DEC = {c: chr(97 + i) for i, c in enumerate(_BRAILLE_LETTERS)}
_BRAILLE_PUNCT = {"⠂": ",", "⠲": ".", "⠦": "?", "⠖": "!", "⠄": "'", "⠤": "-",
                  "⠒": ":", "⠆": ";"}
_BRAILLE_NUMBER, _BRAILLE_CAPITAL, _BRAILLE_BLANK = "⠼", "⠠", "⠀"


def dec_braille(s: str) -> Iterator[Output]:
    t = s.strip()
    cells = [c for c in t if "\u2800" <= c <= "\u28ff"]
    if len(cells) < 2 or any(not ("\u2800" <= c <= "\u28ff" or c.isspace()) for c in t):
        return
    out = []
    number = capital = False
    for c in t:
        if c.isspace() or c == _BRAILLE_BLANK:
            out.append("\n" if c == "\n" else " ")
            number = False
        elif c == _BRAILLE_NUMBER:
            number = True
        elif c == _BRAILLE_CAPITAL:
            capital = True
        elif c in _BRAILLE_DEC:
            letter = _BRAILLE_DEC[c]
            if number and letter <= "j":
                out.append("1234567890"[ord(letter) - 97])
            else:
                number = False
                out.append(letter.upper() if capital else letter)
            capital = False
        elif c in _BRAILLE_PUNCT:
            out.append(_BRAILLE_PUNCT[c])
            number = False
        else:
            return
    yield "Braille", "".join(out).encode()


def enc_braille(data: bytes) -> bytes:
    punct = {v: k for k, v in _BRAILLE_PUNCT.items()}
    out = []
    number = False
    for c in data.decode("utf-8"):
        if c.isdigit():
            if not number:
                out.append(_BRAILLE_NUMBER)
                number = True
            out.append(_BRAILLE_LETTERS["1234567890".index(c)])
            continue
        if number and c.isalpha() and c.lower() <= "j":
            out.append(_BRAILLE_BLANK)       # avoid reading the letter as a digit
        number = False
        if c == " ":
            out.append(_BRAILLE_BLANK)
        elif c.isascii() and c.isalpha():
            if c.isupper():
                out.append(_BRAILLE_CAPITAL)
            out.append(_BRAILLE_LETTERS[ord(c.lower()) - 97])
        elif c in punct:
            out.append(punct[c])
        else:
            raise ValueError(f"braille cannot encode {c!r}")
    return "".join(out).encode()


# ── Classical ciphers ───────────────────────────────────────────────────

_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_LOWER = _UPPER.lower()
_HAS_LETTER = re.compile(r"[A-Za-z]")


_CAESAR_TABLES = [
    str.maketrans(_UPPER + _LOWER,
                  _UPPER[k:] + _UPPER[:k] + _LOWER[k:] + _LOWER[:k])
    for k in range(26)]


def caesar(s: str, shift: int) -> str:
    return s.translate(_CAESAR_TABLES[shift % 26])


_ROT47_TABLE = str.maketrans(
    "".join(map(chr, range(33, 127))),
    "".join(chr(33 + (i + 47) % 94) for i in range(94)))
_ATBASH_TABLE = str.maketrans(_UPPER + _LOWER, _UPPER[::-1] + _LOWER[::-1])


def dec_caesar(s: str) -> Iterator[Output]:
    if not _HAS_LETTER.search(s):
        return
    for shift in range(1, 26):
        label = "ROT13" if shift == 13 else f"Caesar (shift {shift})"
        yield label, caesar(s, -shift).encode()


def dec_rot47(s: str) -> Iterator[Output]:
    if s.isascii() and re.search(r"[!-~]", s):
        yield "ROT47", s.translate(_ROT47_TABLE).encode()


def dec_atbash(s: str) -> Iterator[Output]:
    if _HAS_LETTER.search(s):
        yield "Atbash", s.translate(_ATBASH_TABLE).encode()


def dec_reverse(s: str) -> Iterator[Output]:
    if len(s) > 1 and s != s[::-1]:
        yield "Reversed string", s[::-1].encode()


def _rail_pattern(n: int, rails: int) -> List[int]:
    cycle = list(range(rails)) + list(range(rails - 2, 0, -1))
    return [cycle[i % len(cycle)] for i in range(n)]


def rail_encrypt(s: str, rails: int) -> str:
    pattern = _rail_pattern(len(s), rails)
    return "".join(c for r in range(rails) for c, p in zip(s, pattern) if p == r)


def rail_decrypt(s: str, rails: int) -> str:
    pattern = _rail_pattern(len(s), rails)
    order = sorted(range(len(s)), key=lambda i: (pattern[i], i))
    out = [""] * len(s)
    for src, dst in enumerate(order):
        out[dst] = s[src]
    return "".join(out)


def dec_railfence(s: str) -> Iterator[Output]:
    if len(s) > 100_000:
        return
    for rails in range(2, 6):
        if len(s) >= rails * 2:
            out = rail_decrypt(s, rails)
            if out != s:
                yield f"Rail fence ({rails} rails)", out.encode()


def vigenere(s: str, key: str, decrypt: bool) -> str:
    shifts = [ord(c) - 97 for c in key.lower() if "a" <= c <= "z"]
    if not shifts:
        return s
    out = []
    i = 0
    for c in s:
        if c.isascii() and c.isalpha():
            k = shifts[i % len(shifts)]
            out.append(caesar(c, -k if decrypt else k))
            i += 1
        else:
            out.append(c)
    return "".join(out)


_XOR_TABLES = [bytes(b ^ k for b in range(256)) for k in range(256)]


def xor_bytes(data: bytes, key: bytes) -> bytes:
    if len(key) == 1:
        return data.translate(_XOR_TABLES[key[0]])
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


# ── Binary layers ───────────────────────────────────────────────────────

def _bounded(decompressor, data: bytes) -> Optional[bytes]:
    try:
        out = decompressor.decompress(data, MAX_DECOMPRESSED)
    except Exception:           # zlib.error, OSError, lzma.LZMAError, EOFError
        return None
    if not out or not getattr(decompressor, "eof", True):
        return None
    return out


def dec_gzip(data: bytes) -> Iterator[Output]:
    if data[:2] == b"\x1f\x8b":
        out = _bounded(zlib.decompressobj(31), data)
        if out:
            yield "Gzip", out


def dec_zlib(data: bytes) -> Iterator[Output]:
    if len(data) > 2 and data[0] == 0x78 and data[1] in (0x01, 0x5E, 0x9C, 0xDA):
        out = _bounded(zlib.decompressobj(), data)
        if out:
            yield "Zlib", out


def dec_deflate(data: bytes) -> Iterator[Output]:
    if len(data) < 8:
        return
    d = zlib.decompressobj(-15)
    out = _bounded(d, data)
    if out and not d.unused_data and len(out) >= 4:
        yield "Raw DEFLATE", out


def enc_deflate(data: bytes) -> bytes:
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def dec_bzip2(data: bytes) -> Iterator[Output]:
    if data[:3] == b"BZh":
        out = _bounded(bz2.BZ2Decompressor(), data)
        if out:
            yield "Bzip2", out


def dec_xz(data: bytes) -> Iterator[Output]:
    if data[:6] == b"\xfd7zXZ\x00":
        out = _bounded(lzma.LZMADecompressor(), data)
        if out:
            yield "XZ / LZMA", out


def dec_utf16(data: bytes) -> Iterator[Output]:
    if len(data) < 4 or len(data) % 2:
        return
    try:
        if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
            yield "UTF-16 (BOM)", data.decode("utf-16").encode()
        elif data[1::2].count(0) >= 0.9 * (len(data) // 2):
            yield "UTF-16 LE", data.decode("utf-16-le").encode()
        elif data[0::2].count(0) >= 0.9 * (len(data) // 2):
            yield "UTF-16 BE", data.decode("utf-16-be").encode()
    except UnicodeError:
        return


# ════════════════════════════════════════════════════════════════════════
#  Codec registry
# ════════════════════════════════════════════════════════════════════════

class Codec:
    """One entry of the transformation library.

    kind:
      "text"    structural decoder working on a text node
      "binary"  structural decoder working on raw bytes
      "cipher"  keyless classical cipher working on a text node
    """

    def __init__(self, name: str, title: str, kind: str, dec: Callable,
                 enc: Optional[Callable] = None, group: str = "",
                 cost: float = 0.0, lossy: bool = False,
                 escapes: bool = False, per_in: float = 0.0,
                 per_out: float = 0.9, bonus: float = 0.0,
                 cap: float = EVIDENCE_CAP):
        self.name, self.title, self.kind = name, title, kind
        self.dec, self.enc, self.group = dec, enc, group
        self.cost, self.lossy = cost, lossy
        # Evidence model, in nats: ``per_in`` per input character (how
        # unlikely it is for arbitrary text to fit the codec's alphabet),
        # ``per_out`` per output byte when the output is clean text (how
        # unlikely for random bytes), ``bonus`` for checksummed formats.
        self.per_in, self.per_out, self.bonus = per_in, per_out, bonus
        self.cap = cap
        # True for decoders that only rewrite escape sequences inside a text
        # (URL, HTML...): their evidence is the amount of text they removed.
        self.escapes = escapes


def _t(fn: Callable[[bytes], bytes]) -> Callable[[bytes, str], bytes]:
    return lambda data, arg="": fn(data)


def _text_enc(fn: Callable[[str], str]) -> Callable[[bytes, str], bytes]:
    return lambda data, arg="": fn(data.decode("utf-8")).encode("utf-8")


def _enc_caesar(data: bytes, arg: str = "") -> bytes:
    return caesar(data.decode("utf-8"), int(arg or 3)).encode()


def _enc_rail(data: bytes, arg: str = "") -> bytes:
    return rail_encrypt(data.decode("utf-8"), int(arg or 3)).encode()


def _enc_xor(data: bytes, arg: str = "") -> bytes:
    if not arg:
        raise ValueError("xor needs a key, e.g. xor:0x2a or xor:secret")
    return xor_bytes(data, parse_key(arg))


def _enc_vigenere(data: bytes, arg: str = "") -> bytes:
    if not arg:
        raise ValueError("vigenere needs a key, e.g. vigenere:lemon")
    return vigenere(data.decode("utf-8"), arg, decrypt=False).encode()


def _enc_unicode(data: bytes, arg: str = "") -> bytes:
    s = data.decode("utf-8")
    return "".join(f"\\u{ord(c):04x}" if ord(c) < 0x10000 else f"\\U{ord(c):08x}"
                   for c in s).encode()


def _enc_html(data: bytes, arg: str = "") -> bytes:
    return "".join(f"&#{ord(c)};" for c in data.decode("utf-8")).encode()


CODECS: List[Codec] = [
    # ── structural, text input ──
    Codec("base64", "Base64", "text", dec_base64, _t(base64.b64encode), per_in=0.39),
    Codec("base64url", "Base64 URL-safe", "text", dec_base64url,
          _t(base64.urlsafe_b64encode), per_in=0.39),
    Codec("base32", "Base32", "text", dec_base32, _t(base64.b32encode), per_in=1.0),
    Codec("base32hex", "Base32 with extended hex alphabet", "text", dec_base32hex,
          _t(getattr(base64, "b32hexencode", base64.b32encode)), per_in=1.0),
    Codec("hex", "Hexadecimal (plain, spaced, 0x.., \\x..)", "text", dec_hex,
          _t(binascii.hexlify), per_in=1.5),
    Codec("binary", "Binary (8-bit or 7-bit groups)", "text", dec_binary,
          _t(lambda d: " ".join(format(b, "08b") for b in d).encode()), per_in=2.0),
    Codec("octal", "Octal byte values", "text", dec_octal,
          _t(lambda d: " ".join(format(b, "03o") for b in d).encode()), per_in=1.0),
    Codec("decimal", "Decimal byte values / code points", "text", dec_decimal,
          _text_enc(lambda s: " ".join(str(ord(c)) for c in s)), per_in=0.8),
    Codec("ascii85", "Ascii85 (plain or Adobe <~ ~>)", "text", dec_ascii85,
          _t(base64.a85encode), per_in=0.1),
    Codec("base85", "Base85 RFC 1924 (git / Python b85)", "text", dec_base85,
          _t(base64.b85encode), per_in=0.1),
    Codec("z85", "Z85 (ZeroMQ)", "text", dec_z85, _t(enc_z85), per_in=0.1),
    Codec("base58", "Base58 (Bitcoin alphabet)", "text", dec_base58,
          _t(lambda d: _bigint_encode(d, _B58)), per_in=0.5),
    Codec("base62", "Base62 (both alphabets)", "text", dec_base62,
          _t(lambda d: _bigint_encode(d, _B62_A)), per_in=0.4),
    Codec("base45", "Base45 (RFC 9285)", "text", dec_base45, _t(enc_base45), per_in=0.75),
    Codec("base91", "basE91", "text", dec_base91, _t(enc_base91), per_in=0.04),
    Codec("url", "URL percent-encoding", "text", dec_url,
          _t(lambda d: urllib.parse.quote_from_bytes(d, safe="").encode()),
          escapes=True),
    Codec("html", "HTML entities", "text", dec_html, _enc_html, escapes=True),
    Codec("qp", "Quoted-printable", "text", dec_quoted_printable,
          _t(lambda d: "".join(f"={b:02X}" for b in d).encode()), escapes=True),
    Codec("unicode", "Unicode escapes (\\uXXXX, \\xNN, %uXXXX, U+XXXX)", "text",
          dec_unicode_escape, _enc_unicode, escapes=True),
    Codec("uuencode", "Uuencode", "text", dec_uuencode, _t(enc_uuencode), bonus=10.0),
    Codec("morse", "Morse code", "text", dec_morse, _t(enc_morse), lossy=True, per_in=2.5, per_out=0.0),
    Codec("bacon", "Bacon cipher (A/B)", "text", dec_bacon, _t(enc_bacon), lossy=True, per_in=1.5, per_out=0.0),
    Codec("a1z26", "A1Z26 letter numbers", "text", dec_a1z26, _t(enc_a1z26), lossy=True, per_in=0.3, per_out=0.0),
    Codec("polybius", "Polybius square (5x5)", "text", dec_polybius,
          _t(enc_polybius), lossy=True, per_in=0.4, per_out=0.0),
    Codec("nato", "NATO phonetic alphabet", "text", dec_nato, _t(enc_nato), lossy=True, per_in=1.5, per_out=0.0,
          cap=1e9),      # the encoded form is made of real words: no cap
    Codec("multitap", "Multi-tap phone keypad", "text", dec_multitap,
          _t(enc_multitap), lossy=True, per_in=0.6, per_out=0.0),
    Codec("braille", "Braille (Unicode patterns)", "text", dec_braille,
          _t(enc_braille), per_in=3.0, per_out=0.0),
    # ── structural, binary input ──
    Codec("gzip", "Gzip", "binary", dec_gzip, _t(gzip.compress),
          per_out=0.0, bonus=28.0),
    Codec("zlib", "Zlib", "binary", dec_zlib, _t(zlib.compress), per_out=0.0, bonus=28.0),
    Codec("deflate", "Raw DEFLATE", "binary", dec_deflate, _t(enc_deflate), per_out=0.0, bonus=8.0),
    Codec("bzip2", "Bzip2", "binary", dec_bzip2, _t(bz2.compress), per_out=0.0, bonus=28.0),
    Codec("xz", "XZ / LZMA", "binary", dec_xz, _t(lzma.compress), per_out=0.0, bonus=28.0),
    Codec("utf16", "UTF-16 (LE / BE / BOM)", "binary", dec_utf16,
          _t(lambda d: d.decode("utf-8").encode("utf-16-le"))),
    # ── keyless ciphers ──
    Codec("reverse", "Reversed string", "cipher", dec_reverse,
          _text_enc(lambda s: s[::-1]), group="reverse", cost=COST_REVERSE),
    Codec("railfence", "Rail fence, 2 to 5 rails (railfence:N)", "cipher",
          dec_railfence, _enc_rail, group="rail", cost=COST_RAIL),
    Codec("caesar", "Caesar / ROT-N, all 25 shifts (caesar:N)", "cipher",
          dec_caesar, _enc_caesar, group="sub", cost=COST_CIPHER),
    Codec("rot47", "ROT47", "cipher", dec_rot47,
          _text_enc(lambda s: s.translate(_ROT47_TABLE)), group="sub", cost=COST_CIPHER),
    Codec("atbash", "Atbash", "cipher", dec_atbash,
          _text_enc(lambda s: s.translate(_ATBASH_TABLE)), group="sub", cost=COST_CIPHER),
]

# Pseudo-codecs: handled by the engine itself, listed for --list / --encode.
EXTRA_CODECS: List[Codec] = [
    Codec("xor", "Single-byte XOR brute force, or repeating key with -k "
          "(xor:KEY)", "special", None, _enc_xor, group="xor", cost=COST_XOR),
    Codec("vigenere", "Vigenère, only with a key given through -k "
          "(vigenere:KEY)", "special", None, _enc_vigenere, group="sub", cost=1.0),
    Codec("rot13", "Alias of caesar:13 (encoding only)", "special", None,
          lambda d, a="": _enc_caesar(d, "13")),
]

CODEC_BY_NAME: Dict[str, Codec] = {c.name: c for c in CODECS + EXTRA_CODECS}


def parse_key(arg: str) -> bytes:
    """``0x2a`` / ``0xdeadbeef`` -> raw bytes, anything else -> UTF-8."""
    if re.fullmatch(r"0[xX](?:[0-9a-fA-F]{2})+", arg):
        return bytes.fromhex(arg[2:])
    return arg.encode("utf-8")


def encode_chain(data: bytes, spec: str) -> bytes:
    """Apply ``spec`` ("base64,rot13,hex") from left to right."""
    for item in filter(None, (p.strip() for p in spec.split(","))):
        name, _, arg = item.partition(":")
        codec = CODEC_BY_NAME.get(name.lower())
        if codec is None or codec.enc is None:
            raise ValueError(f"unknown encoder {name!r} (see --list)")
        data = codec.enc(data, arg)
    return data


# ════════════════════════════════════════════════════════════════════════
#  Search engine
# ════════════════════════════════════════════════════════════════════════

class Node:
    __slots__ = ("data", "text", "parent", "label", "codec", "depth",
                 "evidence", "run", "score")

    def __init__(self, data: bytes, parent: Optional["Node"] = None,
                 label: str = "", codec: str = "", evidence: float = 0.0,
                 run: frozenset = frozenset()):
        self.data = data
        self.text = as_text(data)
        self.parent = parent
        self.label = label
        self.codec = codec
        self.depth = parent.depth + 1 if parent else 0
        self.evidence = evidence
        self.run = run
        self.score = float("-inf")

    def chain(self) -> List["Node"]:
        node, out = self, []
        while node.parent is not None:
            out.append(node)
            node = node.parent
        return out[::-1]


class Result:
    def __init__(self, candidates: List[Node], root: Node, explored: int,
                 elapsed: float, truncated: Optional[str]):
        self.candidates = candidates
        self.root = root
        self.explored = explored
        self.elapsed = elapsed
        self.truncated = truncated

    @property
    def best(self) -> Node:
        return self.candidates[0] if self.candidates else self.root


def _evidence(codec: Codec, src: Node, out: Node) -> float:
    """Evidence brought by one successful strict decoding (see Codec)."""
    if codec.escapes:
        gained = 0.9 * max(0, len(src.data) - len(out.data))
        return min(gained, codec.cap) - COST_ESCAPES
    else:
        gained = 0.0
        if not src.run:
            # A cipher can manufacture alphabet membership (ROT47 turns the
            # letters a-f into digits), so the alphabet only counts when the
            # input was not produced by one.
            gained = codec.per_in * len(src.text if src.text is not None
                                        else src.data)
        if out.text is not None:
            gained += codec.per_out * len(out.data)
    return min(gained, codec.cap) + codec.bonus - COST_STRUCTURAL


class Rosetta:
    """The recursive multi-layer decoder."""

    def __init__(self, max_depth: int = MAX_DEPTH_DEFAULT,
                 keys: Iterable[str] = (), only: Iterable[str] = (),
                 exclude: Iterable[str] = (), flag: Optional[str] = None,
                 max_nodes: int = MAX_NODES_DEFAULT,
                 timeout: float = TIMEOUT_DEFAULT):
        self.max_depth = max(1, min(int(max_depth), MAX_DEPTH_LIMIT))
        self.keys = [k for k in keys if k]
        self.flag_re = re.compile(flag) if flag else None
        self.max_nodes = max_nodes
        self.timeout = timeout
        only, exclude = {n.lower() for n in only}, {n.lower() for n in exclude}
        unknown = (only | exclude) - set(CODEC_BY_NAME)
        if unknown:
            raise ValueError("unknown codec(s): " + ", ".join(sorted(unknown)))

        def enabled(name: str) -> bool:
            return (not only or name in only) and name not in exclude

        self.text_codecs = [c for c in CODECS if c.kind == "text" and enabled(c.name)]
        self.binary_codecs = [c for c in CODECS if c.kind == "binary" and enabled(c.name)]
        self.cipher_codecs = [c for c in CODECS if c.kind == "cipher" and enabled(c.name)]
        self.use_xor = enabled("xor")
        # Printable input is only XOR-brute-forced when it comes straight out
        # of a byte-level decoder (Base64, hex...): XOR output is rarely
        # printable, so it is almost always wrapped in one of those.
        self.byte_producers = {c.name for c in CODECS
                               if c.kind != "cipher" and c.per_out and not c.escapes}
        self.use_vigenere = enabled("vigenere")

    # ── expansion ──

    def _children(self, node: Node) -> Iterator[Node]:
        text = node.text
        if text is not None:
            for codec in self.text_codecs:
                for label, out in codec.dec(text):
                    child = Node(out, node, label, codec.name)
                    child.evidence = node.evidence + _evidence(codec, node, child)
                    yield child
        for codec in self.binary_codecs:
            for label, out in codec.dec(node.data):
                child = Node(out, node, label, codec.name)
                child.evidence = node.evidence + _evidence(codec, node, child)
                yield child
        if text is not None and "sub" not in node.run:
            # Within a run of consecutive ciphers each family is used at most
            # once and the substitution comes last: every other ordering is
            # equivalent to one of these, so nothing is lost.
            for codec in self.cipher_codecs:
                if codec.group in node.run:
                    continue
                run = node.run | {codec.group}
                for label, out in codec.dec(text):
                    yield Node(out, node, label, codec.name,
                               node.evidence - codec.cost, run)
            if self.use_vigenere:
                for key in self.keys:
                    if re.fullmatch(r"[A-Za-z]+", key) and _HAS_LETTER.search(text):
                        out = vigenere(text, key, decrypt=True)
                        yield Node(out.encode(), node, f"Vigenère (key {key!r})",
                                   "vigenere", node.evidence - COST_KEYED,
                                   node.run | {"sub"})
        if self.use_xor and "xor" not in node.run:
            yield from self._xor_children(node)

    def _xor_children(self, node: Node) -> Iterator[Node]:
        run = node.run | {"xor"}
        for key in self.keys:
            raw = parse_key(key)
            child = Node(xor_bytes(node.data, raw), node,
                         f"XOR (key {key!r})", "xor",
                         node.evidence - COST_KEYED, run)
            if node.text is None and child.text is not None:
                child.evidence += 0.9 * min(len(child.data), EVIDENCE_CAP)
            yield child
        # Brute force only right after a byte-level decoding (or on raw binary
        # input), and only keep the keys that produce something readable:
        # single-byte XOR is searched as the innermost layer.
        if node.run or not 4 <= len(node.data) <= 1_000_000:
            return
        if node.text is not None and node.codec not in self.byte_producers:
            return
        if node.parent is not None and node.parent.run:
            return                  # cipher -> decoder -> XOR: not searched
        found = []
        distinct = bytes(set(node.data))
        for k in range(1, 256):
            table = _XOR_TABLES[k]
            if distinct.translate(table).translate(None, _PRINTABLE_ASCII):
                continue
            out = node.data.translate(table)
            text = out.decode("ascii")
            quality = language_score(text, self.flag_re)
            if quality >= max(8.0, 0.4 * min(len(text), SCORE_WINDOW)):
                found.append((quality, k, out))
        # Turning a binary blob into clean text is evidence in itself.
        credit = 0.9 * min(len(node.data), EVIDENCE_CAP) if node.text is None else 0.0
        for quality, k, out in sorted(found, reverse=True)[:3]:
            yield Node(out, node, f"XOR (single byte 0x{k:02x})", "xor",
                       node.evidence + credit - COST_XOR, run)

    # ── search ──

    def decode(self, data: bytes) -> Result:
        start = time.monotonic()
        root = Node(data)
        seen = {data}
        queue = deque([root])
        texts: List[Node] = [root] if root.text is not None else []
        explored = 0
        truncated = None
        while queue:
            node = queue.popleft()
            if node.depth >= self.max_depth:
                continue
            explored += 1
            if explored > self.max_nodes:
                truncated = f"node limit reached ({self.max_nodes})"
                break
            if time.monotonic() - start > self.timeout:
                truncated = f"timeout reached ({self.timeout:g}s)"
                break
            for child in self._children(node):
                if not child.data or child.data in seen:
                    continue
                seen.add(child.data)
                queue.append(child)
                if child.text is not None:
                    texts.append(child)
        for node in texts:
            node.score = language_score(node.text, self.flag_re) + node.evidence
        texts.sort(key=lambda n: (-n.score, n.depth))
        # Hide the alternatives that are just the same text with other casing
        # or spacing (several ciphers are case-insensitive).
        unique, keys = [], set()
        for node in texts:
            key = re.sub(r"\s+", " ", node.text.strip()).casefold()
            if key not in keys:
                keys.add(key)
                unique.append(node)
        return Result(unique, root, explored, time.monotonic() - start, truncated)


def decode(data, **options) -> Result:
    """Convenience wrapper: ``rosetta5.decode("aGVsbG8=").best.text``."""
    if isinstance(data, str):
        data = data.strip().encode("utf-8")
    return Rosetta(**options).decode(data)


# ════════════════════════════════════════════════════════════════════════
#  Command line interface
# ════════════════════════════════════════════════════════════════════════

class Style:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def __call__(self, code: str, s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if self.enabled else s

    def bold(self, s): return self("1", s)
    def dim(self, s): return self("2", s)
    def green(self, s): return self("1;32", s)
    def cyan(self, s): return self("36", s)
    def yellow(self, s): return self("33", s)
    def red(self, s): return self("31", s)


def _preview(node: Node, width: int) -> str:
    if node.text is None:
        head = node.data[:max(4, width // 3)].hex(" ")
        return f"<{len(node.data)} bytes: {head}…>"
    s = re.sub(r"\s+", " ", node.text.strip())
    return s if width <= 0 or len(s) <= width else s[:width - 1] + "…"


def _render(result: Result, args, st: Style) -> str:
    lines: List[str] = []
    shown = result.candidates[:max(1, args.top)]
    if not shown:
        shown = [result.root]
    width = 0 if args.verbose else 64
    for rank, node in enumerate(shown, 1):
        chain = node.chain()
        if args.top > 1:
            lines.append(st.bold(f"── Candidate {rank} ") +
                         st.dim(f"(score {node.score:.1f})"))
        if not chain:
            lines.append(st.yellow("No encoding detected: the input already "
                                   "looks like the most plausible plaintext."))
        else:
            plural = "s" if len(chain) > 1 else ""
            lines.append(st.bold(f"{len(chain)} layer{plural} peeled off:"))
            pad = max(len(n.label) for n in chain)
            for i, step in enumerate(chain, 1):
                lines.append(f"  {st.cyan(f'[{i}]')} {step.label.ljust(pad)}  "
                             f"{st.dim('→')} {st.dim(_preview(step, width))}")
        lines.append("")
        lines.append(st.bold("Result:"))
        lines.append(st.green(node.text if node.text is not None
                              else _preview(node, 0)))
        lines.append("")
    footer = (f"{result.explored} nodes explored in {result.elapsed:.2f}s, "
              f"{len(result.candidates)} readable candidates")
    if result.truncated:
        footer += " · " + st.red(f"search stopped early: {result.truncated}")
    lines.append(st.dim(footer))
    return "\n".join(lines)


def _as_json(result: Result, top: int) -> str:
    def dump(node: Node) -> dict:
        return {
            "score": round(node.score, 2),
            "depth": node.depth,
            "plaintext": node.text,
            "layers": [{"codec": s.codec, "label": s.label,
                        "output": s.text if s.text is not None else None,
                        "output_hex": None if s.text is not None else s.data.hex()}
                       for s in node.chain()],
        }
    return json.dumps({
        "input": result.root.text if result.root.text is not None
        else result.root.data.hex(),
        "explored": result.explored,
        "elapsed": round(result.elapsed, 3),
        "truncated": result.truncated,
        "candidates": [dump(n) for n in result.candidates[:max(1, top)]],
    }, ensure_ascii=False, indent=2)


def _list_codecs(st: Style) -> str:
    sections = [("Encodings", "text"), ("Binary layers", "binary"),
                ("Ciphers", "cipher"), ("Special", "special")]
    lines = []
    for title, kind in sections:
        lines.append(st.bold(title))
        for c in CODECS + EXTRA_CODECS:
            if c.kind == kind:
                lines.append(f"  {st.cyan(c.name.ljust(10))} {c.title}")
        lines.append("")
    count = len(CODECS) + 2
    lines.append(st.dim(f"{count} transformations. Names are the ones used by "
                        "--only, --exclude and --encode."))
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="rosetta5",
        description="Automated multi-layer decoder: detects and reverses up "
                    "to 5 levels of nested encodings and classical ciphers.",
        epilog="examples:\n"
               "  rosetta5 'NjY2YzYxNjc3YjY4NjU2YzZjNmY3ZA=='\n"
               "  echo 'aGVsbG8gd29ybGQ=' | rosetta5 -q\n"
               "  rosetta5 -f challenge.txt -n 3 -v\n"
               "  rosetta5 -e 'rot13,base64,hex' 'attack at dawn'\n",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("input", nargs="?", help="string to decode (default: stdin)")
    p.add_argument("-f", "--file", help="read the input from a file")
    p.add_argument("-d", "--depth", type=int, default=MAX_DEPTH_DEFAULT,
                   help=f"maximum number of layers (default {MAX_DEPTH_DEFAULT}, "
                        f"max {MAX_DEPTH_LIMIT})")
    p.add_argument("-n", "--top", type=int, default=1, metavar="N",
                   help="show the N best candidates (default 1)")
    p.add_argument("-k", "--key", action="append", default=[], metavar="KEY",
                   help="key to try for Vigenère and repeating-key XOR "
                        "(text or 0xHEX, repeatable)")
    p.add_argument("--flag", metavar="REGEX",
                   help="regex of the expected plaintext, e.g. 'HTB\\{.*\\}'")
    p.add_argument("--only", metavar="LIST", default="",
                   help="comma-separated codecs to use exclusively")
    p.add_argument("--exclude", metavar="LIST", default="",
                   help="comma-separated codecs to disable")
    p.add_argument("-e", "--encode", metavar="CHAIN",
                   help="encode instead of decoding, e.g. 'rot13,base64,hex'")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="print only the best plaintext")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="do not truncate intermediate values")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("-l", "--list", action="store_true",
                   help="list the supported transformations and exit")
    p.add_argument("--timeout", type=float, default=TIMEOUT_DEFAULT,
                   help=f"search time budget in seconds (default {TIMEOUT_DEFAULT:g})")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    p.add_argument("-V", "--version", action="version",
                   version=f"rosetta5 {__version__}")
    return p


def _read_input(args) -> bytes:
    if args.file:
        with open(args.file, "rb") as fh:
            raw = fh.read()
    elif args.input is not None:
        raw = args.input.encode("utf-8", "surrogateescape")
    elif not sys.stdin.isatty():
        raw = sys.stdin.buffer.read()
    else:
        raise ValueError("no input: pass a string, use -f FILE or pipe data in")
    # Text input: surrounding whitespace is never part of the message.
    return raw.strip() if as_text(raw) is not None else raw


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    st = Style(not args.no_color and sys.stdout.isatty()
               and "NO_COLOR" not in os.environ)
    if args.list:
        print(_list_codecs(st))
        return 0
    try:
        data = _read_input(args)
        if not data:
            raise ValueError("empty input")
        if args.encode:
            sys.stdout.buffer.write(encode_chain(data, args.encode) + b"\n")
            return 0
        engine = Rosetta(
            max_depth=args.depth, keys=args.key, flag=args.flag,
            only=[n for n in args.only.split(",") if n.strip()],
            exclude=[n for n in args.exclude.split(",") if n.strip()],
            timeout=args.timeout)
        result = engine.decode(data)
    except (ValueError, OSError, re.error, UnicodeError) as exc:
        print(f"rosetta5: error: {exc}", file=sys.stderr)
        return 2
    best = result.best
    if args.json:
        print(_as_json(result, args.top))
    elif args.quiet:
        if best.text is not None:
            print(best.text)
        else:
            sys.stdout.buffer.write(best.data)
    else:
        print(_render(result, args, st))
    return 0 if best.depth > 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except BrokenPipeError:
        sys.exit(0)
