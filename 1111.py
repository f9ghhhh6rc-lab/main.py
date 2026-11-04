# -*- coding: utf-8 -*-
import asyncio
import glob
import json
import os
import random
import re
import sys
import threading
import time
from dataclasses import dataclass, field
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional
import logging

logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(name)s: %(message)s")

CRYPTO_BACKEND = "tgcrypto"


def _install_fast_aes():
    """\u0644\u0648 tgcrypto \u0645\u0648 \u0645\u0646\u0635\u0651\u0628: \u0646\u0631\u0643\u0651\u0628 \u0628\u062f\u064a\u0644 \u0633\u0631\u064a\u0639 (\u0645\u0643\u062a\u0628\u0629 C) \u0628\u062f\u0644 \u0627\u0644\u062a\u0634\u0641\u064a\u0631 \u0627\u0644\u0628\u0637\u064a\u0621 \u0628\u0627\u0644\u0628\u0627\u064a\u062b\u0648\u0646."""
    global CRYPTO_BACKEND
    try:
        import tgcrypto  # noqa: F401
        CRYPTO_BACKEND = "tgcrypto"
        return
    except Exception:
        pass

    ecb = None
    for mod, attr in (("Cryptodome.Cipher", "AES"), ("Crypto.Cipher", "AES")):
        try:
            AES = getattr(__import__(mod, fromlist=[attr]), attr)

            def ecb(key, AES=AES):
                c = AES.new(key, AES.MODE_ECB)
                return c.encrypt, c.decrypt

            CRYPTO_BACKEND = "pycryptodome"
            break
        except Exception:
            continue
    if ecb is None:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

            def ecb(key):
                cipher = Cipher(algorithms.AES(key), modes.ECB())
                return cipher.encryptor().update, cipher.decryptor().update

            CRYPTO_BACKEND = "cryptography"
        except Exception:
            CRYPTO_BACKEND = "pyaes (\u0628\u0637\u064a\u0621)"
            return

    import types

    def _ige(data, key, iv, encrypt):
        e, d = ecb(bytes(key))
        fb = int.from_bytes
        data = bytes(data)
        if len(data) % 16:
            raise ValueError("data length must be a multiple of 16")
        a = fb(iv[:16], "big")
        b = fb(iv[16:32], "big")
        out = bytearray(len(data))
        for i in range(0, len(data), 16):
            x = fb(data[i:i + 16], "big")
            if encrypt:
                y = fb(e((x ^ a).to_bytes(16, "big")), "big") ^ b
                out[i:i + 16] = y.to_bytes(16, "big")
                a, b = y, x
            else:
                pl = fb(d((x ^ b).to_bytes(16, "big")), "big") ^ a
                out[i:i + 16] = pl.to_bytes(16, "big")
                a, b = x, pl
        return bytes(out)

    def _ctr_unsupported(*args, **kwargs):
        raise NotImplementedError("ctr256 \u063a\u064a\u0631 \u0645\u062f\u0639\u0648\u0645 \u0641\u064a \u0627\u0644\u0628\u062f\u064a\u0644")

    shim = types.ModuleType("tgcrypto")
    shim.ige256_encrypt = lambda data, key, iv: _ige(data, key, iv, True)
    shim.ige256_decrypt = lambda data, key, iv: _ige(data, key, iv, False)
    shim.ctr256_encrypt = _ctr_unsupported
    shim.ctr256_decrypt = _ctr_unsupported
    sys.modules["tgcrypto"] = shim


_install_fast_aes()


def _tune_malloc():
    """\u064a\u0642\u0644\u0644 \u0639\u062f\u062f \u0645\u0646\u0627\u0637\u0642 \u0627\u0644\u0630\u0627\u0643\u0631\u0629 (arenas) = \u0631\u0627\u0645 \u0623\u0642\u0644 \u0639\u0644\u0649 \u0627\u0644\u0627\u0633\u062a\u0636\u0627\u0641\u0627\u062a \u0627\u0644\u0636\u0639\u064a\u0641\u0629."""
    try:
        import ctypes
        libc = ctypes.CDLL("libc.so.6")
        libc.mallopt(-8, 2)          # M_ARENA_MAX = 2
        return libc
    except Exception:
        return None


_libc = _tune_malloc()


def ram_mb():
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) // 1024
    except Exception:
        pass
    return -1


def new_client(name, **kw):
    """\u0639\u0645\u064a\u0644 \u062e\u0641\u064a\u0641: \u0643\u0627\u0634 \u0631\u0633\u0627\u0626\u0644 \u0635\u063a\u064a\u0631 (\u064a\u0648\u0641\u0631 \u0631\u0627\u0645) \u0645\u0639 \u0631\u062c\u0648\u0639 \u062a\u0644\u0642\u0627\u0626\u064a \u0644\u0648 \u0627\u0644\u0646\u0633\u062e\u0629 \u0645\u0627 \u062a\u062f\u0639\u0645\u0647."""
    base = dict(api_id=API_ID, api_hash=API_HASH, workdir=WORKDIR, workers=4)
    try:
        return Client(name, max_message_cache_size=300, **base, **kw)
    except TypeError:
        return Client(name, **base, **kw)


def tune_storage(app):
    """WAL + synchronous=NORMAL: \u0643\u062a\u0627\u0628\u0629 \u0627\u0644\u062c\u0644\u0633\u0629 \u0628\u062f\u0648\u0646 fsync \u0643\u0644 \u0645\u0631\u0629 (\u064a\u0645\u0646\u0639 \u062a\u062c\u0645\u064a\u062f \u0627\u0644\u0644\u0648\u0628 \u0639\u0644\u0649 \u0627\u0644\u0623\u0642\u0631\u0627\u0635 \u0627\u0644\u0628\u0637\u064a\u0626\u0629)."""
    try:
        conn = app.storage.conn
        conn.commit()                       # \u0644\u0627\u0632\u0645 \u0645\u0627 \u064a\u0643\u0648\u0646 \u0641\u064a\u0647 transaction \u0645\u0641\u062a\u0648\u062d
        conn.execute("PRAGMA journal_mode=WAL")
        conn.commit()
        conn.execute("PRAGMA synchronous=NORMAL")
    except Exception as e:
        print(f"[KIRA] storage tune skipped: {e}")


LAG = {"now": 0, "max": 0}
BOOTS = {"n24": 0}
BOOTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "boots.json")


def record_boot():
    now = time.time()
    lst = []
    try:
        with open(BOOTS_FILE, "r", encoding="utf-8") as f:
            lst = [float(t) for t in json.load(f)]
    except Exception:
        pass
    lst = [t for t in lst if now - t < 172800][-30:] + [now]
    try:
        with open(BOOTS_FILE, "w", encoding="utf-8") as f:
            json.dump(lst, f)
    except Exception:
        pass
    BOOTS["n24"] = len([t for t in lst if now - t < 86400])


async def lag_monitor():
    """\u064a\u0642\u064a\u0633 \u062a\u0623\u062e\u0631 \u062d\u0644\u0642\u0629 \u0627\u0644\u0633\u0648\u0631\u0633: \u0644\u0648 \u0627\u0644\u0631\u0642\u0645 \u0643\u0628\u064a\u0631 = \u0627\u0644\u0633\u0648\u0631\u0633 \u0646\u0641\u0633\u0647 \u0645\u0634\u063a\u0648\u0644/\u0645\u062e\u0646\u0648\u0642."""
    last = time.perf_counter()
    worst = 0.0
    window = time.time()
    warned = 0.0
    while True:
        await asyncio.sleep(1)
        now = time.perf_counter()
        lag = max(0.0, (now - last - 1.0) * 1000)
        last = now
        LAG["now"] = int(lag)
        worst = max(worst, lag)
        if time.time() - window > 60:
            LAG["max"], worst, window = int(worst), 0.0, time.time()
        if lag > 1500 and time.time() - warned > 30:
            warned = time.time()
            print(f"[KIRA] \u062a\u062d\u0630\u064a\u0631: \u0627\u0644\u0633\u0648\u0631\u0633 \u062a\u0623\u062e\u0631 {int(lag)}ms (\u0627\u0644\u0645\u0639\u0627\u0644\u062c \u0623\u0648 \u0627\u0644\u0631\u0627\u0645 \u0645\u062e\u0646\u0648\u0642)")


async def memory_keeper():
    """\u0643\u0644 \u062f\u0642\u064a\u0642\u062a\u064a\u0646: \u064a\u0646\u0638\u0641 \u0627\u0644\u0630\u0627\u0643\u0631\u0629 \u0648\u064a\u0631\u062c\u0651\u0639 \u0627\u0644\u0645\u062d\u0631\u0631 \u0645\u0646\u0647\u0627 \u0644\u0644\u0646\u0638\u0627\u0645."""
    import gc
    while True:
        await asyncio.sleep(120)
        try:
            gc.collect()
            if _libc is not None:
                _libc.malloc_trim(0)
        except Exception:
            pass


from pyrogram import Client, filters, idle, raw
from pyrogram.enums import ParseMode, MessageEntityType
from pyrogram.errors import (
    FloodWait, SessionPasswordNeeded, PhoneCodeInvalid, PhoneCodeExpired,
    PasswordHashInvalid, PhoneNumberInvalid,
)
from pyrogram.handlers import MessageHandler, CallbackQueryHandler
from pyrogram.types import InlineKeyboardMarkup, InlineKeyboardButton

BOT_TOKEN = "9152910155:AAFysc0Vlync9m68lc8e4L25hBh9IvA1Wfg"
API_ID = 38313735
API_HASH = "da9458168f0d3bc7ef07fc56ed25266b"
OWNER_ID = 8714252594

WORKDIR = os.path.dirname(os.path.abspath(__file__))
START_TIME = time.time()

SOURCE_NAME = "\u0647\u0633\u062a\u0631\u0647"      # \u0627\u0633\u0645 \u0627\u0644\u0633\u0648\u0631\u0633 (\u064a\u0638\u0647\u0631 \u0641\u064a \u0643\u0644\u064a\u0634\u0629 \u0627\u0644\u0623\u0648\u0627\u0645\u0631)
DEV_NAME = "\u0647\u0633\u062a\u0631\u0647"         # \u0627\u0633\u0645 \u0645\u0637\u0648\u0631 \u0627\u0644\u0633\u0648\u0631\u0633 (\u064a\u0638\u0647\u0631 \u0641\u064a \u0643\u0644\u064a\u0634\u0629 \u0627\u0644\u0623\u0648\u0627\u0645\u0631)
SUBS_FILE = os.path.join(WORKDIR, "subs.json")

# \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550 \u0627\u0644\u0646\u0635\u0648\u0635 (\u0643\u0644\u0647\u0627 \u0628\u064a\u0646 \u062b\u0644\u0627\u062b \u0639\u0644\u0627\u0645\u0627\u062a \u0627\u0642\u062a\u0628\u0627\u0633) \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

T_HELP = """\U0001f525 **\u0633\u0648\u0631\u0633 {src}** \U0001f525
\u0645\u0631\u062d\u0628\u0627\u064b \u0641\u064a\u0643 \u064a\u0627 **{who}** \U0001f44b
\u0627\u0644\u0645\u0646\u0635\u0651\u0628 \u0648\u0627\u0644\u0645\u0633\u062a\u062e\u062f\u0645 \u0644\u0644\u0633\u0648\u0631\u0633 \u0628\u062d\u0633\u0627\u0628\u0647
\U0001f468\u200d\U0001f4bb \u0645\u0637\u0648\u0631 \u0627\u0644\u0633\u0648\u0631\u0633: **{dev}**
\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501
\U0001f4c2 **\u0627\u0644\u0623\u0642\u0633\u0627\u0645:** \u062a\u0643 | \u0637\u0634 | \u0635\u0639 | \u0636\u062f | \u0648\u064a\u0643 | \u0639\u0634 | \u0645\u0642 | \u062c\u0631 | \u0639\u0643 | \u062f\u0628 | \u062c\u0645

\U0001f3ae **\u0627\u0644\u0645\u062d\u0627\u0643\u064a:**
1\ufe0f\u20e3 `.\u0645\u062d\u0627\u0643\u064a` - \u0631\u062f \u0628\u0647\u0627 \u0639\u0644\u0649 \u0631\u0633\u0627\u0644\u0629 \u0627\u0644\u0628\u0648\u062a \u0644\u062a\u062d\u062f\u064a\u062f\u0647 (\u0623\u0648 `.\u0645\u062d\u0627\u0643\u064a @bot`)
2\ufe0f\u20e3 `.\u0628\u0644\u0634` - \u0628\u062f\u0621 \u0627\u0644\u0644\u0639\u0628 \u0628\u0633\u0631\u0639\u0629 \u0643\u0644 \u0642\u0633\u0645
3\ufe0f\u20e3 `.\u0641\u0643\u0643` - \u062a\u0641\u0643\u064a\u0643 \u0641\u0648\u0631\u064a (\u0628\u0627\u0644\u0631\u062f \u0639\u0644\u0649 \u0631\u0633\u0627\u0644\u0629 = \u0645\u0631\u0629 \u0648\u062d\u062f\u0629)
4\ufe0f\u20e3 `.\u0648\u0642\u0641` - \u0625\u064a\u0642\u0627\u0641 \u0627\u0644\u0644\u0639\u0628 \u0648\u0627\u0644\u062a\u0643\u0631\u0627\u0631

\U0001f501 **\u0627\u0644\u062a\u0643\u0631\u0627\u0631:**
\u2022 `.\u062a\u0643\u0631\u0627\u0631 \u0637\u0634 70` - \u064a\u0631\u0633\u0644 `\u0637\u0634` \u0643\u0644 70 \u062b\u0627\u0646\u064a\u0629 \u0648\u064a\u0644\u0639\u0628 \u0648\u064a\u062c\u0627\u0648\u0628
\u2022 `.\u062a\u0643\u0631\u0627\u0631 \u0648\u0642\u0641` - \u0625\u064a\u0642\u0627\u0641 \u0627\u0644\u062a\u0643\u0631\u0627\u0631 \u0641\u0642\u0637

\u26a1 **\u0627\u0644\u0633\u0631\u0639\u0629:**
\u2022 `.\u0633\u0631\u0639\u0629` - \u0639\u0631\u0636 \u0633\u0631\u0639\u0629 \u0643\u0644 \u0627\u0644\u0623\u0642\u0633\u0627\u0645
\u2022 `.\u0633\u0631\u0639\u0629 \u0637\u0634 3` - \u0633\u0631\u0639\u0629 \u0642\u0633\u0645 \u0645\u0639\u064a\u0651\u0646
\u2022 `.\u0633\u0631\u0639\u0629 5.55` - \u0627\u0644\u0633\u0631\u0639\u0629 \u0627\u0644\u0627\u0641\u062a\u0631\u0627\u0636\u064a\u0629 \u0644\u0628\u0627\u0642\u064a \u0627\u0644\u0623\u0642\u0633\u0627\u0645
\u2022 `.\u0633\u0631\u0639\u0629 \u0645\u0633\u062d` - \u0645\u0633\u062d \u0633\u0631\u0639\u0627\u062a \u0627\u0644\u0623\u0642\u0633\u0627\u0645

\u2699\ufe0f **\u0623\u0648\u0627\u0645\u0631 \u062b\u0627\u0646\u064a\u0629:**
\u2022 `.\u0639\u0634\u0648\u0627\u0626\u064a 0.5` - \u062a\u0623\u062e\u064a\u0631 \u0639\u0634\u0648\u0627\u0626\u064a \u0625\u0636\u0627\u0641\u064a
\u2022 `.\u0643\u0648\u062f` - \u062a\u0634\u063a\u064a\u0644 \u0623\u0648 \u0625\u064a\u0642\u0627\u0641 \u062d\u0644 \u0627\u0644\u0646\u0635\u0648\u0635 \u062f\u0627\u062e\u0644 \u0627\u0644\u0643\u0648\u062f
\u2022 `.\u0641\u062d\u0635` - \u062d\u0627\u0644\u0629 \u0627\u0644\u0633\u0648\u0631\u0633
\u2022 `.\u0627\u062d\u0635\u0627\u0626\u064a\u0627\u062a` - \u0639\u062f\u062f \u0627\u0644\u0625\u062c\u0627\u0628\u0627\u062a
\u2022 `.\u0642\u0633\u0645\u064a` - \u0627\u0644\u0623\u0642\u0633\u0627\u0645
\u2022 `.\u0628\u0646\u0642` - \u0633\u0631\u0639\u0629 \u0627\u0644\u0627\u062a\u0635\u0627\u0644
\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501
\u26a1 \u0627\u0644\u0633\u0631\u0639\u0629 \u0627\u0644\u0627\u0641\u062a\u0631\u0627\u0636\u064a\u0629: `{delay}` \u062b
\U0001f516 \u0627\u0644\u0627\u0634\u062a\u0631\u0627\u0643: {sub}"""

T_SPEED_ERR = """\u26a0\ufe0f \u0627\u0643\u062a\u0628 \u0631\u0642\u0645 \u0635\u062d\u064a\u062d \u0645\u062b\u0644 `.\u0633\u0631\u0639\u0629 5.55` \u0623\u0648 `.\u0633\u0631\u0639\u0629 \u0637\u0634 3`
\u0627\u0644\u0627\u0641\u062a\u0631\u0627\u0636\u064a\u0629 \u0627\u0644\u062d\u0627\u0644\u064a\u0629: `{v}` \u062b"""

T_SPEEDS = """\u26a1 **\u0633\u0631\u0639\u0629 \u0627\u0644\u0625\u062c\u0627\u0628\u0629 \u0644\u0643\u0644 \u0642\u0633\u0645** (\u062b\u0627\u0646\u064a\u0629):
{body}
\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501
\u0627\u0644\u0627\u0641\u062a\u0631\u0627\u0636\u064a: `{d}` \u062b | \u0639\u0634\u0648\u0627\u0626\u064a: \u062d\u062a\u0649 `{j}` \u062b
\u0645\u062b\u0627\u0644: `.\u0633\u0631\u0639\u0629 \u0637\u0634 3`"""

T_SPEED_GAME_OK = """\u26a1 **\u0633\u0631\u0639\u0629 \u0642\u0633\u0645** `{g}` **\u0635\u0627\u0631\u062a** `{v}` \u062b\u0627\u0646\u064a\u0629 \u2705"""

T_SPEED_CLEAR = """\U0001f9f9 **\u062a\u0645 \u0645\u0633\u062d \u0633\u0631\u0639\u0627\u062a \u0627\u0644\u0623\u0642\u0633\u0627\u0645** - \u0627\u0644\u0643\u0644 \u0639\u0644\u0649 \u0627\u0644\u0627\u0641\u062a\u0631\u0627\u0636\u064a `{d}` \u062b \u2705"""

T_REP_ERR = """\u26a0\ufe0f \u0645\u062b\u0627\u0644: `.\u062a\u0643\u0631\u0627\u0631 \u0637\u0634 70`
\u0623\u0642\u0644 \u0645\u062f\u0629: `{m}` \u062b\u0627\u0646\u064a\u0629
\u0644\u0644\u0625\u064a\u0642\u0627\u0641: `.\u062a\u0643\u0631\u0627\u0631 \u0648\u0642\u0641`"""

T_REP_ON = """\U0001f501 **\u0628\u062f\u0623 \u0627\u0644\u062a\u0643\u0631\u0627\u0631**
\u2022 \u0627\u0644\u0643\u0644\u0645\u0629: `{w}`
\u2022 \u0643\u0644: `{i}` \u062b\u0627\u0646\u064a\u0629
\u2022 \u0633\u0631\u0639\u0629 \u0627\u0644\u0625\u062c\u0627\u0628\u0629: `{d}` \u062b\u0627\u0646\u064a\u0629
\u0627\u0643\u062a\u0628 `.\u062a\u0643\u0631\u0627\u0631 \u0648\u0642\u0641` \u0623\u0648 `.\u0648\u0642\u0641` \u0644\u0644\u0625\u064a\u0642\u0627\u0641."""

T_REP_OFF = """\u23f9 **\u062a\u0645 \u0625\u064a\u0642\u0627\u0641 \u0627\u0644\u062a\u0643\u0631\u0627\u0631.**"""

T_REP_NONE = """\u2139\ufe0f \u0645\u0627 \u0641\u064a\u0647 \u062a\u0643\u0631\u0627\u0631 \u0634\u063a\u0651\u0627\u0644."""

T_SPEED_OK = """\u26a1 **\u062a\u0645 \u062a\u062d\u062f\u064a\u062b \u0627\u0644\u062a\u0648\u0642\u064a\u062a \u0625\u0644\u0649** `{v}` \u062b\u0627\u0646\u064a\u0629 \u2705"""

T_JIT_ERR = """\u26a0\ufe0f \u0645\u062b\u0627\u0644: `.\u0639\u0634\u0648\u0627\u0626\u064a 0.5`
\u0627\u0644\u062d\u0627\u0644\u064a: `{v}`"""

T_JIT_OK = """\U0001f3b2 **\u0627\u0644\u062a\u0623\u062e\u064a\u0631 \u0627\u0644\u0639\u0634\u0648\u0627\u0626\u064a:** \u062d\u062a\u0649 `{v}` \u062b\u0627\u0646\u064a\u0629 \u2705"""

T_CODE = """\U0001f4bb **\u062d\u0644 \u0627\u0644\u0646\u0635\u0648\u0635 \u062f\u0627\u062e\u0644 \u0627\u0644\u0643\u0648\u062f:** {status}"""
T_ON = """\U0001f7e2 \u0634\u063a\u0627\u0644"""
T_OFF = """\U0001f534 \u0645\u062a\u0648\u0642\u0641"""

T_SIM_SET = """\U0001f3af **\u062a\u0645 \u062a\u062d\u062f\u064a\u062f \u0627\u0644\u0628\u0648\u062a \u0627\u0644\u0645\u0633\u062a\u0647\u062f\u0641:** `{t}`

\u0627\u0643\u062a\u0628 `.\u0641\u0643\u0643` \u0644\u0644\u062a\u0641\u0643\u064a\u0643 \u0627\u0644\u0641\u0648\u0631\u064a \u0623\u0648 `.\u0628\u0644\u0634 1.5` \u0644\u0644\u0639\u0628 \u0628\u0627\u0644\u062a\u0648\u0642\u064a\u062a."""

T_NEED_TARGET = """\u26a0\ufe0f \u0631\u062f \u0639\u0644\u0649 \u0631\u0633\u0627\u0644\u0629 \u0627\u0644\u0628\u0648\u062a \u0628\u0627\u0644\u0623\u0645\u0631 `.\u0645\u062d\u0627\u0643\u064a` \u0623\u0648 \u0627\u0643\u062a\u0628 `.\u0645\u062d\u0627\u0643\u064a @bot`"""

T_DECODE_ON = """\u26a1 **\u062a\u0645 \u062a\u0634\u063a\u064a\u0644 \u0627\u0644\u062a\u0641\u0643\u064a\u0643 \u0627\u0644\u0641\u0648\u0631\u064a** \u0641\u064a \u0647\u0630\u0647 \u0627\u0644\u0645\u062d\u0627\u062f\u062b\u0629
\u0627\u0643\u062a\u0628 `.\u0648\u0642\u0641` \u0644\u0644\u0625\u064a\u0642\u0627\u0641."""

T_PLAY_ON = """\U0001f3ae **\u0628\u062f\u0623 \u0627\u0644\u0644\u0639\u0628** - \u0627\u0644\u0625\u062c\u0627\u0628\u0629 \u0628\u062d\u0633\u0628 \u0633\u0631\u0639\u0629 \u0643\u0644 \u0642\u0633\u0645 (\u0627\u0644\u0627\u0641\u062a\u0631\u0627\u0636\u064a `{d}` \u062b)
\u0627\u0643\u062a\u0628 `.\u0648\u0642\u0641` \u0644\u0644\u0625\u064a\u0642\u0627\u0641."""

T_PLAY_ERR = """\u26a0\ufe0f \u0627\u0643\u062a\u0628 \u0627\u0644\u0648\u0642\u062a \u0631\u0642\u0645\u0627\u064b \u0645\u062b\u0644 `.\u0628\u0644\u0634 1.5`"""

T_NO_ANSWER = """\u26a0\ufe0f \u0645\u0627 \u0642\u062f\u0631\u062a \u0623\u0641\u0643\u0643 \u0647\u0630\u064a \u0627\u0644\u0631\u0633\u0627\u0644\u0629\u060c \u0645\u0627 \u0641\u064a\u0647\u0627 \u0641\u0648\u0627\u0635\u0644 \u0623\u0648 \u0623\u0642\u0648\u0627\u0633."""

T_STOP = """\U0001f6d1 **\u062a\u0645 \u0625\u064a\u0642\u0627\u0641 \u0627\u0644\u0644\u0639\u0628.**"""

T_CHECK = """\U0001f50d **\u062a\u0642\u0631\u064a\u0631 \u0641\u062d\u0635 \u0627\u0644\u0633\u0648\u0631\u0633:**
\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501
\u2022 \u0627\u0644\u062d\u0633\u0627\u0628: `{name}`
\u2022 \u0627\u0644\u062d\u0627\u0644\u0629: {state}
\u2022 \u0627\u0644\u0648\u0636\u0639: {mode}
\u2022 \u0627\u0644\u0628\u0648\u062a \u0627\u0644\u0645\u0633\u062a\u0647\u062f\u0641: `{target}`
\u2022 \u0627\u0644\u0633\u0631\u0639\u0629 \u0627\u0644\u0627\u0641\u062a\u0631\u0627\u0636\u064a\u0629: `{rdelay}` \u062b + \u0639\u0634\u0648\u0627\u0626\u064a `{jitter}`
\u2022 \u0627\u0644\u062a\u0643\u0631\u0627\u0631: {rep}
\u2022 \u0627\u0644\u0627\u0634\u062a\u0631\u0627\u0643: {sub}
\u2022 \u0627\u0644\u0628\u0646\u0642: `{ping}ms` \U0001f4e1
\u2022 \u0627\u0644\u0631\u0627\u0645: `{ram}` MB
\u2022 \u062a\u0623\u062e\u0631 \u0627\u0644\u0645\u0639\u0627\u0644\u062c\u0629: `{lag}` ms
\u2022 \u0627\u0644\u062a\u0634\u0641\u064a\u0631: `{crypto}`
\u2022 \u0625\u0639\u0627\u062f\u0629 \u0627\u0644\u062a\u0634\u063a\u064a\u0644 (24\u0633): `{boots}`
\u2022 \u0627\u0644\u0625\u062c\u0627\u0628\u0627\u062a \u0627\u0644\u0645\u0631\u0633\u0644\u0629: `{solved}`
\u2022 \u0645\u062f\u0629 \u0627\u0644\u062a\u0634\u063a\u064a\u0644: `{uptime}`"""

T_STATE_ON = """\U0001f7e2 \u0645\u0641\u0639\u0651\u0644 \u0648\u0634\u063a\u0627\u0644"""
T_STATE_OFF = """\U0001f534 \u0645\u062a\u0648\u0642\u0641"""
T_MODE_OFF = """-"""
T_MODE_DECODE = """\u0641\u0643\u0643 (\u0641\u0648\u0631\u064a)"""
T_MODE_PLAY = """\u0628\u0644\u0634 (\u0628\u062a\u0648\u0642\u064a\u062a)"""
T_NO_TARGET = """\u0643\u0644 \u0627\u0644\u0628\u0648\u062a\u0627\u062a \u0641\u064a \u0627\u0644\u0645\u062d\u0627\u062f\u062b\u0629"""

T_STATS = """\U0001f4ca **\u0627\u0644\u0625\u062d\u0635\u0627\u0626\u064a\u0627\u062a:**
\u2022 \u0627\u0644\u0625\u062c\u0627\u0628\u0627\u062a \u0627\u0644\u0645\u0631\u0633\u0644\u0629: `{solved}`
\u2022 \u0645\u062f\u0629 \u0627\u0644\u062a\u0634\u063a\u064a\u0644: `{uptime}`"""

T_SECTIONS = """\U0001f4c2 **\u0623\u0642\u0633\u0627\u0645 \u0628\u0648\u062a \u0643\u064a\u0631\u0627:**

\u2022 \u062a\u0643 | \u0637\u0634 | \u0635\u0639 | \u0636\u062f | \u0648\u064a\u0643 | \u0639\u0634 | \u0645\u0642 | \u062c\u0631 | \u0639\u0643 | \u062f\u0628 | \u062c\u0645"""

T_PING = """\U0001f3d3 **Pong!** `{ms}ms`
\u23f1 \u062a\u0623\u062e\u0631 \u0627\u0644\u0645\u0639\u0627\u0644\u062c\u0629: `{lag}` ms"""

T_UPTIME = """{h}\u0633 {m}\u062f {s}\u062b"""

T_WELCOME = """\U0001f916 **\u0623\u0647\u0644\u0627\u064b \u0628\u0643 \u0641\u064a \u0646\u0638\u0627\u0645 \u0647\u0633\u062a\u0631\u0647 \u0627\u0644\u0634\u0627\u0645\u0644 \u0644\u0644\u0623\u0644\u0639\u0627\u0628** \u2728
\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501
\u2022 \u0627\u0644\u0628\u0648\u062a \u0644\u0644\u062a\u0633\u062c\u064a\u0644 \u0641\u0642\u0637\u060c \u0648\u0627\u0644\u062a\u062d\u0643\u0645 \u0643\u0644\u0647 \u0645\u0646 \u062d\u0633\u0627\u0628\u0643.
\u2022 \u0623\u0631\u0633\u0644 `.\u0627\u0644\u0627\u0648\u0627\u0645\u0631` \u0645\u0646 \u0623\u064a \u062d\u0633\u0627\u0628 \u0645\u0633\u062c\u0651\u0644 \u0644\u0639\u0631\u0636 \u0627\u0644\u0623\u0648\u0627\u0645\u0631."""

T_BOOT = """\U0001f50c \u062c\u0627\u0631\u064a \u062a\u0634\u063a\u064a\u0644 \u0627\u0644\u0646\u0638\u0627\u0645..."""

T_ASK_PHONE = """\U0001f4f1 \u0623\u0631\u0633\u0644 **\u0631\u0642\u0645 \u0647\u0627\u062a\u0641\u0643** \u0645\u0639 \u0631\u0645\u0632 \u0627\u0644\u062f\u0648\u0644\u0629
\u0645\u062b\u0627\u0644: `+9665xxxxxxxx`"""

T_LIST = """\U0001f4cb **\u0627\u0644\u062d\u0633\u0627\u0628\u0627\u062a:**

{body}"""

T_NO_ACCOUNTS = """\u0644\u0627 \u062a\u0648\u062c\u062f \u062d\u0633\u0627\u0628\u0627\u062a \u0634\u063a\u0651\u0627\u0644\u0629."""

T_BAD_PHONE = """\u274c \u0627\u0644\u0631\u0642\u0645 \u063a\u064a\u0631 \u0635\u062d\u064a\u062d\u060c \u0623\u0631\u0633\u0644\u0647 \u0645\u0639 \u0631\u0645\u0632 \u0627\u0644\u062f\u0648\u0644\u0629."""

T_EXISTS = """\u2705 \u0647\u0630\u0627 \u0627\u0644\u062d\u0633\u0627\u0628 \u0645\u0633\u062c\u0651\u0644 \u0645\u0633\u0628\u0642\u0627\u064b \u0648\u062a\u0645 \u062a\u0634\u063a\u064a\u0644\u0647."""

T_SEND_ERR = """\u274c \u062e\u0637\u0623 \u0623\u062b\u0646\u0627\u0621 \u0625\u0631\u0633\u0627\u0644 \u0627\u0644\u0643\u0648\u062f: `{e}`
\u0623\u0631\u0633\u0644 /start \u0644\u0644\u0645\u062d\u0627\u0648\u0644\u0629."""

T_CODE_SENT = """\u23f3 \u062a\u0645 \u0625\u0631\u0633\u0627\u0644 \u0627\u0644\u0643\u0648\u062f \u0644\u0644\u0631\u0642\u0645 `{phone}`

\U0001f511 \u0623\u0631\u0633\u0644 \u0627\u0644\u0643\u0648\u062f **\u0628\u0645\u0633\u0627\u0641\u0627\u062a \u0628\u064a\u0646 \u0627\u0644\u0623\u0631\u0642\u0627\u0645** \u0645\u062b\u0644: `1 2 3 4 5`
\u26a0\ufe0f \u0644\u0648 \u0623\u0631\u0633\u0644\u062a\u0647 \u0645\u062a\u0635\u0644 \u062a\u064a\u0644\u064a\u062c\u0631\u0627\u0645 \u064a\u0644\u063a\u064a\u0647."""

T_ASK_PASS = """\U0001f512 \u0627\u0644\u062d\u0633\u0627\u0628 \u0645\u062d\u0645\u064a \u0628\u0627\u0644\u062a\u062d\u0642\u0642 \u0628\u062e\u0637\u0648\u062a\u064a\u0646.
\u0623\u0631\u0633\u0644 **\u0643\u0644\u0645\u0629 \u0627\u0644\u0633\u0631**:"""

T_BAD_CODE = """\u274c \u0627\u0644\u0643\u0648\u062f \u063a\u064a\u0631 \u0635\u062d\u064a\u062d\u060c \u0623\u0639\u062f \u0625\u0631\u0633\u0627\u0644\u0647."""
T_EXPIRED = """\u231b \u0627\u0646\u062a\u0647\u062a \u0635\u0644\u0627\u062d\u064a\u0629 \u0627\u0644\u0643\u0648\u062f\u060c \u0627\u0628\u062f\u0623 \u0645\u0646 \u062c\u062f\u064a\u062f \u0628\u0640 /start"""
T_ERR = """\u274c \u062e\u0637\u0623: `{e}`"""
T_BAD_PASS = """\u274c \u0643\u0644\u0645\u0629 \u0627\u0644\u0633\u0631 \u063a\u064a\u0631 \u0635\u062d\u064a\u062d\u0629\u060c \u0623\u0639\u062f \u0627\u0644\u0645\u062d\u0627\u0648\u0644\u0629."""

T_DONE = """\u2705 **\u062a\u0645 \u062a\u0633\u062c\u064a\u0644 \u0648\u062a\u0634\u063a\u064a\u0644 \u0627\u0644\u062d\u0633\u0627\u0628** `{phone}` **\u0628\u0646\u062c\u0627\u062d!**

\u0627\u0643\u062a\u0628 `.\u0627\u0644\u0627\u0648\u0627\u0645\u0631` \u0645\u0646 \u0627\u0644\u062d\u0633\u0627\u0628 \u0644\u0644\u0628\u062f\u0621 \U0001f525"""

T_DONE_FAIL = """\u274c \u062a\u0645 \u0627\u0644\u062a\u0633\u062c\u064a\u0644 \u0644\u0643\u0646 \u062a\u0639\u0630\u0631 \u0627\u0644\u062a\u0634\u063a\u064a\u0644\u060c \u0623\u0639\u062f \u0627\u0644\u0645\u062d\u0627\u0648\u0644\u0629."""

T_BOT_ONLINE = """\u2705 **\u0647\u0633\u062a\u0631\u0647 \u0634\u063a\u0651\u0627\u0644** - \u0627\u0644\u062d\u0633\u0627\u0628\u0627\u062a: `{n}`"""

T_SUB_OFF = """\u26d4 **\u0627\u0644\u0627\u0634\u062a\u0631\u0627\u0643 \u063a\u064a\u0631 \u0641\u0639\u0651\u0627\u0644** ({s})
\u062a\u0648\u0627\u0635\u0644 \u0645\u0639 \u0645\u0637\u0648\u0631 \u0627\u0644\u0633\u0648\u0631\u0633 **{dev}** \u0644\u0644\u062a\u0641\u0639\u064a\u0644 \u0623\u0648 \u0627\u0644\u062a\u062c\u062f\u064a\u062f."""

T_SUB_ENDED_OWNER = """\u23f0 **\u0627\u0646\u062a\u0647\u0649 \u0627\u0634\u062a\u0631\u0627\u0643 \u0627\u0644\u062d\u0633\u0627\u0628** **{name}** \u0648\u062a\u0645 \u0625\u064a\u0642\u0627\u0641\u0647."""

T_SUB_ENDED_USER = """\u23f0 **\u0627\u0646\u062a\u0647\u0649 \u0627\u0634\u062a\u0631\u0627\u0643\u0643 \u0641\u064a \u0633\u0648\u0631\u0633 {src}.**
\u062a\u0648\u0627\u0635\u0644 \u0645\u0639 **{dev}** \u0644\u0644\u062a\u062c\u062f\u064a\u062f."""

T_ACC_PANEL = """\U0001f464 **{name}**
\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501
\U0001f516 \u0627\u0644\u0627\u0634\u062a\u0631\u0627\u0643: {status}"""

T_DONE_ACT = """

\u26a0\ufe0f \u0627\u0644\u062d\u0633\u0627\u0628 \u0628\u0627\u0646\u062a\u0638\u0627\u0631 \u0627\u0644\u062a\u0641\u0639\u064a\u0644\u060c \u0627\u062e\u062a\u0631 \u0627\u0644\u0645\u062f\u0629 \U0001f447"""

B_ADD = """\u2795 \u0625\u0636\u0627\u0641\u0629 \u062d\u0633\u0627\u0628"""
B_LIST = """\U0001f4cb \u062d\u0633\u0627\u0628\u0627\u062a\u064a"""
B_HELP = """\U0001f4d6 \u0627\u0644\u0623\u0648\u0627\u0645\u0631"""
B_HOME = """\U0001f3e0 \u0627\u0644\u0631\u0626\u064a\u0633\u064a\u0629"""
B_CANCEL = """\u274c \u0625\u0644\u063a\u0627\u0621"""

# \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550 \u0623\u0633\u0645\u0627\u0621 \u0627\u0644\u0623\u0648\u0627\u0645\u0631 \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

CMD = {
    "help": ["\u0627\u0644\u0627\u0648\u0627\u0645\u0631", "\u0627\u0648\u0627\u0645\u0631"],
    "speed": ["\u0633\u0631\u0639\u0629"],
    "jitter": ["\u0639\u0634\u0648\u0627\u0626\u064a"],
    "code": ["\u0643\u0648\u062f"],
    "sim": ["\u0645\u062d\u0627\u0643\u064a"],
    "decode": ["\u0641\u0643\u0643"],
    "play": ["\u0628\u0644\u0634"],
    "stop": ["\u0648\u0642\u0641"],
    "check": ["\u0641\u062d\u0635"],
    "stats": ["\u0627\u062d\u0635\u0627\u0626\u064a\u0627\u062a"],
    "sections": ["\u0642\u0633\u0645\u064a"],
    "ping": ["\u0628\u0646\u0642"],
    "repeat": ["\u062a\u0643\u0631\u0627\u0631"],
}

print("[KIRA] Initializing...")
sys.stdout.flush()


# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500 Health server \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
class HealthCheckHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Kira Master System is Online!")

    def log_message(self, format, *args):
        pass


def start_web_server():
    port = int(os.environ.get("PORT", 8080))
    try:
        HTTPServer(("0.0.0.0", port), HealthCheckHandler).serve_forever()
    except Exception:
        pass


threading.Thread(target=start_web_server, daemon=True).start()


# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500 State \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
@dataclass
class AccState:
    active: bool = False
    mode: str = "off"            # off | decode | play
    target_id: Optional[int] = None
    target_name: Optional[str] = None
    chat_id: Optional[int] = None
    delay: float = 5.55          # \u0627\u0644\u0633\u0631\u0639\u0629 \u0627\u0644\u0627\u0641\u062a\u0631\u0627\u0636\u064a\u0629 (\u0644\u0623\u064a \u0642\u0633\u0645 \u0645\u0627 \u0644\u0647 \u0633\u0631\u0639\u0629 \u062e\u0627\u0635\u0629)
    jitter: float = 0.0          # 0 = \u0627\u0644\u0633\u0631\u0639\u0629 \u062b\u0627\u0628\u062a\u0629 \u0628\u0627\u0644\u0636\u0628\u0637 (\u063a\u064a\u0651\u0631\u0647\u0627 \u0628\u0640 .\u0639\u0634\u0648\u0627\u0626\u064a)
    game_delays: dict = field(default_factory=dict)   # \u0633\u0631\u0639\u0629 \u0643\u0644 \u0642\u0633\u0645
    use_code: bool = True
    solved: int = 0
    started: float = field(default_factory=time.time)
    # ---- \u062c\u0648\u0644\u0627\u062a \u0627\u0644\u0644\u0639\u0628 (\u0625\u062c\u0627\u0628\u0629 \u0648\u062d\u062f\u0629 \u0644\u0643\u0644 \u0644\u0639\u0628\u0629) ----
    current_game: Optional[str] = None
    round_open: bool = False
    round_ts: float = 0.0
    foreign_pending: bool = False   # \u0644\u0627\u0639\u0628 \u062b\u0627\u0646\u064a \u0628\u062f\u0623 \u0644\u0639\u0628\u0629 \u0648\u0646\u0646\u062a\u0638\u0631 \u0633\u0624\u0627\u0644 \u0627\u0644\u0628\u0648\u062a
    foreign_ts: float = 0.0
    seen: dict = field(default_factory=dict)
    sigs: dict = field(default_factory=dict)
    pending: int = 0
    gen: int = 0                 # \u064a\u0632\u064a\u062f \u0639\u0646\u062f \u0627\u0644\u0625\u064a\u0642\u0627\u0641: \u064a\u0644\u063a\u064a \u0623\u064a \u0625\u062c\u0627\u0628\u0629 \u0645\u0639\u0644\u0651\u0642\u0629
    # ---- \u0627\u0644\u062a\u0643\u0631\u0627\u0631 ----
    repeat_word: Optional[str] = None
    repeat_interval: float = 0.0
    repeat_task: Optional[asyncio.Task] = None
    rgen: int = 0
    beat: float = 0.0
    # ---- \u062d\u0645\u0627\u064a\u0629 \u0627\u0644\u0625\u0631\u0633\u0627\u0644 ----
    last_send: float = 0.0
    me_id: Optional[int] = None
    display: Optional[str] = None
    username: Optional[str] = None
    send_lock: asyncio.Lock = field(default_factory=asyncio.Lock)


GAMES = ["\u062a\u0643", "\u0637\u0634", "\u0635\u0639", "\u0636\u062f", "\u0648\u064a\u0643", "\u0639\u0634", "\u0645\u0642", "\u062c\u0631", "\u0639\u0643", "\u062f\u0628", "\u062c\u0645"]
MIN_REPEAT = 20.0      # \u0623\u0642\u0644 \u0645\u062f\u0629 \u0628\u064a\u0646 \u0643\u0644 \u062a\u0643\u0631\u0627\u0631\u064a\u0646 (\u062d\u0645\u0627\u064a\u0629 \u0644\u0644\u062d\u0633\u0627\u0628)
ROUND_TTL = 120.0      # \u0643\u0645 \u062b\u0627\u0646\u064a\u0629 \u062a\u0628\u0642\u0649 \u0627\u0644\u062c\u0648\u0644\u0629 \u0635\u0627\u0644\u062d\u0629 \u0628\u0639\u062f \u0625\u0631\u0633\u0627\u0644 \u0627\u0644\u0643\u0644\u0645\u0629
FOREIGN_WAIT = 30.0    # \u0623\u0642\u0635\u0649 \u0627\u0646\u062a\u0638\u0627\u0631 \u0644\u0633\u0624\u0627\u0644 \u0644\u0639\u0628\u0629 \u0644\u0627\u0639\u0628 \u062b\u0627\u0646\u064a \u0642\u0628\u0644 \u0645\u0627 \u0646\u0631\u0633\u0644 \u0643\u0644\u0645\u062a\u0646\u0627
DEDUP_WINDOW = 30.0    # \u0645\u0646\u0639 \u062a\u0643\u0631\u0627\u0631 \u0646\u0641\u0633 \u0627\u0644\u0633\u0624\u0627\u0644
SEND_GAP = 1.0         # \u0623\u0642\u0644 \u0641\u0631\u0642 \u0628\u064a\u0646 \u0623\u064a \u0631\u0633\u0627\u0644\u062a\u064a\u0646 \u0646\u0631\u0633\u0644\u0647\u0645


states = {}
running = {}
running_ids = {}   # user_id -> \u0627\u0633\u0645 \u0627\u0644\u062c\u0644\u0633\u0629 (\u064a\u0645\u0646\u0639 \u062a\u0634\u063a\u064a\u0644 \u0646\u0641\u0633 \u0627\u0644\u062d\u0633\u0627\u0628 \u0645\u0631\u062a\u064a\u0646)
tasks = set()
login = {"state": None, "client": None, "phone": None, "hash": None, "name": None}

LOAD_FRAMES = ["\u23f3 \u25b1\u25b1\u25b1\u25b1\u25b1", "\u23f3 \u25b0\u25b0\u25b1\u25b1\u25b1", "\u23f3 \u25b0\u25b0\u25b0\u25b0\u25b1", "\u26a1 \u25b0\u25b0\u25b0\u25b0\u25b0"]


def settings_path(name):
    return os.path.join(WORKDIR, f"settings_{name}.json")


def load_settings(name, st):
    try:
        with open(settings_path(name), "r", encoding="utf-8") as f:
            d = json.load(f)
        st.delay = float(d.get("delay", st.delay))
        st.jitter = float(d.get("jitter", st.jitter)) if d.get("ver", 1) >= 2 else 0.0
        st.use_code = bool(d.get("use_code", st.use_code))
        st.game_delays = {str(k): float(v) for k, v in d.get("game_delays", {}).items()}
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"[{name}] settings load error: {e}")


def save_settings(name, st):
    data = {
        "ver": 2,
        "delay": st.delay,
        "jitter": st.jitter,
        "use_code": st.use_code,
        "game_delays": st.game_delays,
    }
    path = settings_path(name)
    try:
        with open(path + ".tmp", "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
        os.replace(path + ".tmp", path)
    except Exception as e:
        print(f"[{name}] settings save error: {e}")


def is_num(s):
    try:
        float(s)
        return True
    except (ValueError, TypeError):
        return False


def spawn(coro):
    t = asyncio.create_task(coro)
    tasks.add(t)
    t.add_done_callback(tasks.discard)
    return t


subs = {}


def load_subs():
    global subs
    try:
        with open(SUBS_FILE, "r", encoding="utf-8") as f:
            subs = json.load(f)
    except FileNotFoundError:
        subs = {}
    except Exception as e:
        print(f"[KIRA] subs load error: {e}")
        subs = {}


def save_subs():
    try:
        with open(SUBS_FILE + ".tmp", "w", encoding="utf-8") as f:
            json.dump(subs, f, ensure_ascii=False)
        os.replace(SUBS_FILE + ".tmp", SUBS_FILE)
    except Exception as e:
        print(f"[KIRA] subs save error: {e}")


def new_sub_record():
    return {"expires": 0.0, "paused": False, "remaining": 0.0, "unlimited": False}


def sub_status(name):
    """(\u0627\u0644\u062d\u0627\u0644\u0629, \u0627\u0644\u062b\u0648\u0627\u0646\u064a \u0627\u0644\u0645\u062a\u0628\u0642\u064a\u0629): unlimited | active | paused | pending | expired"""
    rec = subs.get(name)
    if rec is None:
        return "unlimited", 0.0          # \u062d\u0633\u0627\u0628\u0627\u062a \u0642\u062f\u064a\u0645\u0629 \u0628\u062f\u0648\u0646 \u0633\u062c\u0644 = \u0645\u0641\u062a\u0648\u062d\u0629
    if rec.get("paused"):
        return "paused", float(rec.get("remaining", 0))
    if rec.get("unlimited"):
        return "unlimited", 0.0
    exp = float(rec.get("expires", 0))
    left = exp - time.time()
    if left > 0:
        return "active", left
    return ("expired" if exp else "pending"), 0.0


def is_allowed(name):
    return sub_status(name)[0] in ("unlimited", "active")


def sub_op(name, op):
    rec = subs.setdefault(name, new_sub_record())
    now = time.time()
    if op in ("d30", "d5", "d1"):
        add = {"d30": 30, "d5": 5, "d1": 1}[op] * 86400
        rec["unlimited"] = False
        if rec.get("paused"):
            rec["remaining"] = float(rec.get("remaining", 0)) + add
        else:
            rec["expires"] = max(now, float(rec.get("expires", 0))) + add
    elif op == "pause":
        status, left = sub_status(name)
        if status == "active":
            rec["remaining"] = left
            rec["expires"] = 0.0
        rec["paused"] = True
    elif op == "resume":
        if rec.get("paused"):
            rec["paused"] = False
            if not rec.get("unlimited"):
                rec["expires"] = now + float(rec.get("remaining", 0))
            rec["remaining"] = 0.0
    elif op == "inf":
        rec.update(unlimited=True, paused=False, remaining=0.0)
    elif op == "reset":
        rec.update(new_sub_record())
    save_subs()


def fmt_left(sec):
    sec = int(sec)
    d, r = divmod(sec, 86400)
    h, r = divmod(r, 3600)
    m = r // 60
    if d:
        return f"{d} \u064a\u0648\u0645 {h} \u0633"
    if h:
        return f"{h} \u0633 {m} \u062f"
    return f"{max(m, 1)} \u062f"


def sub_line(name):
    status, left = sub_status(name)
    if status == "unlimited":
        return "\u267e \u0645\u0641\u062a\u0648\u062d"
    if status == "active":
        return f"\U0001f7e2 \u0628\u0627\u0642\u064a {fmt_left(left)}"
    if status == "paused":
        return f"\u23f8 \u0645\u0648\u0642\u0648\u0641 (\u0628\u0627\u0642\u064a {fmt_left(left)})" if left else "\u23f8 \u0645\u0648\u0642\u0648\u0641"
    if status == "expired":
        return "\U0001f534 \u0645\u0646\u062a\u0647\u064a"
    return "\U0001f553 \u0628\u0627\u0646\u062a\u0638\u0627\u0631 \u0627\u0644\u062a\u0641\u0639\u064a\u0644"


def clean(text):
    return re.sub(r"[`*_\[\]]", "", str(text or ""))


def disp(name, st=None):
    """\u0627\u0633\u0645 \u0627\u0644\u062d\u0633\u0627\u0628 (\u0645\u0648 \u0627\u0644\u0631\u0642\u0645)."""
    st = st or states.get(name)
    if st is not None and st.display:
        return clean(st.display)
    return name


def get_state(c):
    return states.setdefault(c.name, AccState())


def fmt_uptime(sec):
    sec = int(sec)
    h, r = divmod(sec, 3600)
    m, s = divmod(r, 60)
    return T_UPTIME.format(h=h, m=m, s=s)


def parse_num(text, lo, hi):
    try:
        v = float(text)
    except (ValueError, TypeError):
        return None
    if lo <= v <= hi:
        return v
    return None


def arg_num(m, lo, hi):
    if len(m.command) < 2:
        return None
    return parse_num(m.command[1], lo, hi)


async def animate(msg, frames, pause=0.3):
    for f in frames:
        try:
            await msg.edit_text(f)
        except FloodWait as e:
            await asyncio.sleep(e.value)
        except Exception:
            pass
        await asyncio.sleep(pause)


async def show(msg, text, frames=None):
    """\u0631\u062f \u0641\u0648\u0631\u064a: \u062a\u0639\u062f\u064a\u0644 \u0648\u0627\u062d\u062f \u0641\u0642\u0637 (\u0627\u0644\u0623\u0646\u0645\u064a\u0634\u0646 \u0643\u0627\u0646 \u064a\u0633\u0628\u0628 FloodWait \u0648\u062a\u0623\u062e\u064a\u0631)."""
    try:
        await msg.edit_text(text)
    except FloodWait as e:
        await asyncio.sleep(min(e.value, 5) + 0.5)
        try:
            await msg.edit_text(text)
        except Exception:
            pass
    except Exception:
        pass


async def real_ping(c, samples=1):
    """\u0628\u0646\u0642 \u062d\u0642\u064a\u0642\u064a \u0644\u0633\u064a\u0631\u0641\u0631 \u062a\u064a\u0644\u064a\u062c\u0631\u0627\u0645 (\u062e\u0641\u064a\u0641\u060c \u0628\u062f\u0648\u0646 get_me \u0627\u0644\u062b\u0642\u064a\u0644)."""
    best = None
    for i in range(samples):
        t = time.perf_counter()
        try:
            await asyncio.wait_for(
                c.invoke(raw.functions.Ping(ping_id=random.getrandbits(62))), timeout=20
            )
        except Exception:
            break
        ms = int((time.perf_counter() - t) * 1000)
        best = ms if best is None else min(best, ms)
        if best > 400:          # \u0628\u0637\u064a\u0621: \u0644\u0627 \u0646\u0643\u0631\u0631 \u0627\u0644\u0642\u064a\u0627\u0633
            break
    return -1 if best is None else best


async def safe_edit(msg, text, kb=None):
    try:
        await msg.edit_text(text, reply_markup=kb)
    except Exception:
        pass


def help_text(name, st, sub="-"):
    return T_HELP.format(src=SOURCE_NAME, who=name, dev=DEV_NAME, delay=st.delay, sub=sub)


async def send_plain(c, chat_id, text):
    """\u0631\u0633\u0627\u0644\u0629 \u0639\u0627\u062f\u064a\u0629 \u0641\u064a \u0627\u0644\u0634\u0627\u062a\u060c \u0628\u062f\u0648\u0646 \u0631\u062f \u0639\u0644\u0649 \u0623\u064a \u0631\u0633\u0627\u0644\u0629."""
    return await asyncio.wait_for(
        c.send_message(chat_id, text, parse_mode=ParseMode.DISABLED), timeout=30
    )


recent_sends = {}
SEND_DEDUP = 10.0


async def guarded_send(c, st, chat_id, text, gap=SEND_GAP):
    """\u0625\u0631\u0633\u0627\u0644 \u0648\u0627\u062d\u062f \u0641\u064a \u0646\u0641\u0633 \u0627\u0644\u0648\u0642\u062a + \u0641\u0627\u0635\u0644 + \u0645\u0639\u0627\u0644\u062c\u0629 FloodWait.
    \u064a\u0631\u062c\u0651\u0639 None \u0625\u0630\u0627 \u0646\u0641\u0633 \u0627\u0644\u0631\u0633\u0627\u0644\u0629 \u0627\u0646\u0631\u0633\u0644\u062a \u0642\u0628\u0644 \u062b\u0648\u0627\u0646\u064a (\u0645\u0646\u0639 \u0627\u0644\u062a\u0643\u0631\u0627\u0631)."""
    async with st.send_lock:
        now = time.time()
        for k in [k for k, t in recent_sends.items() if now - t > SEND_DEDUP]:
            recent_sends.pop(k, None)
        key = (chat_id, text)
        if key in recent_sends:
            return None
        recent_sends[key] = now
        wait_gap = gap - (time.time() - st.last_send)
        if wait_gap > 0:
            await asyncio.sleep(wait_gap)
        try:
            try:
                return await send_plain(c, chat_id, text)
            except FloodWait as e:
                await asyncio.sleep(e.value + 1)
                return await send_plain(c, chat_id, text)
        finally:
            st.last_send = time.time()



# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500 Game solver \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
PAREN = re.compile(r"(\S+?)\((\d+)\)")
ARABIC_COMMA = "\u060c"


def utf16_slice(text, offset, length):
    raw = text.encode("utf-16-le")
    return raw[offset * 2:(offset + length) * 2].decode("utf-16-le", errors="ignore")


def solve(m, st):
    text = m.text or ""
    if not text or "WPM" in text:
        return None

    if ARABIC_COMMA in text:
        words = [w.strip() for w in text.split(ARABIC_COMMA) if w.strip()]
        if words:
            return " ".join(words)
        return None

    if "(" in text and ")" in text and PAREN.search(text):
        out = []
        for tok in text.split():
            mm = PAREN.fullmatch(tok)
            if mm:
                out.extend([mm.group(1)] * int(mm.group(2)))
            else:
                tok = tok.replace("(", "").replace(")", "")
                if tok:
                    out.append(tok)
        if out:
            return " ".join(out)
        return None

    if st.use_code and m.entities:
        for e in m.entities:
            if e.type in (MessageEntityType.CODE, MessageEntityType.PRE):
                s = utf16_slice(text, e.offset, e.length).strip()
                if s:
                    return s
    return None


# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500 Userbot command handlers \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
async def cmd_help(c, m):
    st = get_state(c)
    await show(m, help_text(disp(c.name, st), st, sub_line(c.name)))


def game_delay(st, game):
    v = None
    if game:
        v = st.game_delays.get(game)
        if v is None:
            g = _norm_ar(game)
            for k, val in st.game_delays.items():
                if _norm_ar(k) == g:
                    v = val
                    break
    return st.delay if v is None else v


def speeds_text(st):
    names = list(GAMES) + [g for g in st.game_delays if g not in GAMES]
    lines = []
    for g in names:
        if g in st.game_delays:
            lines.append(f"\u2022 {g}: `{st.game_delays[g]}` \u062b")
        else:
            lines.append(f"\u2022 {g}: `{st.delay}` \u062b (\u0627\u0641\u062a\u0631\u0627\u0636\u064a)")
    return T_SPEEDS.format(body="\n".join(lines), d=st.delay, j=st.jitter)


async def cmd_speed(c, m):
    st = get_state(c)
    args = m.command[1:]
    if not args:
        await show(m, speeds_text(st))
        return
    if len(args) == 1:
        if args[0] in ("\u0645\u0633\u062d", "\u062d\u0630\u0641", "reset"):
            st.game_delays.clear()
            save_settings(c.name, st)
            await show(m, T_SPEED_CLEAR.format(d=st.delay))
            return
        v = parse_num(args[0], 0, 60)
        if v is None:
            await safe_edit(m, T_SPEED_ERR.format(v=st.delay))
            return
        st.delay = v
        save_settings(c.name, st)
        await show(m, T_SPEED_OK.format(v=v))
        return
    v = parse_num(args[-1], 0, 60)
    game = " ".join(args[:-1]).strip()
    if v is None or not game:
        await safe_edit(m, T_SPEED_ERR.format(v=st.delay))
        return
    st.game_delays[game] = v
    save_settings(c.name, st)
    await show(m, T_SPEED_GAME_OK.format(g=game, v=v))


async def cmd_jitter(c, m):
    st = get_state(c)
    v = arg_num(m, 0, 10)
    if v is None:
        await safe_edit(m, T_JIT_ERR.format(v=st.jitter))
        return
    st.jitter = v
    save_settings(c.name, st)
    await show(m, T_JIT_OK.format(v=v))


async def cmd_code(c, m):
    st = get_state(c)
    st.use_code = not st.use_code
    save_settings(c.name, st)
    status = T_ON if st.use_code else T_OFF
    await show(m, T_CODE.format(status=status))


async def cmd_sim(c, m):
    """\u062a\u062d\u062f\u064a\u062f \u0627\u0644\u0628\u0648\u062a \u0627\u0644\u0645\u0633\u062a\u0647\u062f\u0641: \u0628\u0627\u0644\u0631\u062f \u0639\u0644\u0649 \u0631\u0633\u0627\u0644\u062a\u0647 \u0623\u0648 \u0628\u064a\u0648\u0632\u0631\u0647."""
    st = get_state(c)
    user = None

    rep = m.reply_to_message
    if rep is not None and rep.from_user is not None:
        user = rep.from_user
    elif len(m.command) > 1:
        try:
            user = await c.get_users(m.command[1].lstrip("@").strip())
        except Exception:
            user = None

    if user is None or user.id == st.me_id:
        await safe_edit(m, T_NEED_TARGET)
        return

    st.target_id = user.id
    st.target_name = user.username or user.first_name or str(user.id)
    await show(m, T_SIM_SET.format(t=st.target_name))


async def _quiet_delete(m):
    try:
        await m.delete()
    except Exception:
        pass


async def cmd_decode(c, m):
    """\u0641\u0643\u0643: \u0628\u0627\u0644\u0631\u062f \u0639\u0644\u0649 \u0631\u0633\u0627\u0644\u0629 = \u062a\u0641\u0643\u064a\u0643 \u0645\u0631\u0629 \u0648\u062d\u062f\u0629\u060c \u0628\u062f\u0648\u0646 \u0631\u062f = \u062a\u0641\u0643\u064a\u0643 \u0641\u0648\u0631\u064a \u0645\u0633\u062a\u0645\u0631."""
    st = get_state(c)
    rep = m.reply_to_message

    if rep is not None and rep.text:
        answer = solve(rep, st)
        if not answer:
            await safe_edit(m, T_NO_ANSWER)
            return
        try:
            if await guarded_send(c, st, rep.chat.id, answer, gap=0) is not None:   # \u0628\u062f\u0648\u0646 \u0631\u062f
                st.solved += 1
        except Exception as e:
            print(f"[{c.name}] decode error: {e}")
        spawn(_quiet_delete(m))
        return

    st.active = True
    st.mode = "decode"
    st.chat_id = m.chat.id
    await show(m, T_DECODE_ON)


async def cmd_play(c, m):
    """\u0628\u0644\u0634 [\u0648\u0642\u062a]: \u064a\u0628\u062f\u0623 \u0627\u0644\u0644\u0639\u0628. \u0628\u062f\u0648\u0646 \u0631\u0642\u0645 = \u0643\u0644 \u0642\u0633\u0645 \u0628\u0633\u0631\u0639\u062a\u0647 \u0627\u0644\u062e\u0627\u0635\u0629."""
    st = get_state(c)
    if len(m.command) > 1:
        v = arg_num(m, 0, 60)
        if v is None:
            await safe_edit(m, T_PLAY_ERR)
            return
        st.delay = v
        save_settings(c.name, st)

    st.active = True
    st.mode = "play"
    st.chat_id = m.chat.id
    await show(m, T_PLAY_ON.format(d=st.delay))


def stop_repeat(st):
    st.rgen += 1
    t = st.repeat_task
    st.repeat_task = None
    st.repeat_word = None
    if t is not None and not t.done():
        t.cancel()


def stop_all(st):
    st.active = False
    st.mode = "off"
    st.gen += 1            # \u064a\u0644\u063a\u064a \u0623\u064a \u0625\u062c\u0627\u0628\u0629 \u0645\u0639\u0644\u0651\u0642\u0629
    st.round_open = False
    stop_repeat(st)


async def cmd_stop(c, m):
    st = get_state(c)
    stop_all(st)
    await show(m, T_STOP)


async def cmd_repeat(c, m):
    """\u062a\u0643\u0631\u0627\u0631 <\u0643\u0644\u0645\u0629> [\u062b\u0648\u0627\u0646\u064a]: \u064a\u0631\u0633\u0644 \u0627\u0644\u0643\u0644\u0645\u0629 \u0643\u0644 X \u062b\u0627\u0646\u064a\u0629 \u0648\u064a\u0644\u0639\u0628 \u0648\u064a\u062c\u0627\u0648\u0628."""
    st = get_state(c)
    args = m.command[1:]

    if args and args[0] in ("\u0648\u0642\u0641", "\u0627\u064a\u0642\u0627\u0641", "\u0625\u064a\u0642\u0627\u0641", "stop"):
        if st.repeat_task is not None:
            stop_repeat(st)
            await show(m, T_REP_OFF)
        else:
            await safe_edit(m, T_REP_NONE)
        return

    interval = 70.0
    word_args = args
    if len(args) > 1 and is_num(args[-1]):
        interval = parse_num(args[-1], MIN_REPEAT, 3600)
        word_args = args[:-1]
    word = " ".join(word_args).strip()
    if interval is None or not word or is_num(word):
        await safe_edit(m, T_REP_ERR.format(m=int(MIN_REPEAT)))
        return

    stop_repeat(st)
    st.active = True
    if st.mode == "off":
        st.mode = "play"
    st.chat_id = m.chat.id
    st.repeat_word = word
    st.repeat_interval = interval
    st.repeat_task = spawn(
        repeat_supervisor(c, st, m.chat.id, word, interval, st.rgen)
    )
    await show(m, T_REP_ON.format(w=word, i=interval, d=game_delay(st, word)))


async def cmd_check(c, m):
    st = get_state(c)
    ping = await real_ping(c)
    state = T_STATE_ON if st.active else T_STATE_OFF
    if st.mode == "decode":
        mode = T_MODE_DECODE
    elif st.mode == "play":
        mode = T_MODE_PLAY
    else:
        mode = T_MODE_OFF
    target = "@" + st.target_name if st.target_name else T_NO_TARGET
    if st.repeat_task is not None and st.repeat_word:
        rep = f"`{st.repeat_word}` \u0643\u0644 `{st.repeat_interval}` \u062b"
    else:
        rep = "-"
    text = T_CHECK.format(
        name=disp(c.name, st) + (f" (@{st.username})" if st.username else ""),
        sub=sub_line(c.name),
        state=state,
        mode=mode,
        target=target,
        rdelay=st.delay,
        jitter=st.jitter,
        rep=rep,
        ping=ping,
        ram=ram_mb(),
        lag=LAG["max"] or LAG["now"],
        crypto=CRYPTO_BACKEND,
        boots=BOOTS["n24"],
        solved=st.solved,
        uptime=fmt_uptime(time.time() - START_TIME),
    )
    await show(m, text)


async def cmd_stats(c, m):
    st = get_state(c)
    text = T_STATS.format(solved=st.solved, uptime=fmt_uptime(time.time() - st.started))
    await show(m, text)


async def cmd_sections(c, m):
    await show(m, T_SECTIONS)


async def cmd_ping(c, m):
    await safe_edit(m, T_PING.format(ms=await real_ping(c), lag=LAG["max"] or LAG["now"]))


# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500 Engine: rounds / answers / repeat \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
def open_round(st, word, foreign=False):
    """\u062c\u0648\u0644\u0629 \u062c\u062f\u064a\u062f\u0629: \u0646\u062a\u0648\u0642\u0639 \u0633\u0624\u0627\u0644 \u0648\u0627\u062d\u062f \u0628\u0633\u060c \u0648\u0646\u062c\u0627\u0648\u0628\u0647 \u0645\u0631\u0629 \u0648\u062d\u062f\u0629."""
    st.current_game = word
    st.round_open = True
    st.round_ts = time.time()
    st.foreign_pending = foreign
    st.foreign_ts = st.round_ts


def is_game_word(st, word):
    w = _norm_ar(word)
    words = set(_norm_ar(g) for g in GAMES)
    words.update(_norm_ar(k) for k in st.game_delays)
    if st.repeat_word:
        words.add(_norm_ar(st.repeat_word))
    return w in words


def must_wait(st):
    """\u0647\u0644 \u0641\u064a\u0647 \u062c\u0648\u0627\u0628 \u0634\u063a\u0651\u0627\u0644 \u0623\u0648 \u0644\u0639\u0628\u0629 \u0644\u0627\u0639\u0628 \u062b\u0627\u0646\u064a \u062a\u0646\u062a\u0638\u0631 \u062c\u0648\u0627\u0628\u0646\u0627\u061f"""
    if st.pending > 0:
        return True
    return st.foreign_pending and time.time() - st.foreign_ts < FOREIGN_WAIT


def claim_question(st, m, text):
    """True \u0645\u0631\u0629 \u0648\u062d\u062f\u0629 \u0641\u0642\u0637 \u0644\u0643\u0644 \u062c\u0648\u0644\u0629. \u0628\u062f\u0648\u0646 await \u0639\u0634\u0627\u0646 \u0645\u0627 \u064a\u0635\u064a\u0631 \u062a\u062f\u0627\u062e\u0644."""
    now = time.time()
    for d, ttl in ((st.seen, 600.0), (st.sigs, DEDUP_WINDOW)):
        for k in [k for k, t in d.items() if now - t > ttl]:
            d.pop(k, None)

    key = (m.chat.id, m.id)
    if key in st.seen:
        return False
    st.seen[key] = now

    if st.round_ts and now - st.round_ts < ROUND_TTL:
        if not st.round_open:
            return False          # \u0647\u0630\u064a \u0627\u0644\u062c\u0648\u0644\u0629 \u0627\u0646\u062c\u0627\u0648\u0628\u062a \u0642\u0628\u0644
        st.round_open = False
        st.foreign_pending = False
        return True

    sig = (m.chat.id, text)       # \u0645\u0627 \u0641\u064a\u0647 \u062c\u0648\u0644\u0629 \u0645\u0639\u0631\u0648\u0641\u0629: \u0646\u0645\u0646\u0639 \u062a\u0643\u0631\u0627\u0631 \u0646\u0641\u0633 \u0627\u0644\u0633\u0624\u0627\u0644
    if sig in st.sigs:
        return False
    st.sigs[sig] = now
    return True


async def send_answer(c, st, chat_id, answer, game, gen):
    st.pending += 1
    try:
        wait = 0.0 if st.mode == "decode" else game_delay(st, game)
        if st.jitter > 0 and st.mode != "decode":
            wait += random.uniform(0, st.jitter)
        if wait > 0:
            await asyncio.sleep(wait)
        if not st.active or st.gen != gen or not is_allowed(c.name):
            return
        if await guarded_send(c, st, chat_id, answer,
                                 gap=0 if st.mode == "decode" else SEND_GAP) is not None:   # \u0631\u0633\u0627\u0644\u0629 \u0639\u0627\u062f\u064a\u0629 \u0628\u062f\u0648\u0646 \u0631\u062f
            st.solved += 1
    except asyncio.CancelledError:
        raise
    except Exception as e:
        print(f"[{c.name}] answer error: {e}")
    finally:
        st.pending -= 1


async def on_game(c, m):
    st = states.get(c.name)
    if st is None or not st.active or not is_allowed(c.name):
        return
    if st.chat_id is not None and m.chat.id != st.chat_id:
        return
    u = m.from_user
    if not u:
        return
    if not u.is_bot:
        word = (m.text or "").translate(_MARKS).strip()
        if word and len(word) <= 20 and is_game_word(st, word):
            open_round(st, word, foreign=True)      # \u0644\u0627\u0639\u0628 \u062b\u0627\u0646\u064a \u0628\u062f\u0623 \u0644\u0639\u0628\u0629: \u0646\u062c\u0627\u0648\u0628 \u0633\u0624\u0627\u0644\u0647\u0627
        if not st.target_id:
            return
    if st.target_id and u.id != st.target_id:
        return

    answer = solve(m, st)
    if not answer:
        return
    if not claim_question(st, m, m.text):
        return

    spawn(send_answer(c, st, m.chat.id, answer, st.current_game, st.gen))


async def on_my_text(c, m):
    """\u0644\u0648 \u0643\u062a\u0628\u062a \u0623\u0646\u062a \u0627\u0644\u0643\u0644\u0645\u0629 \u064a\u062f\u0648\u064a (\u0637\u0634 \u0645\u062b\u0644\u0627\u064b) \u0646\u0641\u062a\u062d \u062c\u0648\u0644\u0629 \u062c\u062f\u064a\u062f\u0629 \u0644\u0647\u0627."""
    raw_t = (m.text or "").translate(_MARKS).strip()
    if raw_t[:1] in _DOTS or raw_t[-1:] in _DOTS:
        print(f"[RX] {c.name}: {raw_t[:30]}")
    st = states.get(c.name)
    if st is None or not st.active or not is_allowed(c.name):
        return
    word = (m.text or "").translate(_MARKS).strip()
    if not word or word[0] in _DOTS:
        return
    if word in GAMES or word in st.game_delays:
        if st.chat_id is None or m.chat.id == st.chat_id:
            open_round(st, word)


async def repeat_worker(c, st, chat_id, word, interval, rgen):
    fails = 0
    while st.active and st.rgen == rgen:
        try:
            st.beat = time.time()
            waited = 0.0          # \u0645\u0627 \u0646\u0631\u0633\u0644 \u0643\u0644\u0645\u062a\u0646\u0627 \u0642\u0628\u0644 \u0645\u0627 \u0646\u062c\u0627\u0648\u0628 \u0644\u0639\u0628\u0629 \u0634\u063a\u0651\u0627\u0644\u0629 (\u062d\u062a\u0649 \u0644\u0644\u0627\u0639\u0628 \u062b\u0627\u0646\u064a)
            while must_wait(st) and waited < 60:
                await asyncio.sleep(0.25)
                waited += 0.25
            open_round(st, word)
            await guarded_send(c, st, chat_id, word)
            fails = 0
            st.beat = time.time()
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            fails += 1
            print(f"[{c.name}] repeat error #{fails}: {e}")
            st.beat = time.time()
            await asyncio.sleep(min(5 * fails, 60))


async def repeat_supervisor(c, st, chat_id, word, interval, rgen):
    """\u064a\u0631\u0627\u0642\u0628 \u0627\u0644\u062a\u0643\u0631\u0627\u0631 \u0648\u064a\u0639\u064a\u062f \u062a\u0634\u063a\u064a\u0644\u0647 \u0644\u0648 \u0648\u0642\u0641 \u0623\u0648 \u062a\u062c\u0645\u0651\u062f."""
    worker = None
    try:
        while st.active and st.rgen == rgen:
            worker = asyncio.create_task(
                repeat_worker(c, st, chat_id, word, interval, rgen)
            )
            st.beat = time.time()
            while not worker.done():
                await asyncio.wait({worker}, timeout=10)
                if worker.done():
                    break
                if not (st.active and st.rgen == rgen):
                    break
                if time.time() - st.beat > interval * 2 + 120:
                    print(f"[{c.name}] repeat watchdog: restarting worker")
                    break
            if not worker.done():
                worker.cancel()
                await asyncio.gather(worker, return_exceptions=True)
            elif not worker.cancelled() and worker.exception() is not None:
                print(f"[{c.name}] repeat worker died: {worker.exception()}")
                await asyncio.sleep(3)
            else:
                await asyncio.sleep(1)
    finally:
        if worker is not None and not worker.done():
            worker.cancel()


USER_COMMANDS = [
    (cmd_help, CMD["help"]),
    (cmd_speed, CMD["speed"]),
    (cmd_jitter, CMD["jitter"]),
    (cmd_code, CMD["code"]),
    (cmd_sim, CMD["sim"]),
    (cmd_decode, CMD["decode"]),
    (cmd_play, CMD["play"]),
    (cmd_stop, CMD["stop"]),
    (cmd_check, CMD["check"]),
    (cmd_stats, CMD["stats"]),
    (cmd_sections, CMD["sections"]),
    (cmd_ping, CMD["ping"]),
    (cmd_repeat, CMD["repeat"]),
]


def gated(func):
    """\u0623\u064a \u0623\u0645\u0631 \u0645\u0627 \u064a\u0634\u062a\u063a\u0644 \u0625\u0644\u0627 \u0644\u0648 \u0627\u0644\u0627\u0634\u062a\u0631\u0627\u0643 \u0641\u0639\u0651\u0627\u0644."""
    async def wrapper(c, m):
        print(f"[CMD] {disp(c.name)}: {(m.text or '')[:30]}")
        try:
            if not is_allowed(c.name):
                await safe_edit(m, T_SUB_OFF.format(s=sub_line(c.name), dev=DEV_NAME))
                return
            await func(c, m)
        except Exception as e:
            import traceback
            traceback.print_exc()
            await safe_edit(m, f"\u26a0\ufe0f \u062e\u0637\u0623 \u0641\u064a \u0627\u0644\u0623\u0645\u0631: {type(e).__name__}: {e}")
    return wrapper


_MARKS = {ord(ch): None for ch in "\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u061c\ufeff\u200b\u200c\u200d"}
_DOTS = (".", "\uff0e", "\u06d4", "\u3002", "\u2024")
_AR = str.maketrans({"\u0623": "\u0627", "\u0625": "\u0627", "\u0622": "\u0627", "\u0649": "\u064a", "\u0640": None})


def _norm_ar(word):
    word = word.translate(_AR)
    return re.sub("[\u064b-\u065f]", "", word)


def parse_command(text, names):
    """\u064a\u0642\u0628\u0644: .\u0627\u0644\u0627\u0648\u0627\u0645\u0631  |  . \u0627\u0644\u0627\u0648\u0627\u0645\u0631  |  \u0627\u0644\u0627\u0648\u0627\u0645\u0631.  (\u0646\u0642\u0637\u0629 \u0628\u0639\u062f \u0627\u0644\u0643\u0644\u0645\u0629)  |  \u0631\u0645\u0648\u0632 \u0627\u062a\u062c\u0627\u0647 \u062e\u0641\u064a\u0629  |  \u0623/\u0627"""
    if not text:
        return None
    t = text.translate(_MARKS).strip()
    if not t:
        return None
    if t[0] in _DOTS:
        tokens = t[1:].split()
    else:
        tokens = t.split()
        if len(tokens) != 1 or tokens[0][-1] not in _DOTS:   # \u0628\u062f\u0648\u0646 \u0646\u0642\u0637\u0629 \u0628\u0627\u0644\u0628\u062f\u0627\u064a\u0629: \u0643\u0644\u0645\u0629 \u0648\u062d\u062f\u0629 + \u0646\u0642\u0637\u0629
            return None
    if not tokens:
        return None
    cmd = tokens[0].rstrip("".join(_DOTS))
    cmd_n = _norm_ar(cmd)
    for n in names:
        if _norm_ar(n) == cmd_n:
            return [n] + tokens[1:]
    return None


def cmd_filter(names):
    async def _f(_, __, m):
        cmd = parse_command(m.text or m.caption, names)
        if cmd is None:
            return False
        m.command = cmd
        return True
    return filters.create(_f, "KiraCmd")


def register_handlers(app):
    for func, names in USER_COMMANDS:
        flt = filters.me & cmd_filter(names)
        app.add_handler(MessageHandler(gated(func), flt))
    app.add_handler(MessageHandler(on_game, filters.incoming & filters.text))
    app.add_handler(MessageHandler(on_my_text, filters.me & filters.text), group=1)


async def is_authorized(name):
    tmp = Client(name, api_id=API_ID, api_hash=API_HASH, workdir=WORKDIR)
    try:
        return bool(await tmp.connect())
    except Exception:
        return False
    finally:
        try:
            await tmp.disconnect()
        except Exception:
            pass


def local_session_ok(name):
    """\u0641\u062d\u0635 \u0645\u062d\u0644\u064a \u0633\u0631\u064a\u0639 \u0644\u0644\u062c\u0644\u0633\u0629 (\u0628\u062f\u0648\u0646 \u0627\u062a\u0635\u0627\u0644). None = \u0645\u0627 \u0642\u062f\u0631\u0646\u0627 \u0646\u0642\u0631\u0623\u0647\u0627."""
    import sqlite3
    path = os.path.join(WORKDIR, f"{name}.session")
    try:
        con = sqlite3.connect(path, timeout=2)
        try:
            row = con.execute("SELECT auth_key, user_id FROM sessions LIMIT 1").fetchone()
        finally:
            con.close()
        return bool(row and row[0] and row[1])
    except Exception:
        return None


async def _log_ping(app, name, st):
    print(f"[KIRA] {disp(name, st)} ping: {await real_ping(app)}ms")


async def start_account(name):
    if name in running:
        return True
    ok = local_session_ok(name)
    if ok is None:
        ok = await is_authorized(name)
    if not ok:
        return False
    app = new_client(name)
    st = states.setdefault(name, AccState())
    load_settings(name, st)
    register_handlers(app)
    await app.start()
    tune_storage(app)
    try:
        me = await app.get_me()
        uid = me.id
        full = " ".join(x for x in (me.first_name, me.last_name) if x)
        st.display = full or me.username or name
        st.username = me.username
    except Exception:
        uid = None
    if uid is not None and running_ids.get(uid) not in (None, name):
        print(f"[KIRA] {name} \u0646\u0641\u0633 \u0627\u0644\u062d\u0633\u0627\u0628 \u0634\u063a\u0651\u0627\u0644 \u0641\u064a \u062c\u0644\u0633\u0629 \u062b\u0627\u0646\u064a\u0629 ({running_ids[uid]}) - \u062a\u0645 \u062a\u062c\u0627\u0647\u0644\u0647")
        try:
            await app.stop()
        except Exception:
            pass
        states.pop(name, None)
        return True
    st.me_id = uid
    if uid is not None:
        running_ids[uid] = name
    running[name] = app
    print(f"[KIRA USERBOT] Engine active for: {disp(name, st)}")
    spawn(_log_ping(app, name, st))
    sys.stdout.flush()
    return True


# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500 Control bot (login only) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
def main_kb():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton(B_ADD, callback_data="add")],
        [InlineKeyboardButton(B_LIST, callback_data="list"),
         InlineKeyboardButton(B_HELP, callback_data="help")],
    ])


def _btn(t, d):
    return InlineKeyboardButton(t, callback_data=d)


def panel_kb(name):
    return InlineKeyboardMarkup([
        [_btn("\u2795 30 \u064a\u0648\u0645", f"sub:{name}:d30"), _btn("\u2795 5 \u0623\u064a\u0627\u0645", f"sub:{name}:d5"),
         _btn("\u2795 \u064a\u0648\u0645", f"sub:{name}:d1")],
        [_btn("\u23f8 \u0625\u064a\u0642\u0627\u0641", f"sub:{name}:pause"), _btn("\u25b6\ufe0f \u062a\u0634\u063a\u064a\u0644", f"sub:{name}:resume")],
        [_btn("\u267e \u0645\u0641\u062a\u0648\u062d", f"sub:{name}:inf"), _btn("\u26d4 \u062a\u0635\u0641\u064a\u0631", f"sub:{name}:reset")],
        [_btn("\U0001f9ea \u0627\u062e\u062a\u0628\u0627\u0631 \u0627\u0644\u062d\u0633\u0627\u0628", f"test:{name}")],
        [_btn("\U0001f519 \u0627\u0644\u062d\u0633\u0627\u0628\u0627\u062a", "list")],
    ])


def list_kb(names):
    icons = {"unlimited": "\u267e", "active": "\U0001f7e2", "paused": "\u23f8"}
    rows = []
    for n in names:
        icon = icons.get(sub_status(n)[0], "\U0001f534")
        rows.append([_btn(f"{icon} {disp(n)}", f"acc:{n}")])
    rows.append([_btn(B_HOME, "home")])
    return InlineKeyboardMarkup(rows)


def acc_panel_text(name):
    st = states.get(name)
    title = disp(name, st)
    if st is not None and st.username:
        title += f" (@{st.username})"
    return T_ACC_PANEL.format(name=title, status=sub_line(name))


async def sub_watcher(bot):
    """\u064a\u0648\u0642\u0641 \u0627\u0644\u062d\u0633\u0627\u0628\u0627\u062a \u0627\u0644\u0644\u064a \u0627\u0646\u062a\u0647\u0649 \u0627\u0634\u062a\u0631\u0627\u0643\u0647\u0627 \u0648\u064a\u0628\u0644\u0651\u063a\u0643."""
    notified = set()
    while True:
        try:
            for name, app in list(running.items()):
                if is_allowed(name):
                    notified.discard(name)
                    continue
                st = states.get(name)
                if st is not None and (st.active or st.repeat_task is not None):
                    stop_all(st)
                if name not in notified:
                    notified.add(name)
                    if sub_status(name)[0] == "expired":
                        try:
                            await bot.send_message(
                                OWNER_ID, T_SUB_ENDED_OWNER.format(name=disp(name, st)))
                        except Exception:
                            pass
                        try:
                            await app.send_message(
                                "me", T_SUB_ENDED_USER.format(src=SOURCE_NAME, dev=DEV_NAME))
                        except Exception:
                            pass
        except Exception as e:
            print(f"[KIRA] sub_watcher error: {e}")
        await asyncio.sleep(15)


def back_kb():
    return InlineKeyboardMarkup([[InlineKeyboardButton(B_HOME, callback_data="home")]])


def cancel_kb():
    return InlineKeyboardMarkup([[InlineKeyboardButton(B_CANCEL, callback_data="cancel")]])


async def reset_login():
    cl = login.get("client")
    name = login.get("name")
    if cl:
        try:
            await cl.disconnect()
        except Exception:
            pass
        if name:
            path = os.path.join(WORKDIR, f"{name}.session")
            if os.path.exists(path) and name not in running:
                try:
                    os.remove(path)
                except Exception:
                    pass
    login.update(state=None, client=None, phone=None, hash=None, name=None)


async def finish_login(bot, chat_id):
    cl = login["client"]
    name = login["name"]
    phone = login["phone"]
    try:
        await cl.storage.save()
    except Exception:
        pass
    try:
        await cl.disconnect()
    except Exception:
        pass
    login.update(state=None, client=None, phone=None, hash=None, name=None)
    ok = await start_account(name)
    if ok and name in running:
        if name not in subs:
            subs[name] = new_sub_record()        # \u062d\u0633\u0627\u0628 \u062c\u062f\u064a\u062f: \u0628\u0627\u0646\u062a\u0638\u0627\u0631 \u062a\u0641\u0639\u064a\u0644 \u0627\u0644\u0645\u0637\u0648\u0631
            save_subs()
        await bot.send_message(
            chat_id,
            T_DONE.format(phone=phone) + "\n\n" + acc_panel_text(name) + T_DONE_ACT,
            reply_markup=panel_kb(name),
        )
    elif ok:
        await bot.send_message(chat_id, T_EXISTS, reply_markup=main_kb())
    else:
        await bot.send_message(chat_id, T_DONE_FAIL, reply_markup=main_kb())


async def on_bot_start(c, m):
    await reset_login()
    msg = await m.reply_text("\u26a1")
    await animate(msg, [T_BOOT, "\U0001f50c \u25b0\u25b0\u25b1\u25b1\u25b1", "\U0001f50c \u25b0\u25b0\u25b0\u25b0\u25b1", "\u2705 \u25b0\u25b0\u25b0\u25b0\u25b0"], 0.3)
    await safe_edit(msg, T_WELCOME, main_kb())


async def on_callback(c, q):
    d = q.data
    toast = None
    if d == "add":
        await reset_login()
        login["state"] = "PHONE"
        await safe_edit(q.message, T_ASK_PHONE, cancel_kb())
    elif d == "list":
        names = sorted(running)
        if names:
            await safe_edit(q.message, T_LIST.format(body="\u0627\u062e\u062a\u0631 \u062d\u0633\u0627\u0628 \u0644\u0644\u062a\u062d\u0643\u0645 \u0628\u0645\u062f\u062a\u0647 \U0001f447"), list_kb(names))
        else:
            await safe_edit(q.message, T_LIST.format(body=T_NO_ACCOUNTS), back_kb())
    elif d.startswith("test:"):
        name = d[5:]
        app = running.get(name)
        if app is not None:
            ping = await real_ping(app)
            try:
                await app.send_message(
                    "me", "\u2705 \u0627\u062e\u062a\u0628\u0627\u0631 \u0647\u0633\u062a\u0631\u0647: \u0627\u0644\u062d\u0633\u0627\u0628 \u0645\u062a\u0635\u0644.\n\u0627\u0643\u062a\u0628 \u0647\u0646\u0627 (\u0627\u0644\u0631\u0633\u0627\u0626\u0644 \u0627\u0644\u0645\u062d\u0641\u0648\u0638\u0629): .\u0628\u0646\u0642")
                sent = "\u2705"
            except Exception as e:
                sent = f"\u274c {type(e).__name__}"
            await safe_edit(
                q.message,
                acc_panel_text(name)
                + f"\n\n\U0001f9ea **\u0646\u062a\u064a\u062c\u0629 \u0627\u0644\u0627\u062e\u062a\u0628\u0627\u0631:**\n\u2022 \u0627\u0644\u0628\u0646\u0642: `{ping}` ms\n\u2022 \u0627\u0644\u0631\u0627\u0645: `{ram_mb()}` MB"
                + f"\n\u2022 \u0631\u0633\u0627\u0644\u0629 \u0648\u0635\u0644\u062a \u0627\u0644\u0645\u062d\u0641\u0648\u0638\u0627\u062a: {sent}"
                + "\n\n\u0627\u0641\u062a\u062d **\u0627\u0644\u0631\u0633\u0627\u0626\u0644 \u0627\u0644\u0645\u062d\u0641\u0648\u0638\u0629** \u0641\u064a \u0647\u0630\u0627 \u0627\u0644\u062d\u0633\u0627\u0628 \u0646\u0641\u0633\u0647 \u0648\u0627\u0643\u062a\u0628 `.\u0628\u0646\u0642`",
                panel_kb(name),
            )
            toast = "\u062a\u0645 \u0627\u0644\u0627\u062e\u062a\u0628\u0627\u0631"
    elif d.startswith("acc:"):
        name = d[4:]
        if name in running:
            await safe_edit(q.message, acc_panel_text(name), panel_kb(name))
    elif d.startswith("sub:"):
        try:
            _, name, op = d.split(":", 2)
        except ValueError:
            name, op = None, None
        if name in running:
            sub_op(name, op)
            st = states.get(name)
            if st is not None and not is_allowed(name):
                stop_all(st)
            await safe_edit(q.message, acc_panel_text(name), panel_kb(name))
            toast = "\u062a\u0645 \u2705"
    elif d == "help":
        await safe_edit(q.message, help_text("-", AccState(), "-"), back_kb())
    elif d in ("home", "cancel"):
        await reset_login()
        await safe_edit(q.message, T_WELCOME, main_kb())
    try:
        await q.answer(toast)
    except Exception:
        pass


async def handle_phone(c, m, text):
    digits = re.sub(r"\D", "", text)
    if len(digits) < 8:
        await m.reply_text(T_BAD_PHONE, reply_markup=cancel_kb())
        return

    phone = "+" + digits
    name = f"session_{digits}"
    path = os.path.join(WORKDIR, f"{name}.session")

    if os.path.exists(path):
        if await start_account(name):
            login["state"] = None
            await m.reply_text(T_EXISTS, reply_markup=main_kb())
            return
        try:
            os.remove(path)
        except Exception:
            pass

    cl = Client(name, api_id=API_ID, api_hash=API_HASH, workdir=WORKDIR)
    try:
        await cl.connect()
        sent = await cl.send_code(phone)
    except PhoneNumberInvalid:
        try:
            await cl.disconnect()
        except Exception:
            pass
        await m.reply_text(T_BAD_PHONE, reply_markup=cancel_kb())
        return
    except Exception as e:
        try:
            await cl.disconnect()
        except Exception:
            pass
        login["state"] = None
        await m.reply_text(T_SEND_ERR.format(e=e))
        return

    login.update(state="CODE", client=cl, phone=phone, hash=sent.phone_code_hash, name=name)
    await m.reply_text(T_CODE_SENT.format(phone=phone), reply_markup=cancel_kb())


async def handle_code(c, m, text):
    code = re.sub(r"\D", "", text)
    try:
        await m.delete()
    except Exception:
        pass
    try:
        await login["client"].sign_in(login["phone"], login["hash"], code)
    except SessionPasswordNeeded:
        login["state"] = "PASSWORD"
        await c.send_message(m.chat.id, T_ASK_PASS, reply_markup=cancel_kb())
        return
    except PhoneCodeInvalid:
        await c.send_message(m.chat.id, T_BAD_CODE, reply_markup=cancel_kb())
        return
    except PhoneCodeExpired:
        await reset_login()
        await c.send_message(m.chat.id, T_EXPIRED)
        return
    except Exception as e:
        await reset_login()
        await c.send_message(m.chat.id, T_ERR.format(e=e))
        return
    await finish_login(c, m.chat.id)


async def handle_password(c, m, text):
    try:
        await m.delete()
    except Exception:
        pass
    try:
        await login["client"].check_password(text)
    except PasswordHashInvalid:
        await c.send_message(m.chat.id, T_BAD_PASS, reply_markup=cancel_kb())
        return
    except Exception as e:
        await reset_login()
        await c.send_message(m.chat.id, T_ERR.format(e=e))
        return
    await finish_login(c, m.chat.id)


async def on_flow(c, m):
    step = login["state"]
    if not step:
        return
    text = m.text.strip()
    if step == "PHONE":
        await handle_phone(c, m, text)
    elif step == "CODE":
        await handle_code(c, m, text)
    elif step == "PASSWORD":
        await handle_password(c, m, text)


def register_bot_handlers(bot):
    owner = filters.user(OWNER_ID)
    bot.add_handler(MessageHandler(on_bot_start, filters.private & owner & filters.command("start")))
    bot.add_handler(CallbackQueryHandler(on_callback, owner))
    bot.add_handler(MessageHandler(on_flow, filters.private & owner & filters.text & ~filters.command("start")))


# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500 Main \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
async def main():
    bot = new_client("kira_bot", bot_token=BOT_TOKEN)
    load_subs()
    record_boot()
    register_bot_handlers(bot)
    bot_task = asyncio.create_task(bot.start())      # \u064a\u0634\u062a\u063a\u0644 \u0628\u0627\u0644\u062a\u0648\u0627\u0632\u064a \u0645\u0639 \u0627\u0644\u062d\u0633\u0627\u0628\u0627\u062a

    files = [
        f for f in glob.glob(os.path.join(WORKDIR, "session_*.session"))
        if re.fullmatch(r"session_\d+\.session", os.path.basename(f))
    ]
    legacy = os.path.join(WORKDIR, "kira_userbot_session.session")
    if os.path.exists(legacy):
        files.append(legacy)

    tails = {}
    to_start = []
    for f in sorted(files, key=lambda x: -len(x)):      # \u0627\u0644\u0631\u0642\u0645 \u0627\u0644\u062f\u0648\u0644\u064a \u0623\u0648\u0644\u0627\u064b
        name = os.path.basename(f)[:-len(".session")]
        digits = name[len("session_"):] if name.startswith("session_") else ""
        if digits.isdigit():
            if digits[-9:] in tails:
                print(f"[KIRA] \u062a\u062c\u0627\u0647\u0644 \u062c\u0644\u0633\u0629 \u0645\u0643\u0631\u0631\u0629 \u0644\u0646\u0641\u0633 \u0627\u0644\u0631\u0642\u0645: {name} (\u0627\u0644\u0623\u0635\u0644\u064a\u0629: {tails[digits[-9:]]})")
                continue
            tails[digits[-9:]] = name
        to_start.append(name)

    async def _start_safe(n):
        try:
            await start_account(n)
        except Exception as e:
            print(f"Error in session {n}: {e}")

    await asyncio.gather(*[_start_safe(n) for n in to_start])
    await bot_task
    tune_storage(bot)
    print("[KIRA BOT] Control bot is active...")

    try:
        lines = []
        for n in sorted(running):
            stx = states.get(n)
            at = f" (@{stx.username})" if stx is not None and stx.username else ""
            lines.append(f"\u2022 {disp(n)}{at} \u2014 {sub_line(n)}")
        body = "\n".join(lines) if lines else "\u0644\u0627 \u064a\u0648\u062c\u062f \u062d\u0633\u0627\u0628\u0627\u062a"
        await bot.send_message(
            OWNER_ID,
            T_BOT_ONLINE.format(n=len(running)) + "\n\n" + body
            + "\n\n\u26a0\ufe0f \u0627\u0644\u0623\u0648\u0627\u0645\u0631 \u062a\u064f\u0643\u062a\u0628 **\u0645\u0646 \u0647\u0630\u064a \u0627\u0644\u062d\u0633\u0627\u0628\u0627\u062a \u0646\u0641\u0633\u0647\u0627** (\u0645\u062b\u0627\u0644: `.\u0628\u0646\u0642`).")
    except Exception:
        pass

    spawn(sub_watcher(bot))
    spawn(memory_keeper())
    spawn(lag_monitor())
    print(f"[KIRA] python {sys.version.split()[0]} | \u0627\u0644\u062a\u0634\u0641\u064a\u0631: {CRYPTO_BACKEND} | \u0625\u0639\u0627\u062f\u0629 \u062a\u0634\u063a\u064a\u0644 \u0622\u062e\u0631 24\u0633: {BOOTS['n24']}")
    print(f"[KIRA] RAM: {ram_mb()} MB")
    print("[KIRA SYSTEM] Master System operational!")
    sys.stdout.flush()
    try:
        await idle()
    finally:
        for app in running.values():
            try:
                await app.stop()
            except Exception:
                pass
        await bot.stop()


_lock_fh = None


def acquire_single_instance(wait=60):
    """\u064a\u0645\u0646\u0639 \u062a\u0634\u063a\u064a\u0644 \u0627\u0644\u0633\u0648\u0631\u0633 \u0645\u0631\u062a\u064a\u0646 \u0628\u0646\u0641\u0633 \u0627\u0644\u0648\u0642\u062a (\u064a\u0646\u062a\u0638\u0631 \u0644\u0648 \u0627\u0644\u0646\u0633\u062e\u0629 \u0627\u0644\u0642\u062f\u064a\u0645\u0629 \u0644\u0633\u0627 \u062a\u0633\u0643\u0651\u0631)."""
    global _lock_fh
    try:
        import fcntl
    except ImportError:
        return True
    _lock_fh = open(os.path.join(WORKDIR, "kira.lock"), "w")
    end = time.time() + wait
    while True:
        try:
            fcntl.flock(_lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            _lock_fh.write(str(os.getpid()))
            _lock_fh.flush()
            return True
        except OSError:
            if time.time() > end:
                return False
            time.sleep(0.5)


if __name__ == "__main__":
    if not acquire_single_instance():
        print("[KIRA] \u0646\u0633\u062e\u0629 \u062b\u0627\u0646\u064a\u0629 \u0634\u063a\u0651\u0627\u0644\u0629 \u0645\u0646 \u0627\u0644\u0633\u0648\u0631\u0633\u060c \u062a\u0645 \u0627\u0644\u0625\u064a\u0642\u0627\u0641.")
        sys.exit(1)
    try:
        import uvloop
        uvloop.install()
    except Exception:
        pass
    try:
        import tgcrypto  # noqa: F401
    except Exception:
        print("[KIRA] \u062a\u0646\u0628\u064a\u0647: tgcrypto \u063a\u064a\u0631 \u0645\u062b\u0628\u0651\u062a - \u062b\u0628\u0651\u062a\u0647 \u0644\u0633\u0631\u0639\u0629 \u0623\u0639\u0644\u0649: pip install tgcrypto uvloop")
    asyncio.run(main())
