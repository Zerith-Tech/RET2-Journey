 ### Challenge Overview

The target is a Secure Logon mechanism (RET 2: MEMORY CORRUPTION) that implements a one-time password (OTP) authentication check. The objective is to achieve unauthorized access by subverting the application's memory layout and authentication logic.

### Vulnerability Analysis

Static analysis of the binary reveals a classic buffer overflow condition stemming from improper bounds checking. The stack frame contains two adjacent 32-byte buffers: `user_password` and a dynamically generated `otp_password`. The vulnerability is triggered by a call to `fgets(user_password, 0x32, stdin);`. Because `fgets` is instructed to read up to 50 (`0x32`) bytes into the explicitly sized 32-byte `user_password` buffer, any input exceeding 32 bytes spills directly into the adjacent memory space. This linear buffer overflow primitive allows for the direct clobbering of the `otp_password` buffer.

### Exploitation Strategy

The exploitation strategy revolves around manipulating C-string termination semantics to force a logical collision during the authentication check. Standard C library functions like `strlen` and `strcmp` read memory byte-by-byte and terminate upon encountering a null byte (`\x00`), ignoring any subsequent data.

The application implements a rudimentary input validation check, `if (strlen(user_password) == 0)`, which prevents the deployment of a pure null-byte payload. To bypass this, the primary payload begins with `b"A\x00"`. This satisfies the `strlen` check by presenting a length of 1. We then append 30 bytes of junk padding (`b"B"*30`) to perfectly align our payload with the end of the `user_password` buffer.

The critical primitive occurs at bytes 33 and 34, where we append another `b"A\x00"`. Because the `user_password` buffer is exhausted, this data overflows into the `otp_password` buffer, explicitly overwriting its first two bytes.

When the execution flow reaches the `strcmp(user_password, otp_password)` validation phase , the function evaluates `user_password` as simply "A" due to our strategically placed null terminator. Concurrently, it evaluates the corrupted `otp_password` as "A", completely ignoring the remaining 30 bytes of valid cryptographic entropy still residing in memory. Because both strings evaluate to "A", the `strcmp` condition succeeds, and the authentication logic is bypassed.

### The Exploit

```Python
import interact
from pwn import *

p = interact.Process()
p.readuntil("Enter password: ")

# Constructing the payload:
# [Bypass strlen check (2 bytes)] + [Buffer exhaustion (30 bytes)] + [Clobber otp_password (2 bytes)]
payload = b'A\x00' + b'B'*30 + b'A\x00'

p.sendline(payload)
p.interactive()
```

### Conclusion / Takeaway

The root cause is a fundamental mismatch between the destination buffer size (32 bytes) and the explicit read limit passed to `fgets` (50 bytes). This spatial memory violation, combined with the predictable memory layout of adjacent stack variables and a naive reliance on null-terminated string comparisons, results in a trivial and complete bypass of the target's primary security boundary.
