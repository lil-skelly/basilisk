# Basilisk
Basilisk is a Linux Loaded Kernel Module (**LKM**) rootkit designed specifically to win TryHackMe's King of The Hill (**KoTH**) games.

## Key features
- Self-hiding from procfs and sysfs via signal `SIG_HIDE`
- Root backdoor via signal `SIG_ROOT`
- Advanced king protection (see [here](#protecting-the-king))

## Usage
```bash
$ git clone https://github.com/lil-skelly/basilisk
[...]
$ cd basilisk/src && make
[...]
```
You can customize the LKM by modifying the following macros:
```c
#define SIG_HIDE 63;
#define SIG_ROOT 64;

#define KING_FILENAME "/root/king.txt" // Path to king file

#define KING "SKELLY\n" // King
```

The signals used for hiding/showing the module and for the root backdoor are common amongst rootkits. 
I highly advice you change them to something less predictable from the range 32-64 (unused signals/process specific)

| SIGNAL        | VALUE | FUNCTION CALL                       | DESCRIPTION                                        |
|-------------|-------|-------------------------------------|----------------------------------------------------|
| SIG_HIDE    | 63    | handle_lkm_hide                     | hide/show from sysfs, procfs                       |
| SIG_PROTECT | 32    | handle_lkm_protect                  | increase/decrease the module ref count             |
| SIG_GODMODE | 38    | handle_lkm_hide, handle_lkm_protect | combines functionality of SIG_HIDE and SIG_PROTECT |
| SIG_ROOT    | 64    | set_root                            | give root to the calling process                   |

## Protecting the King
At first glance, the goal of a KoTH game is to root the machine and place your username inside the king file (`/root/king.txt`).

The real challenge is to **keep** your name in there. To do that, basilisk utilizes a new technique focusing on manipulating the file operations structure of the king file (`/root/king.txt`).

First, basilisk hooks the `openat` syscall and resolves the path from the given file descriptor.
If the path is that of our king file, it opens a new file descriptor by calling the original `openat` syscall, poisons the files `file_operations` structure and returns the file descriptor to our now poisoned file.

We poisoned the file operations structure by making the `read` field point to the address of our **own** implementation of the read syscall.
Now every time somebody reads from the king file, it will always read our name! Despite what its actual contents are.

In the KoTH scene, hooking the read syscall is not new.
But we are not just hooking any read syscall. We are only hooking the read syscall which will be used to read from that very specific file.

Furthermore, the function that is resolving the final path also follows any symbolic links/mount points so there is no way around it ? ? ?