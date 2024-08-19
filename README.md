# Basilisk
Basilisk is a loaded kernel module rootkit (LKM rootkit) that started as a rootkit 
for TryHackMe's King of The Hill game.

It also contains the code for my article in tmp.out.

While this project is centered around king of the hill, it includes a variety of interesting techniques.

## Key features
- Self-hiding from procfs and sysfs
- Make the module unremovable (even when visible) by tampering with the reference count
- Advanced king protection (see [here](#protecting-the-king))
- Stealthy communication via ProcFS hooking

## Installation and Usage
To install Basilisk, clone the repository and build the module as follows:
```bash
$ git clone https://github.com/lil-skelly/basilisk
$ cd basilisk/src && make
```

### Communicating with the LKM
Basilisk employs a new technique that hooks the operations of trusted procfs entries (e.g., /proc/kallsyms). 
To interact with the rootkit, compile and use client.c:

```bash
$ gcc -o client client.c 
$ ./client
Usage: ./client <cmd> [pid]
```
#### Available commands
       
- `hide`: Toggles the visibility of the module in procfs and sysfs.
- `protect`: Toggles protection to prevent the removal of the module (even if visible)  
- `god`: combines the functionality of hide and protect
- `root`: Grants root privileges to a specified process (by [pid]).<br>
If no PID is provided, the rootkit elevates the privileges of the client's parent process (typically the shell from which the client was executed).


You can customize the LKM by modifying the following:
```c
/* in basilisk.c */

#define KING_FILENAME "/root/king.txt" // Path to king file

#define KING "SKELLY\n" // King
```
Command signals can also be adjusted:
```c
enum {
  SIG_GOD = 0xFF,
  SIG_HIDE = 0xFA,
  SIG_PROTECT = 0xFB,
  SIG_ROOT = 0xBA,
};
```
> [!IMPORTANT]
> Ensure that any modifications to signals in client.c match those in basilisk.c.


## Protecting the King
At first glance, the goal of a KoTH game is to root the machine and place your username inside the king file (`/root/king.txt`).

The real challenge is to **keep** your name in there. 
To do that, basilisk utilizes a new technique focusing on manipulating the file operations structure of the king file (`/root/king.txt`).

First, basilisk hooks the `openat` syscall and resolves the path from the given file descriptor.
If the path is that of our king file, it opens a new file descriptor by calling the original `openat` syscall, poisons the files `file_operations` structure and returns the file descriptor to our now poisoned file.

We poisoned the file operations structure by making the `read` field point to the address of our **own** implementation of the read syscall.
Now every time somebody reads from the king file, it will always read our name! Despite what its actual contents are.

In the KoTH scene, hooking the read syscall is not new.
But we are not just hooking any read syscall. We are only hooking the read syscall which will be used to read from that very specific file.

Furthermore, the function that is resolving the final path also follows any symbolic links/mount points.
