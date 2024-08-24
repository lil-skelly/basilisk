savedcmd_/home/skelly/projects/basilisk/basilisk.o := ld -m elf_x86_64 -z noexecstack --no-warn-rwx-segments   -r -o /home/skelly/projects/basilisk/basilisk.o @/home/skelly/projects/basilisk/basilisk.mod  ; ./tools/objtool/objtool --hacks=jump_label --hacks=noinstr --hacks=skylake --ibt --orc --retpoline --rethunk --sls --static-call --uaccess --prefix=16  --link  --module /home/skelly/projects/basilisk/basilisk.o

/home/skelly/projects/basilisk/basilisk.o: $(wildcard ./tools/objtool/objtool)
