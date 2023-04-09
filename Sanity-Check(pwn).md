# Sanity Check (pwn)

Challenge 3, lets check out the binary we got:

``` Bash
$ file checks
checks: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f1667cfadf0c564e31c5076bb20782fe5e54a70a, for GNU/Linux 4.4.0, not stripped

$ checksec --file=checks
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   51 Symbols        No    0               3               checks
```
Again, we have pretty much the same binary in terms of protections. We're probably going to be looking a buffer overflow again with no shellcode injection. Lets run it and see what we can find:

``` Bash
$ ./checks
Enter the secret word: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Login failed!
zsh: segmentation fault  ./checks
```
We see we can overflow the buffer which is a good sign, lets do ```ltrace``` again:

``` Bash
$ ltrace ./checks
setbuf(0x7f922d7cd760, 0)                                                                                = <void>
setbuf(0x7f922d7cd680, 0)                                                                                = <void>
printf("Enter the secret word: "Enter the secret word: )                                                                        = 23
gets(0x7ffdf0d069e0, 0x7ffdf0d04840, 0, 0password123
)                                                               = 0x7ffdf0d069e0
strcmp("password123", "password123")                                                                     = 0
puts("Logged in! Let's just do some qu"...Logged in! Let's just do some quick checks to make sure everything's in order...
)                                                              = 81
puts("Nope, something seems off."Nope, something seems off.
)                                                                       = 27
+++ exited (status 27) +++
```
We again see that the password its looking for is ```password123``` but that doesn't give us our flag right away. Lets check out the source code:

``` C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void main(){
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    char password[64];
    int ways_to_leave_your_lover = 0;
    int what_i_cant_drive = 0;
    int when_im_walking_out_on_center_circle = 0;
    int which_highway_to_take_my_telephones_to = 0;
    int when_i_learned_the_truth = 0;
    
    printf("Enter the secret word: ");
    
    gets(&password);
    
    if(strcmp(password, "password123") == 0){
        puts("Logged in! Let's just do some quick checks to make sure everything's in order...");
        if (ways_to_leave_your_lover == 50) {
            if (what_i_cant_drive == 55) {
                if (when_im_walking_out_on_center_circle == 245) {
                    if (which_highway_to_take_my_telephones_to == 61) {
                        if (when_i_learned_the_truth == 17) {
                            char flag[128];
                            
                            FILE *f = fopen("flag.txt","r");
                            
                            if (!f) {
                                printf("Missing flag.txt. Contact an admin if you see this on remote.");
                                exit(1);
                            }
                            
                            fgets(flag, 128, f);
                            
                            printf(flag);
                            return;
                        }
                    }
                }
            }
        }
        puts("Nope, something seems off.");
    } else {
        puts("Login failed!");
    }
}
```
Ok, so this challenge is about overwriting local variables. We see that we need to enter the correct password and then overwrite all of these variables to their correct values in order for the program to continue to execute.
