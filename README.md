# Admin Panel (name can be changed, I'm not creative)

## Info for organisers
You need to give the participants the `admin_panel` binary (and only that file) so they can reverse and debug it.
The participants need to pwn it remotely (you can build the docker with the provided Dockerfile; the exposed port is 9999).

## How to change the flag
Simply change the flag inside flag.txt and rebuild the docker image.

## Writeup
You can use the exploit.py script in the repo to exploit it (for testing and having a proof that the challenge is possible).

### Reverse Engineering
The first part is to try to understand the program. It is somewhat obvious that the actual code is encoded somehow from binary data in memory.
After a bit of poking around, the participant will, if he knows a bit about exploitation, realise that the program triggers a rop-chain. 
This ropchain uses a cmp and a sub rsp to create a loop in the ropchain. This decodes the string into a newly mapped RW memory section, 
mprotect the section to be executable, writes some function pointers to the .plt to bind libc function to the inner code and jumps to it.

The inner code is encoded via a repeating-key xor which is hardcoded in the binary. As that point, the participant is expected to decode this memory region
with, let's say, python, to be able to reverse-engineer it statically.

In the inner code, one thing to realise is that a lot of pointers are resolved dynamically by offsetting r15, which points to the beggining of the map.
From there, the participant can easily identifies the gets() call and, if he hasn't realised yet, that there is a buffer overflow.

However, before returning, the input data is encrypted to be compared with a "hash" to verify the password. (note that the password itself isn't useful 
at all for the challenge.) This is where the crypto vulnerability comes in to allow the participant to forge his payload.

### Cryptography
The input is encrypted using ChaCha20. However, the implementation is broken and doesn't give the good results, but still acts as a stream cipher.
From there, the participant has to figure out by diving into the code that he is dealing with a stream cipher. The easiest way to find it is to locate
the `sigma` and `tau` constants which are readable strings and should direct the participant to the ChaCha20 spec.

At this point, the participant cannot simply use the hardcoded key and nonce to decrypt his payload into the input he needs to feed to the program because
of the broken implementation. The problem with the ChaCha20 implementation is that the wrong keystream is generated; However, 
the input being XORed with the keystream is still well done.

At that point, there are multiple ways to forge the payload. One of them is to send a bunch of A's in the program, dump the reuslting ciphertext and do 
ks = p ^ c to dump the keystream, which is static because of the hardcoded key and nonce. From there, the participant can take his plaintext payload and XOR it 
with the keystream that, once re-encrypted, will give back the plaintext payload, once again because of ks = p ^ c (in a keystream, 
the encryption and the decryption process is the same). Another way to go is to inject the payload directly into memory with GDB(sending it 
normally would fail because of null bytes) and using the result, since once again, encryption and decryption is the same process.

### PWN
At that point, the only thing left to do is to write the ROPchain to exploit the process. The intended way is to use an `execve()` syscall.
Note that the stager addresses can be hardcoded because there is no PIE.
Because the data is encrypted, there is only mild worries about bad characters that can easily be avoided. There are `pop` gadgets for all needed regiters,
including a "pop rdx; syscall" gadget for end of the chain, and there is a write-what-where gadget used in the decoding ropchain of the stager.

## Author
zer0x64 (Philippe Dugré)