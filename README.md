# netcall (WIP)

netcall is (probably) your (most) friendly library to execute manual syscalls from .NET

Features: 
* x86/wow64/x64 support
* Very easy-to-use wrapper

Missing: 
* Final trigger of manual syscall (I have ideas but I'm trying to think about the easiest way)
* Optionally some sort of fully automated runtime encryption/decryption for your syscall stubs, which will decrypt before manual syscall and encrypt after leaving epilogue
* Code clean up 
* Make things more simple
