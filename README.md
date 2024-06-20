### Mutante protection
A wide collection of anti-debugging techniques that not only break skids but also destroy their passion for reverse engineering.

### Why I'm releasing this?
Well, someone approached me a while ago claiming they could bypass the authentication system by filling the program with 0x90 NOP instructions and they actually did it! It made me laugh because my anti-0x90 function was there, but I forgot to call it, lol. Since this method is so simple, it has been shared widely, even cracking RedLine spoofer on YouTube using the same approach. I'm releasing this to demonstrate how easy it is to break skids' cracking attempts. If they thought filling the program with 0x90 would lead to bypassing the auth, they're mistaken. We're scanning for INT3, INT2D, prefixes, tracing, EXCEPTION_HANDLER calls, and much more than you can imagine. We also detect every unpacker out there to ensure they won't be able to unpack the program. If they attempt to pack the program, the first thread in our program will invoke NtRaiseHardError or taskkill, resulting in CRITICAL_PROCESS_DIED, 0xDEADDEAD, or whatever you prefer!









### Who made this?
Some of these techniques I've developed myself, while others are borrowed for example, lazy_importer or xorstr for C++.


### Is this method crackble?
Honestly, nothing is fully proof against reverse engineering, but with these methods, even skilled individuals struggle. The purpose here is to disrupt skids' activities.

### Support
> [!TIP]
> Please star the repo if you find it usful 




### Recources
- [lazy_importer](https://github.com/JustasMasiulis/lazy_importer)
- [xorstr](https://github.com/JustasMasiulis/xorstr)
