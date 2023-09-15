# msf_udrl

An attempt to learn about reflective loaders via "rewriting" meterpreter's one. If I read the docs, there's probably an actual way to go about this, but I did it the janky way. Does not bypass defender.

The only significant thing about this project is that it demos the usage of IAT hooking to spoof the call stack of some calls (in this case, LoadLibraryA)

![LoadLibraryA being spoofed from meterpreter](https://i.imgur.com/96rwQDU.png)

This won't bypass defender and the codebase is very messy. It was just a goofy experiment.

# Credits
* AceLdr - Literally did this exact thing already
* KaynLdr - The original reflective loader that I butchered to create this   
