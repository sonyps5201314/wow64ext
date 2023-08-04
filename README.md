# wow64ext
WOW64Ext is a helper library for x86/arm32 programs that runs under WOW64 layer on x64/arm64 versions of Microsoft Windows operating systems. It enables x86/arm32 applications to read, write and enumerate memory of a native x64/arm64 applications. There is also possibility to call any x64/arm64 function from 64-bits version of NTDLL through a special function called Native64Call(). As a bonus, wow64ext.h contains definitions of some structures that might be useful for programs that want to access PEB, TEB, TIB etc.

## prior project:
https://github.com/sonyps5201314/ntdll

## refer to:
https://gitlab.winehq.org/wine/wine

https://github.com/reactos/reactos

https://github.com/rwfpl/rewolf-wow64ext
