all: sysflip

sysflip:
	x86_64-w64-mingw32-gcc -o sysflip.exe main.c helper.c -municode -I . -lwintrust -lcrypt32 -ldbghelp

clean:
	rm -f sysflip.exe