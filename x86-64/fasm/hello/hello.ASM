format PE console
entry main

include 'macro/import32.inc'

section 'data' data readable writable
	hello db "Hello, world", 10, 0
	p db "pause", 0

section '.idata' import data readable
	library msvcrt, 'msvcrt.dll'
	import msvcrt, printf, 'printf', system, 'system', exit, 'exit'

section '.code' code readable executable
main:
	push ebp
	mov ebp, esp
	push hello
	call [printf]
	add esp, 4
	push p
	call [system]
	add esp, 4
	mov dword [esp], 0
	call [exit]
