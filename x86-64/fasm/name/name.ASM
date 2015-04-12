format PE console
entry start

include 'macro/import32.inc'

section '.data' data readable writable
	request db "Enter your name: ", 0
	response db "Your name is: %s", 10, 0
	fm db "%s", 0
	p db "pause", 0

section '.idata' import data readable
	library msvcrt, 'msvcrt.dll'
	import msvcrt, printf, 'printf', scanf, 'scanf', system, 'system', \
		       exit, 'exit'

section '.code'  code readable executable
start:
	push ebp	; Prepare stack
	mov ebp, esp
	sub esp, 100	; Prepare space for local variables
	push request	; Print request
	call [printf]
	lea eax, [ebp - 100]  ; Load local variable
	mov dword [esp], eax ; Reuse stack
	push fm
	call [scanf]
	mov dword [esp], response
	call [printf]
	mov dword [esp], p
	call [system]
	mov dword [esp], 0
	call [exit]
