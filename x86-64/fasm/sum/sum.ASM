format PE console
entry main

include 'macro/import32.inc'

section '.idata' import data readable
	library msvcrt, 'msvcrt.dll'
	import msvcrt, printf, 'printf', scanf, 'scanf', system, 'system', \
		       exit, 'exit'

section '.data' data readable writable
	request db 'Enter a number: ', 0
	response db 'The sum from 1 to %d is: %d', 10, 0
	fm db '%d', 0
	ps db "pause"

section '.code' code readable executable

sum:
	push ebp
	mov ebp, esp
	push ecx
	mov dword ecx, [ebp + 8]
	xor eax, eax
   check_sum:
	cmp ecx, 0
	je finish_sum
	add eax, ecx
	dec ecx
	jmp check_sum
   finish_sum:
	pop ecx
	leave
	ret

main:
	push ebp
	mov ebp, esp
	sub esp, 4
	push esp
	push request
	call [printf]
	mov dword [esp], fm
	call [scanf]
	add esp, 8
	call sum
	pop ebx
	push eax
	push ebx
	push response
	call [printf]
	mov dword [esp], ps
	call [system]
	mov dword [esp], 0
	call [exit]

