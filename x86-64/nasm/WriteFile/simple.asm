extern OpenFile
extern WriteFile
extern CloseHandle

SECTION .data
	fname db "hello.txt", 0
	msg db "This is a test"
	msg_stop db 0
	
SECTION .text
	global main
	
main:
	push ebp
	mov ebp, esp
	sub esp, 4			; File handle
	sub esp, 136		; OFSTRUCT is about 136 bytes
	lea ebx, [esp]
	
	push dword 1 | 0x1000
	push dword ebx
	push dword fname
		call OpenFile
	mov dword [ebp-4], eax 	;	Save file handle
	lea ebx, [esp]			;	Number of bytes actual written
	
	push dword 0
	push ebx
	push dword msg_stop - msg	; Size of message
	push dword msg				; Message pointer
	push dword [ebp-4]			; File handler
		call WriteFile
	
	push dword [ebp-4]
		call CloseHandle
	
	leave
	ret
