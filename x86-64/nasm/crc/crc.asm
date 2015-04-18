extern scanf
extern printf

SECTION .text
	global main
	
main:
	push ebp
	mov ebp, esp
	sub esp, 100	; Input string
	sub esp, 4		; CRC
	push msg
		call printf
	lea eax, [ebp - 100]
	push eax
	push input_str
		call scanf
	lea eax, [ebp - 100]
		call generateCRC
	push eax
	push res
		call printf
	leave
	ret
	
generateCRC:
	push ebx
    push ecx
    or ebx,-1
_byteByByte:
	xor bl,byte [eax]
	push 8
	pop ecx
_bitBybit:
    shr ebx,1
    jnc _skip
    xor ebx,0xEDB88320
_skip:
    loop _bitBybit
	inc eax
	cmp byte [eax],0
	jnz _byteByByte
    mov eax,ebx  ;eax = api function string checksum
    pop ecx
    pop ebx
	ret
	
SECTION .data
	msg db "Enter your a string: ", 0
	res db "CRC of given string: %x", 10, 0
	input_str db "%s", 0