extern printf

SECTION .data
	hello db "Hello world", 10, 0
	
SECTION .text
	global main
main:
	push    ebp
    mov     ebp,esp
	
	push dword hello
		call printf
		
	leave
	ret
	