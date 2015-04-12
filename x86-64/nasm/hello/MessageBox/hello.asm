extern MessageBoxA
extern ExitProcess

SECTION .data
	hello db "Hello world", 0
	caption db "Hello", 0
	
SECTION .text
	global main
main:
	
	push byte 0
	push dword caption
	push dword hello
	push byte 0
		call MessageBoxA
	
	push 0
		call ExitProcess