; This PE library is for private use of the member staff of TEAM tRUE only!
;
; DO NOT release / post / upload this file anywhere on the net.
; (C) MiSSiNG iN ByTES (aka jeux) / tRUE - 27.09.2005
; 
; Please respect these terms of use. Thank you.
;





peGetPeEntryPoint         		proto :DWORD
peIncPeFileSize				proto :DWORD,:DWORD
peSetPeEntryPoint			proto :DWORD,:DWORD
peAddSection				proto :DWORD,:DWORD,:DWORD,:DWORD ;eax = Sec Raw Offset, edx = Sec Virtual Offset

.code

peGetPeEntryPoint proc _PeFileName:DWORD
    
    LOCAL IOH:IMAGE_OPTIONAL_HEADER
    LOCAL _hFile:DWORD
    LOCAL hMapping:DWORD
    LOCAL pMapping:DWORD
    local _PeEntryPoint:DWORD
    
    invoke CreateFile,_PeFileName,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_ARCHIVE,NULL
    .if eax != INVALID_HANDLE_VALUE
        mov _hFile, eax
        invoke CreateFileMapping,_hFile,NULL,PAGE_READONLY,0,0,0
        .if eax != NULL
            mov hMapping, eax
            invoke MapViewOfFile,hMapping,FILE_MAP_READ,0,0,0
            .if eax != NULL
                mov pMapping, eax
                mov edi, pMapping
                assume edi:ptr IMAGE_DOS_HEADER
                add edi, [edi].e_lfanew
                assume edi:ptr IMAGE_NT_HEADERS 
                push [edi].OptionalHeader.AddressOfEntryPoint
                pop _PeEntryPoint
                invoke UnmapViewOfFile,pMapping
                invoke CloseHandle,hMapping
                invoke CloseHandle,_hFile
                mov eax, _PeEntryPoint
                ret
            .endif
            invoke CloseHandle,hMapping
        .endif
        invoke CloseHandle,_hFile
    .endif
    mov _PeEntryPoint, 0
    ret

peGetPeEntryPoint endp

peIncPeFileSize proc _PeFileName:DWORD,_newsize:DWORD
	LOCAL _hFile:DWORD
	LOCAL _fSize:DWORD
	LOCAL _NBR:DWORD
	LOCAL hMem:DWORD
	LOCAL pMem:DWORD
	
	invoke CreateFile,_PeFileName,GENERIC_READ or GENERIC_WRITE,NULL,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_ARCHIVE,NULL
	.if eax != INVALID_HANDLE_VALUE
		mov _hFile, eax
		invoke GlobalAlloc,GMEM_FIXED + GMEM_ZEROINIT,_newsize
		mov hMem, eax
		invoke GlobalLock,hMem
    	push eax
		invoke SetFilePointer,_hFile,0,NULL,FILE_END
		pop ecx
		invoke WriteFile,_hFile,ecx,_newsize,addr _NBR,NULL
		invoke GlobalFree,hMem
		invoke CloseHandle,_hFile
	.endif
	
	ret

peIncPeFileSize endp


peSetPeEntryPoint proc _PeFileName:DWORD,_NewEP:DWORD
    
    LOCAL _hFile:DWORD
    LOCAL _fSize:DWORD
    LOCAL _NBR:DWORD
    LOCAL hMapping:DWORD
    LOCAL pMapping:DWORD
    local _PeEntryPoint:DWORD
    
    invoke CreateFile,_PeFileName,GENERIC_READ + GENERIC_WRITE,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_ARCHIVE,NULL
    .if eax != INVALID_HANDLE_VALUE
        mov _hFile, eax
        invoke GetFileSize,_hFile,NULL
        mov _fSize, eax
        invoke CreateFileMapping,_hFile,NULL,PAGE_READWRITE,0,0,0
        .if eax != NULL
            mov hMapping, eax
            invoke MapViewOfFile,hMapping,FILE_MAP_ALL_ACCESS,0,0,0
            .if eax != NULL
                mov pMapping, eax
                mov edi, pMapping
                assume edi:ptr IMAGE_DOS_HEADER
                add edi, [edi].e_lfanew
                assume edi:ptr IMAGE_NT_HEADERS 
                ;seting new entry point
                mov eax, _NewEP
                mov dword ptr [edi].OptionalHeader.AddressOfEntryPoint, eax
                invoke WriteFile,_hFile,pMapping,_fSize,addr _NBR,NULL
                invoke UnmapViewOfFile,pMapping
                invoke CloseHandle,hMapping
                invoke CloseHandle,_hFile
                mov eax, _PeEntryPoint
                ret
            .endif
            invoke CloseHandle,hMapping
        .endif
        invoke CloseHandle,_hFile
    .endif
    mov _PeEntryPoint, 0
    ret

peSetPeEntryPoint endp

peAddSection proc PEFile:DWORD, SectionName:DWORD, SectionSize:DWORD,Characteristics:DWORD
	LOCAL _hFile:DWORD
	LOCAL hMap:DWORD
	LOCAL pMap:DWORD
	LOCAL _NBR:DWORD
	LOCAL NumOfSections:DWORD
	LOCAL _fSize:DWORD
	LOCAL _hMem:DWORD
	LOCAL VOffset:DWORD
	LOCAL FAlignment:DWORD
	LOCAL ROffset:DWORD
	LOCAL SizeOfRawData:DWORD
	
	invoke CreateFile,PEFile,GENERIC_READ + GENERIC_WRITE,NULL,NULL,OPEN_EXISTING,NULL,NULL
	.if eax != INVALID_HANDLE_VALUE
		mov _hFile, eax
		invoke GetFileSize,_hFile,NULL
		mov _fSize, eax
		invoke CreateFileMapping,_hFile,NULL,PAGE_READWRITE,0,0,0
		mov hMap, eax
		invoke MapViewOfFile,hMap,FILE_MAP_ALL_ACCESS,0,0,0
		mov pMap, eax
		
        mov edi, pMap
        assume edi:ptr IMAGE_DOS_HEADER
        add edi, [edi].e_lfanew
        assume edi:ptr IMAGE_NT_HEADERS
        inc dword ptr [edi].FileHeader.NumberOfSections	;increment number of sections
        mov ax, [edi].FileHeader.NumberOfSections		;save number of sections
        movzx eax, ax
        mov NumOfSections, eax
        
        ;get the file alignment
        mov eax, [edi].OptionalHeader.FileAlignment
    	mov FAlignment, eax
    	
		;gets the virtual offset alignment
    	mov eax, [edi].OptionalHeader.SectionAlignment
    	mov VOffset, eax    
        
        add edi, sizeof IMAGE_NT_HEADERS				
        assume edi:ptr IMAGE_SECTION_HEADER
        
        ;seek to the first byte at the last section
		.while NumOfSections > 2		
			dec NumOfSections
			add edi, IMAGE_SECTION_HEADER
		.endw
		
		;calculate the ROffset
		mov ecx, [edi].PointerToRawData
		add ecx, [edi].SizeOfRawData
		mov ROffset, ecx
		
		;calculate the VOffset
		mov eax, [edi].VirtualAddress
		add VOffset, eax
		
		;seek to the first byte after the last section
		add edi, IMAGE_SECTION_HEADER

		;------------ checking up for free space --------------
		.if dword ptr [edi].Name1 != 0
			mov eax, -1
			ret
		.endif
		;------------------------------------------------------
		
		;write section name
		invoke lstrlen,SectionName
		mov ecx, eax
		mov eax, SectionName
		xor ebx, ebx
		lea edx, [edi].Name1
		lp1:
			mov bl, byte ptr [eax]
			mov byte ptr [edx], bl
			inc eax
			inc edx
		loop lp1
		
		;write virtual offset
		push VOffset
		pop [edi].VirtualAddress
		
		;write virtual size
		push SectionSize
		pop [edi].Misc.VirtualSize
		
		;write raw size (aligned section size)
		mov eax, SectionSize
		mov ecx, FAlignment
		.if eax < ecx || eax == ecx
			mov SizeOfRawData, ecx
			push ecx
		.elseif eax > ecx
			.while eax > ecx
				add ecx, ecx
			.endw
			mov SizeOfRawData, ecx
			push ecx
		.endif
		pop [edi].SizeOfRawData
		
		;write section data pointer
		push ROffset
		pop [edi].PointerToRawData
		
		;write section flags
		push Characteristics
		pop [edi].Characteristics
		
		;*** reconstructing the PE ***
		
		;go back to the PE header
        mov edi, pMap
        assume edi:ptr IMAGE_DOS_HEADER
        add edi, [edi].e_lfanew
        assume edi:ptr IMAGE_NT_HEADERS
        mov eax, SizeOfRawData
        add [edi].OptionalHeader.SizeOfCode, eax
        add [edi].OptionalHeader.SizeOfHeaders, IMAGE_SECTION_HEADER
        mov eax, SectionSize
        add [edi].OptionalHeader.SizeOfImage, eax
        
		invoke WriteFile,_hFile,pMap,_fSize,addr _NBR,NULL
        invoke UnmapViewOfFile,pMap
        invoke CloseHandle,hMap
		invoke GlobalAlloc,GMEM_FIXED + GMEM_ZEROINIT,SizeOfRawData
		mov _hMem, eax
		invoke SetFilePointer,_hFile,0,NULL,FILE_END		
		invoke WriteFile,_hFile,_hMem,SizeOfRawData,addr _NBR,NULL
        invoke CloseHandle,_hFile 
        mov eax, _fSize	;returns the pointer to our new section
        mov edx, VOffset
    .else
    	xor eax, eax ;or returns error
	.endif
	ret
	
peAddSection endp 
