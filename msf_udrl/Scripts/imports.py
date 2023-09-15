import pefile
import sys
import os
def parse_imports(pe, option):
    # for entry in pe.DIRECTORY_ENTRY_IMPORT:
    #     print(f"Imported DLL: {entry.dll.decode('utf-8')}")
    #     for imp in entry.imports:
    #         if imp.name is not None:
    #             print(f"  Function: {imp.name.decode('utf-8')}")
    HookFuncs = []
    HashMacros = []
    BoolCons = []
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        if entry.dll.decode('utf-8') == "WS2_32.dll":
            for imp in entry.imports:
                if imp.name is not None:
                    DllName = entry.dll.decode('utf-8')
                    FuncName = imp.name.decode('utf-8')
                    H_NAME = os.popen(f"Scripts/Hasher {imp.name.decode('utf-8')}").read().splitlines()[6].split(" ")[3]
                    DLL_HASH = DllName.split(".dll")[0].upper()+"_HASH"
                    HookFuncs.append(
                        '''  
SEC( text, B ) PVOID {0}Hook( ){{

    PRM p       = {{ 0 }};

    PrepSpoof( &p );

    PVOID p_{0}Addr = LdrFunctionAddr( LdrModulePeb( {1} ), {2} );

    return Spoof( &p, p_{0}Addr, (PVOID)0 );

}}'''.format(FuncName, DLL_HASH, H_NAME))
                    HashMacros.append(os.popen(f"Scripts/Hasher {imp.name.decode('utf-8')}").read().splitlines()[6].split("Function ")[1])
                    BoolCons.append(
                        '''
                        else if ( FunctionHash == {0} )
                        {{
                            Function		= GET_SYMBOL( {1}Hook );
                        }}
                        '''.format(H_NAME, FuncName)
                    )
    if option == 1:
        for x in HookFuncs:
            print(x)
    elif option == 2:
        for x in HashMacros:
            print(x)
    elif option == 3:
        for x in BoolCons:
            print(x)        

if __name__ == "__main__":
    if len(sys.argv) != 3 or "-h" in sys.argv:
        print("Usage: python imports.py <dll> <1 = Hooks, 2 = API Hashes, 3 = Bool Conditions>")
        sys.exit(1)

    pe_file_path = sys.argv[1]

    try:
        pe = pefile.PE(pe_file_path)
        parse_imports(pe, int(sys.argv[2]))
    except Exception as e:
        print(f"Error: {str(e)}")
