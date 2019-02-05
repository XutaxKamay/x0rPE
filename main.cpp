#include "../protect/protect.h"

#define SIGNATURE_CHECK 0x24071337
#define DEBUGINFO
#define FILEBUFFER 0xFFFFFFF

static PVOID __stdcall start_DecryptDLL( PVOID Module , PVOID Reason , PVOID Reserved )
{
    int Count = 0;
    int rdata = -1;
    int reloc = -1;
    bool Wait = false;
    int CountBytes = 0;

    PIMAGE_DOS_HEADER DosHeader = ( PIMAGE_DOS_HEADER ) Module;
    PIMAGE_NT_HEADERS NtHeaders = ( PIMAGE_NT_HEADERS ) ( ( DWORD ) DosHeader + DosHeader->e_lfanew );
    PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION( NtHeaders );

    PBYTE pbOpCode = ( PBYTE ) ( ( DWORD ) DosHeader + SectionHeader[NtHeaders->FileHeader.NumberOfSections - 2].VirtualAddress );
    PDWORD pdwOpCode = ( PDWORD ) pbOpCode;

    PDWORD pdwSectionUnEncrypt = ( PDWORD ) ( ( DWORD ) DosHeader + SectionHeader[NtHeaders->FileHeader.NumberOfSections - 1].VirtualAddress );
    DWORD CountStr = pdwSectionUnEncrypt[0] ^ SIGNATURE_CHECK;

    for ( DWORD i = 0; i < CountStr; i += 2 )
    {
        DWORD Adr = pdwSectionUnEncrypt[i + 1] ^ SIGNATURE_CHECK;
        DWORD Len = pdwSectionUnEncrypt[i + 2] ^ SIGNATURE_CHECK;

        PCHAR pdcSection = ( PCHAR ) ( ( DWORD ) DosHeader + Adr );

        for ( DWORD len = 0; len < Len; len++ )
        {
            pdcSection[len] ^= 0x24;
        }
    }

    PBYTE pdbSection = ( PBYTE ) ( ( DWORD ) DosHeader + SectionHeader[NtHeaders->FileHeader.NumberOfSections - 2].VirtualAddress );

    for ( DWORD size = 0; size < SectionHeader[NtHeaders->FileHeader.NumberOfSections - 2].SizeOfRawData; size++ )
    {
        if ( size <= 1 ) continue;

        pdbSection[size] ^= ( size - ( size & 0xFF ) ) ^ pdbSection[size % 2];
    }


    DWORD EntryPoint = pdwOpCode[0] ^ pdwOpCode[3];

    IMAGE_DATA_DIRECTORY DebugEntry = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    IMAGE_DATA_DIRECTORY ImportEntry = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    IMAGE_DATA_DIRECTORY RelocEntry = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    IMAGE_DATA_DIRECTORY IATEntry = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
    IMAGE_DATA_DIRECTORY LoadCEntry = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];

    for ( int i = 0; i < NtHeaders->FileHeader.NumberOfSections - pbOpCode[7]; i++ )
    {
        PBYTE pdbSection = ( PBYTE ) ( ( DWORD ) DosHeader + SectionHeader[i].VirtualAddress );

        if ( ( SectionHeader[i].VirtualAddress + SectionHeader[i].SizeOfRawData ) >= IATEntry.VirtualAddress
             && ( SectionHeader[i].VirtualAddress <= IATEntry.VirtualAddress ) )
        {
            rdata = i;
        }

        if ( ( SectionHeader[i].VirtualAddress + SectionHeader[i].SizeOfRawData ) >= RelocEntry.VirtualAddress
             && ( SectionHeader[i].VirtualAddress <= RelocEntry.VirtualAddress ) )
        {
            reloc = i;
        }

        if ( SectionHeader[i].Characteristics & IMAGE_SCN_CNT_CODE )
        {
            for ( DWORD size = 0; size < SectionHeader[i].SizeOfRawData; size++ )
            {
                DWORD dwSize = size;
                dwSize *= size;
                dwSize += size;
                dwSize -= size & 0xFF;
                dwSize /= 4;
                dwSize ^= pdwOpCode[3] ^ size ^ pdwOpCode[4 + Count - 1];

                if ( pdwOpCode[4 + Count] == dwSize )
                {
                    Wait = true;
                    CountBytes = 0;
                    Count++;
                }
                else
                {
                    if ( Wait )
                    {
                        CountBytes++;

                        if ( CountBytes >= 3 )
                        {
                            Wait = false;
                            CountBytes = 0;
                        }
                    }
                    else
                        pdbSection[size] ^= ( 0xFF - ( size & 0xFF ) )
                        ^ pbOpCode[4]
                        ^ ( 0xFF - ( pdwOpCode[4 + Count - 2] & 0xFF ) );
                }
            }
        }
        else
        {
            if ( reloc != i && rdata != i )
            {
                for ( DWORD size = 0; size < SectionHeader[i].SizeOfRawData; size++ )
                {
                    DWORD dwSize = size;
                    dwSize *= size;
                    dwSize += size;
                    dwSize -= size & 0xFF;
                    dwSize /= 4;
                    dwSize ^= pdwOpCode[3] ^ size ^ pdwOpCode[4 + Count - 1];

                    if ( pdwOpCode[4 + Count] == dwSize )
                    {
                        Wait = true;
                        CountBytes = 0;
                        Count++;
                    }
                    else
                    {
                        if ( Wait )
                        {
                            CountBytes++;

                            if ( CountBytes >= 3 )
                            {
                                Wait = false;
                                CountBytes = 0;
                            }
                        }
                        else
                            pdbSection[size] ^= ( 0xFF - ( size & 0xFF ) )
                            ^ pbOpCode[5]
                            ^ ( 0xFF - ( pdwOpCode[4 + Count - 2] & 0xFF ) );
                    }
                }
            }
        }
    }

    return ( ( PVOID( __stdcall* )( PVOID , PVOID , PVOID ) )
        ( ( DWORD ) Module + EntryPoint ) )
             ( Module
               , Reason
               , Reserved );
}

static void end_DecryptDLL()
{

}

void AddSection( const char* NewSectionName , PIMAGE_NT_HEADERS NtHeaders , PIMAGE_DOS_HEADER DosHeader , DWORD SizeOfNewSection , size_t &FSize , PBYTE Code )
{
    PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION( NtHeaders );

    WORD NumberOfSections = NtHeaders->FileHeader.NumberOfSections;

    memset( &SectionHeader[NumberOfSections] , 0 , sizeof( IMAGE_SECTION_HEADER ) );

    SectionHeader[NumberOfSections].Characteristics = IMAGE_SCN_MEM_EXECUTE
        | IMAGE_SCN_MEM_READ
        | IMAGE_SCN_MEM_WRITE;


    strcpy_s( ( char* ) SectionHeader[NumberOfSections].Name , 8 , NewSectionName );

    SectionHeader[NumberOfSections].Misc.VirtualSize = SizeOfNewSection;
    SectionHeader[NumberOfSections].SizeOfRawData = Align( SizeOfNewSection , NtHeaders->OptionalHeader.FileAlignment );

    SectionHeader[NumberOfSections].VirtualAddress = Align( SectionHeader[NumberOfSections - 1].Misc.VirtualSize
                                                            , NtHeaders->OptionalHeader.SectionAlignment
                                                            , SectionHeader[NumberOfSections - 1].VirtualAddress );

    SectionHeader[NumberOfSections].PointerToRawData = Align( SectionHeader[NumberOfSections - 1].SizeOfRawData
                                                              , NtHeaders->OptionalHeader.FileAlignment
                                                              , SectionHeader[NumberOfSections - 1].PointerToRawData );

    SectionHeader[NumberOfSections].NumberOfLinenumbers = 0;
    SectionHeader[NumberOfSections].NumberOfRelocations = 0;
    SectionHeader[NumberOfSections].PointerToRelocations = 0;
    SectionHeader[NumberOfSections].PointerToLinenumbers = 0;

    NtHeaders->OptionalHeader.SizeOfImage = Align( SectionHeader[NumberOfSections].Misc.VirtualSize ,
                                                   NtHeaders->OptionalHeader.SectionAlignment ,
                                                   NtHeaders->OptionalHeader.SizeOfImage );

    NtHeaders->OptionalHeader.SizeOfHeaders = Align( sizeof( IMAGE_SECTION_HEADER ) , NtHeaders->OptionalHeader.FileAlignment , NtHeaders->OptionalHeader.SizeOfHeaders );

    if ( Code != nullptr )
    {
        printf( " Added code to %s section (%i (virtual) bytes - %i (raw) bytes) \n" , NewSectionName , SizeOfNewSection , SectionHeader[NumberOfSections].SizeOfRawData );
        memcpy_s( ( PVOID ) ( ( DWORD ) DosHeader + SectionHeader[NumberOfSections].PointerToRawData ) , SectionHeader[NumberOfSections].SizeOfRawData , Code , SizeOfNewSection );
    }
    else
    {
        printf( " No added code to %s section \n" , NewSectionName );
    }

    FSize += SectionHeader[NumberOfSections].SizeOfRawData;
    NtHeaders->FileHeader.NumberOfSections += 1;

}

int main( int args , char **cargs )
{

    if ( args < 2 )
    {
        //printf( "No args. \n" );
        print_bytes( start_DecryptDLL , ( DWORD ) end_DecryptDLL - ( DWORD ) start_DecryptDLL , "Loader" );
        system( "pause" );
        return 0;
    }

    size_t FSize;
    PVOID File = ReadFile( cargs[1] , FSize );

    PVOID FileMallocated = malloc( FILEBUFFER );
    memcpy_s( FileMallocated , FILEBUFFER , File , FSize );

    PIMAGE_DOS_HEADER DosHeader = ( PIMAGE_DOS_HEADER ) FileMallocated;

    if ( DosHeader == nullptr )
    {
        printf( "Couldn't read file. \n" );
        system( "pause" );
        VirtualFree( ( PVOID ) DosHeader , 0 , MEM_RELEASE );
    }

    if ( !( DosHeader->e_magic & IMAGE_DOS_SIGNATURE ) )
    {
        printf( "No dos signature. \n" );
        system( "pause" );
        VirtualFree( ( PVOID ) DosHeader , 0 , MEM_RELEASE );
        return 0;
    }

    PIMAGE_NT_HEADERS NtHeaders = ( PIMAGE_NT_HEADERS ) ImageNtHeader( ( PVOID ) DosHeader );

    PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION( NtHeaders );

    WORD OldNumberOfSections = NtHeaders->FileHeader.NumberOfSections;
    printf( "Old Sections: \n" );
    for ( WORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++ )
    {
        printf( "Section %s, Number %i (0x%X) \n" , SectionHeader[i].Name , i , ( DWORD ) DosHeader + SectionHeader[i].PointerToRawData );
    }

    size_t OldFSize = FSize;

    printf( "Original size of file: %i bytes. (0x%X) \n" , OldFSize , ( DWORD ) DosHeader );

    if ( NtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL
         && NtHeaders->FileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE
         && NtHeaders->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE )
    {
        printf( "DLL Found: Characteristics; 0x%X - Subsytem: 0x%X - File is being encrypted \n" ,
                NtHeaders->FileHeader.Characteristics , NtHeaders->OptionalHeader.Subsystem );

        DWORD OldEP = NtHeaders->OptionalHeader.AddressOfEntryPoint;

        DWORD SizeOfLoader = ( DWORD ) end_DecryptDLL - ( DWORD ) start_DecryptDLL;

        PBYTE Data = ( PBYTE ) malloc( SizeOfLoader );
        memcpy( Data , start_DecryptDLL , SizeOfLoader );

        print_bytes( Data , SizeOfLoader , "Loader" );

        WORD BeforeLdrNBSecs = NtHeaders->FileHeader.NumberOfSections;
        AddSection( ".data" , NtHeaders , DosHeader , SizeOfLoader , FSize , Data );
        NtHeaders->OptionalHeader.AddressOfEntryPoint = SectionHeader[OldNumberOfSections].VirtualAddress;

        DWORD dwNewSectionSize = 0xFFFFF;
        PBYTE pbNewDataADRS = ( PBYTE ) malloc( dwNewSectionSize );

        PDWORD pdwNewDataADRS = ( PDWORD ) pbNewDataADRS;
        pbNewDataADRS[4] = 0xF7;
        pbNewDataADRS[5] = 0x24;
        pbNewDataADRS[6] = 0x37;
        pbNewDataADRS[7] = 3;
        pdwNewDataADRS[2] = SIGNATURE_CHECK;
        pdwNewDataADRS[3] = pdwNewDataADRS[2] ^ pdwNewDataADRS[1];
        pdwNewDataADRS[0] = OldEP ^ pdwNewDataADRS[3];

        printf( "EP changed: 0x%X -> 0x%X (0x%X) \n" , OldEP , NtHeaders->OptionalHeader.AddressOfEntryPoint , pdwNewDataADRS[0] ^ pdwNewDataADRS[3] );

        DWORD vadata = NtHeaders->OptionalHeader.ImageBase + SectionHeader[0].VirtualAddress;
        PBYTE bvaData = ( PBYTE ) &vadata;

        DWORD Maxvadata = NtHeaders->OptionalHeader.ImageBase + NtHeaders->OptionalHeader.SizeOfImage;

        PBYTE bMaxvadata = ( PBYTE ) &Maxvadata;

        printf( "imgbase: (0x%X) -- (max) (0x%X) \n" , vadata , Maxvadata );


        IMAGE_DATA_DIRECTORY DebugEntry = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        IMAGE_DATA_DIRECTORY ImportEntry = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        IMAGE_DATA_DIRECTORY RelocEntry = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        IMAGE_DATA_DIRECTORY IATEntry = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
        IMAGE_DATA_DIRECTORY LoadCEntry = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
        IMAGE_DATA_DIRECTORY RessourceEntry = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];

        int Count = 0;
        int rdata = -1;
        int reloc = -1;
        bool Wait = false;
        int CountBytes = 0;

        std::vector<DWORD> dwCalls;

        for ( int i = 0; i < OldNumberOfSections; i++ )
        {
            PBYTE pdbSection = ( PBYTE ) ( ( DWORD ) DosHeader + SectionHeader[i].PointerToRawData );

            for ( DWORD size = 0; size < SectionHeader[i].SizeOfRawData; size++ )
            {
                DWORD dwSection = *( DWORD* ) &pdbSection[size];

                if ( dwSection >= vadata && dwSection <= Maxvadata )
                {
                    bool CanAdd = true;

                    for ( DWORD size = 0; size < dwCalls.size(); size++ )
                    {
                        if ( dwCalls[size] == dwSection )
                        {
                            CanAdd = false;
                        }
                    }

                    if ( CanAdd )
                    {
                        dwCalls.push_back( dwSection );
                    }
                }
            }
        }

        for ( int i = 0; i < OldNumberOfSections; i++ )
        {
            PBYTE pdbSection = ( PBYTE ) ( ( DWORD ) DosHeader + SectionHeader[i].PointerToRawData );

            if ( ( SectionHeader[i].VirtualAddress + SectionHeader[i].SizeOfRawData ) >= IATEntry.VirtualAddress
                 && ( SectionHeader[i].VirtualAddress <= IATEntry.VirtualAddress ) )
            {
                printf( "Found IAT %i \n" , i );
                rdata = i;
            }

            if ( ( SectionHeader[i].VirtualAddress + SectionHeader[i].SizeOfRawData ) >= RelocEntry.VirtualAddress
                 && ( SectionHeader[i].VirtualAddress <= RelocEntry.VirtualAddress ) )
            {
                printf( "Found RelocTable %i \n" , i );
                reloc = i;
            }

            if ( SectionHeader[i].Characteristics & IMAGE_SCN_CNT_CODE )
            {
                for ( DWORD size = 0; size < SectionHeader[i].SizeOfRawData; size++ )
                {
                    DWORD dwSection = *( DWORD* ) &pdbSection[size];

                    if ( dwSection >= vadata && dwSection <= Maxvadata )
                    {
#ifdef DEBUGINFO
                        printf( "code: 0x%X -> " , dwSection );

                        printf( "data call detected (%X) --- 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X \n" ,
                                NtHeaders->OptionalHeader.ImageBase + SectionHeader[i].VirtualAddress + size
                                , pdbSection[size - 2]
                                , pdbSection[size - 1]
                                , pdbSection[size] , pdbSection[size + 1] , pdbSection[size + 2] , pdbSection[size + 3] );
#endif

                        pdwNewDataADRS[4 + Count] = size;
                        pdwNewDataADRS[4 + Count] *= size;
                        pdwNewDataADRS[4 + Count] += size;
                        pdwNewDataADRS[4 + Count] -= size & 0xFF;
                        pdwNewDataADRS[4 + Count] /= 4;
                        pdwNewDataADRS[4 + Count] ^= pdwNewDataADRS[3] ^ size ^ pdwNewDataADRS[4 + Count - 1];


                        Count++;
                        Wait = true;
                        CountBytes = 0;
                    }
                    else
                    {
                        if ( Wait )
                        {
                            CountBytes++;

                            if ( CountBytes >= 3 )
                            {
#ifdef DEBUGINFO
                                printf( "0x%02X 0x%02X 0x%02X 0x%02X ignored\n"
                                        , pdbSection[size - 3] , pdbSection[size - 2] , pdbSection[size - 1] , pdbSection[size] );

#endif
                                Wait = false;
                                CountBytes = 0;
                            }
                        }
                        else
                            pdbSection[size] ^= ( 0xFF - ( size & 0xFF ) )
                            ^ pbNewDataADRS[4]
                            ^ ( 0xFF - ( pdwNewDataADRS[4 + Count - 2] & 0xFF ) );
                    }
                }
            }
            else
            {
                if ( reloc != i && rdata != i )
                {
                    printf( "Encrypting others possible sections...\n" );
                    // system( "pause" );

                    for ( DWORD size = 0; size < SectionHeader[i].SizeOfRawData; size++ )
                    {
                        DWORD dwSection = *( DWORD* ) &pdbSection[size];

                        if ( dwSection >= vadata && dwSection <= Maxvadata )
                        {
#ifdef DEBUGINFO
                            printf( "others: 0x%X -> " , dwSection );

                            printf( "data call detected (%X) --- 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X \n" ,
                                    NtHeaders->OptionalHeader.ImageBase + SectionHeader[i].VirtualAddress + size
                                    , pdbSection[size - 2]
                                    , pdbSection[size - 1]
                                    , pdbSection[size] , pdbSection[size + 1] , pdbSection[size + 2] , pdbSection[size + 3] );
#endif

                            pdwNewDataADRS[4 + Count] = size;
                            pdwNewDataADRS[4 + Count] *= size;
                            pdwNewDataADRS[4 + Count] += size;
                            pdwNewDataADRS[4 + Count] -= size & 0xFF;
                            pdwNewDataADRS[4 + Count] /= 4;
                            pdwNewDataADRS[4 + Count] ^= pdwNewDataADRS[3] ^ size ^ pdwNewDataADRS[4 + Count - 1];

                            Count++;
                            CountBytes = 0;
                            Wait = true;
                        }
                        else
                        {
                            if ( Wait )
                            {
                                CountBytes++;

                                if ( CountBytes >= 3 )
                                {
#ifdef DEBUGINFO
                                    printf( "0x%02X 0x%02X 0x%02X 0x%02X ignored\n"
                                            , pdbSection[size - 3] , pdbSection[size - 2] , pdbSection[size - 1] , pdbSection[size] );
#endif
                                    Wait = false;
                                    CountBytes = 0;
                                }
                            }
                            else
                                pdbSection[size] ^= ( 0xFF - ( size & 0xFF ) )
                                ^ pbNewDataADRS[5]
                                ^ ( 0xFF - ( pdwNewDataADRS[4 + Count - 2] & 0xFF ) );
                        }
                    }
                }
            }

            SectionHeader[i].Characteristics = SectionHeader[i].Characteristics | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;
        }

        dwNewSectionSize = sizeof( DWORD ) * 4 + Count * sizeof( DWORD );

        AddSection( ".vip" , NtHeaders , DosHeader , dwNewSectionSize , FSize , pbNewDataADRS );

        printf( "Encrypting section... \n" );

        PBYTE pdbSection = ( PBYTE ) ( ( DWORD ) DosHeader + SectionHeader[NtHeaders->FileHeader.NumberOfSections - 1].PointerToRawData );

        for ( DWORD size = 0; size < SectionHeader[NtHeaders->FileHeader.NumberOfSections - 1].SizeOfRawData; size++ )
        {
            if ( size <= 1 ) continue;

            pdbSection[size] ^= ( size - ( size & 0xFF ) ) ^ pdbSection[size % 2];
        }

        printf( "Found %i calls in code section. \n" , dwCalls.size() );

        DWORD dwNewSectionSize2 = 0xFFFFF;
        PBYTE pbNewDataADRS2 = ( PBYTE ) malloc( dwNewSectionSize2 );
        PDWORD pdwNewDataADRS2 = ( PDWORD ) pbNewDataADRS2;
        dwNewSectionSize2 = 0;
        Count = 0;

        for ( DWORD size = 0; size < dwCalls.size(); size++ )
        {
            dwCalls[size] -= NtHeaders->OptionalHeader.ImageBase;

            if ( dwCalls[size] != 0 )
            {
                PIMAGE_SECTION_HEADER pSectionFound = nullptr;

                DWORD dwRawCalls = VaToRawOffset( DosHeader , NtHeaders , dwCalls[size] , pSectionFound );

                PCHAR pdbSection = ( PCHAR ) ( ( DWORD ) DosHeader + dwRawCalls );

                int LenString = 0;

                while ( pdbSection[LenString] != 0 )
                {
                    LenString++;
                }

                if ( dwRawCalls != 0 && LenString > 1 )
                {
#ifdef DEBUGINFO
                    printf( "Call: (Virtual) %X (Raw) %X (%s) %i \n" , dwCalls[size] , dwRawCalls , pdbSection , LenString );

#endif
                    for ( int i = 0; i < LenString; i++ )
                    {
                        pdbSection[i] ^= 0x24;
                    }

                    pdwNewDataADRS2[Count + 1] = dwCalls[size] ^ SIGNATURE_CHECK;
                    pdwNewDataADRS2[Count + 2] = LenString ^ SIGNATURE_CHECK;
                    dwNewSectionSize2 += sizeof( DWORD ) * 2;
                    Count += 2;
                }
            }
        }

        pdwNewDataADRS2[0] = Count ^ SIGNATURE_CHECK;
        dwNewSectionSize2 += sizeof( DWORD );

        AddSection( ".sex" , NtHeaders , DosHeader , dwNewSectionSize2 , FSize , pbNewDataADRS2 );

        printf( "New Sections: \n" );

        for ( int i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++ )
        {
            printf( "Section %s, Number %i (Raw 0x%X) (Virtual 0x%X) \n" , SectionHeader[i].Name , i ,
                    SectionHeader[i].PointerToRawData , SectionHeader[i].VirtualAddress );

            SectionHeader[i].Misc.VirtualSize = 0;
            SectionHeader[i].Misc.PhysicalAddress = 0;
            strcpy_s( ( char* ) SectionHeader[i].Name , 8 , "" );
        }


        srand( ( UINT ) time( 0 ) );
        NtHeaders->FileHeader.Characteristics = 0;
        NtHeaders->FileHeader.Machine = rand() % 0xFFFF;
        NtHeaders->FileHeader.TimeDateStamp = rand() % INFINITE;
        NtHeaders->OptionalHeader.BaseOfCode = rand() % INFINITE;
        NtHeaders->OptionalHeader.SizeOfCode = rand() % INFINITE;
        NtHeaders->OptionalHeader.CheckSum = rand() % INFINITE;
        NtHeaders->OptionalHeader.DllCharacteristics = rand() % 0xFFFF;
        NtHeaders->OptionalHeader.LoaderFlags = rand() % INFINITE;
        NtHeaders->OptionalHeader.Magic = rand() % 0xFFFF;
        NtHeaders->OptionalHeader.FileAlignment = rand() % INFINITE;
        NtHeaders->OptionalHeader.SectionAlignment = rand() % INFINITE;
        NtHeaders->OptionalHeader.SizeOfHeapCommit = rand() % INFINITE;
        NtHeaders->OptionalHeader.BaseOfData = rand() % INFINITE;
        NtHeaders->OptionalHeader.SizeOfInitializedData = rand() % INFINITE;
        NtHeaders->OptionalHeader.SizeOfStackReserve = rand() % INFINITE;
        NtHeaders->OptionalHeader.SizeOfUninitializedData = rand() % INFINITE;
        NtHeaders->OptionalHeader.Subsystem = rand() % 0xFFFF;
        NtHeaders->OptionalHeader.Win32VersionValue = rand() % INFINITE;
        DosHeader->e_cblp = rand() % 0xFFFF;
        DosHeader->e_cp = rand() % 0xFFFF;
        DosHeader->e_cparhdr = rand() % 0xFFFF;
        DosHeader->e_crlc = rand() % 0xFFFF;
        DosHeader->e_csum = rand() % 0xFFFF;
        DosHeader->e_ip = rand() % 0xFFFF;
        DosHeader->e_lfarlc = rand() % 0xFFFF;
        DosHeader->e_maxalloc = rand() % 0xFFFF;
        DosHeader->e_minalloc = rand() % 0xFFFF;
        DosHeader->e_oemid = rand() % 0xFFFF;
        DosHeader->e_oeminfo = rand() % 0xFFFF;
        DosHeader->e_ovno = rand() % 0xFFFF;
        DosHeader->e_res[0] = rand() % 0xFFFF;
        DosHeader->e_res[1] = rand() % 0xFFFF;
        DosHeader->e_res[2] = rand() % 0xFFFF;
        DosHeader->e_res[3] = rand() % 0xFFFF;
        DosHeader->e_res2[0] = rand() % 0xFFFF;
        DosHeader->e_res2[1] = rand() % 0xFFFF;
        DosHeader->e_res2[2] = rand() % 0xFFFF;
        DosHeader->e_res2[3] = rand() % 0xFFFF;
        DosHeader->e_res2[4] = rand() % 0xFFFF;
        DosHeader->e_res2[5] = rand() % 0xFFFF;
        DosHeader->e_res2[6] = rand() % 0xFFFF;
        DosHeader->e_res2[7] = rand() % 0xFFFF;
        DosHeader->e_res2[8] = rand() % 0xFFFF;
        DosHeader->e_res2[9] = rand() % 0xFFFF;
        DosHeader->e_sp = rand() % 0xFFFF;
        DosHeader->e_ss = rand() % 0xFFFF;
        DosHeader->e_magic = rand() % 0xFFFF;
    }
    else
    {
        printf( "Characteristics; 0x%X - Subsytem: 0x%X - File is cannot be encrypted \n" ,
                NtHeaders->FileHeader.Characteristics , NtHeaders->OptionalHeader.Subsystem );

    }

    printf( "New size of file: %i bytes -> new-old %i bytes. \n" , FSize , FSize - OldFSize );

    //if ( !_WriteFile( cargs[1] , ( PBYTE ) DosHeader , FSize ) )
    {
        printf( "Couldn't write file. \n" );
        system( "pause" );
        free( DosHeader );
        VirtualFree( ( PVOID ) File , 0 , MEM_RELEASE );
        return 0;
    }

    printf( "Written file. \n" );
    system( "pause" );

    free( DosHeader );
    VirtualFree( ( PVOID ) File , 0 , MEM_RELEASE );
}

// Encryption simple d'un exécutable sous windows.

#include "../protect/protect.h"

#define SIGNATURE_CHECK 0x24071337
#define DEBUGINFO
#define FILEBUFFER 0xFFFFFFF

static int start_DecryptEXE()
{
    int Count = 0;
    int rdata = -1;
    int reloc = -1;
    bool Wait = false;
    int CountBytes = 0;

    PIMAGE_DOS_HEADER DosHeader = ( PIMAGE_DOS_HEADER ) GetModuleHandleA( 0 );
    PIMAGE_NT_HEADERS NtHeaders = ( PIMAGE_NT_HEADERS ) ( ( DWORD ) DosHeader + DosHeader->e_lfanew );
    PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION( NtHeaders );

    IMAGE_DATA_DIRECTORY DebugEntry = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    IMAGE_DATA_DIRECTORY ImportEntry = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    IMAGE_DATA_DIRECTORY RelocEntry = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    IMAGE_DATA_DIRECTORY IATEntry = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];

    PBYTE pdbSection = ( PBYTE ) ( ( DWORD ) DosHeader + SectionHeader[NtHeaders->FileHeader.NumberOfSections - 2].VirtualAddress );

    for ( DWORD size = 0; size < SectionHeader[NtHeaders->FileHeader.NumberOfSections - 2].SizeOfRawData; size++ )
    {
        if ( size <= 1 ) continue;

        pdbSection[size] ^= ( size - ( size & 0xFF ) ) ^ pdbSection[size % 2];
    }

    int NumberOfSections = NtHeaders->FileHeader.NumberOfSections;

    PBYTE pbOpCode = ( PBYTE ) ( ( DWORD ) DosHeader + SectionHeader[NtHeaders->FileHeader.NumberOfSections - 2].VirtualAddress );
    PDWORD pdwOpCode = ( PDWORD ) pbOpCode;

    DWORD EntryPoint = pdwOpCode[0] ^ pdwOpCode[3];

    for ( int i = 0; i < NtHeaders->FileHeader.NumberOfSections - pbOpCode[7]; i++ )
    {
        PBYTE pdbSection = ( PBYTE ) ( ( DWORD ) DosHeader + SectionHeader[i].VirtualAddress );

        if ( SectionHeader[i].Characteristics & IMAGE_SCN_CNT_CODE )
        {
            for ( DWORD size = 0; size < SectionHeader[i].SizeOfRawData; size++ )
            {
                DWORD dwSize = size;
                dwSize *= size;
                dwSize += size;
                dwSize -= size & 0xFF;
                dwSize /= 4;
                dwSize ^= pdwOpCode[3] ^ size ^ pdwOpCode[4 + Count - 1];

                if ( pdwOpCode[4 + Count] == dwSize )
                {
                    Wait = true;
                    CountBytes = 0;
                    Count++;
                }
                else
                {
                    if ( Wait )
                    {
                        CountBytes++;

                        if ( CountBytes >= 3 )
                        {
                            Wait = false;
                            CountBytes = 0;
                        }
                    }
                    else
                        pdbSection[size] ^= ( 0xFF - ( size & 0xFF ) )
                        ^ pbOpCode[4]
                        ^ ( 0xFF - ( pdwOpCode[4 + Count - 2] & 0xFF ) );
                }
            }
        }
    }

    return ( ( int( *)( ) ) ( ( DWORD ) DosHeader + EntryPoint ) )( );
}

static void end_DecryptEXE()
{

}


void AddSection( const char* NewSectionName , PIMAGE_NT_HEADERS NtHeaders , PIMAGE_DOS_HEADER DosHeader , DWORD SizeOfNewSection , size_t &FSize , PBYTE Code )
{
    PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION( NtHeaders );

    WORD NumberOfSections = NtHeaders->FileHeader.NumberOfSections;

    memset( &SectionHeader[NumberOfSections] , 0 , sizeof( IMAGE_SECTION_HEADER ) );

    SectionHeader[NumberOfSections].Characteristics = IMAGE_SCN_MEM_EXECUTE
        | IMAGE_SCN_MEM_READ
        | IMAGE_SCN_MEM_WRITE;


    strcpy_s( ( char* ) SectionHeader[NumberOfSections].Name , 8 , NewSectionName );

    SectionHeader[NumberOfSections].Misc.VirtualSize = SizeOfNewSection;
    SectionHeader[NumberOfSections].SizeOfRawData = Align( SizeOfNewSection , NtHeaders->OptionalHeader.FileAlignment );

    SectionHeader[NumberOfSections].VirtualAddress = Align( SectionHeader[NumberOfSections - 1].Misc.VirtualSize
                                                            , NtHeaders->OptionalHeader.SectionAlignment
                                                            , SectionHeader[NumberOfSections - 1].VirtualAddress );

    SectionHeader[NumberOfSections].PointerToRawData = Align( SectionHeader[NumberOfSections - 1].SizeOfRawData
                                                              , NtHeaders->OptionalHeader.FileAlignment
                                                              , SectionHeader[NumberOfSections - 1].PointerToRawData );

    SectionHeader[NumberOfSections].NumberOfLinenumbers = 0;
    SectionHeader[NumberOfSections].NumberOfRelocations = 0;
    SectionHeader[NumberOfSections].PointerToRelocations = 0;
    SectionHeader[NumberOfSections].PointerToLinenumbers = 0;

    NtHeaders->OptionalHeader.SizeOfImage = Align( SectionHeader[NumberOfSections].Misc.VirtualSize ,
                                                   NtHeaders->OptionalHeader.SectionAlignment ,
                                                   NtHeaders->OptionalHeader.SizeOfImage );

    NtHeaders->OptionalHeader.SizeOfHeaders = Align( sizeof( IMAGE_SECTION_HEADER ) , NtHeaders->OptionalHeader.FileAlignment , NtHeaders->OptionalHeader.SizeOfHeaders );

    if ( Code != nullptr )
    {
        printf_s( " Added code to %s section (%i (virtual) bytes - %i (raw) bytes) \n" , NewSectionName , SizeOfNewSection , SectionHeader[NumberOfSections].SizeOfRawData );
        memcpy_s( ( PVOID ) ( ( DWORD ) DosHeader + SectionHeader[NumberOfSections].PointerToRawData ) , SectionHeader[NumberOfSections].SizeOfRawData , Code , SizeOfNewSection );
    }
    else
    {
        printf_s( " No added code to %s section \n" , NewSectionName );
    }

    FSize += SectionHeader[NumberOfSections].SizeOfRawData;
    NtHeaders->FileHeader.NumberOfSections += 1;

}

int main( int args , char **cargs )
{

    if ( args < 2 )
    {
        printf_s( "No args. \n" );
        system( "pause" );
        return 0;
    }

    size_t FSize;
    PVOID File = ReadFile( cargs[1] , FSize );

    PVOID FileMallocated = malloc( FILEBUFFER );
    memcpy_s( FileMallocated , FILEBUFFER , File , FSize );

    PIMAGE_DOS_HEADER DosHeader = ( PIMAGE_DOS_HEADER ) FileMallocated;

    if ( DosHeader == nullptr )
    {
        printf_s( "Couldn't read file. \n" );
        system( "pause" );
        VirtualFree( ( PVOID ) DosHeader , 0 , MEM_RELEASE );
    }

    if ( !( DosHeader->e_magic & IMAGE_DOS_SIGNATURE ) )
    {
        printf_s( "No dos signature. \n" );
        system( "pause" );
        VirtualFree( ( PVOID ) DosHeader , 0 , MEM_RELEASE );
        return 0;
    }

    PIMAGE_NT_HEADERS NtHeaders = ( PIMAGE_NT_HEADERS ) ImageNtHeader( ( PVOID ) DosHeader );

    if ( !( NtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL )
         && NtHeaders->FileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE
         && NtHeaders->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE
         && NtHeaders->OptionalHeader.Subsystem & IMAGE_SUBSYSTEM_WINDOWS_GUI )
    {

        PIMAGE_DATA_DIRECTORY ImportEntry = &NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        PIMAGE_DATA_DIRECTORY DebugEntry = &NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        PIMAGE_DATA_DIRECTORY RelocEntry = &NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        PIMAGE_DATA_DIRECTORY IATEntry = &NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];

        int Count = 0;
        int rdata = -1;
        int reloc = -1;
        bool Wait = false;
        int CountBytes = 0;

        PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION( NtHeaders );

        WORD OldNumberOfSections = NtHeaders->FileHeader.NumberOfSections;
        printf_s( "Old Sections: \n" );
        for ( WORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++ )
        {
            printf_s( "Section %s, Number %i (0x%X) \n" , SectionHeader[i].Name , i , SectionHeader[i].VirtualAddress );
        }

        size_t OldFSize = FSize;

        printf_s( "Original size of file: %i bytes. (0x%X) \n" , OldFSize , ( DWORD ) DosHeader );

        DWORD dwOldEP = NtHeaders->OptionalHeader.AddressOfEntryPoint;
        WORD dwOldNumberOfSections = NtHeaders->FileHeader.NumberOfSections;
        DWORD dwRoutineSize = ( DWORD ) end_DecryptEXE - ( DWORD ) start_DecryptEXE;
        PVOID pAllocatedRoutine = malloc( dwRoutineSize );
        memcpy( pAllocatedRoutine , start_DecryptEXE , dwRoutineSize );

        PBYTE pbSection = ( PBYTE ) pAllocatedRoutine;

        PIMAGE_NT_HEADERS NtHeadersCurrentProcess = ( PIMAGE_NT_HEADERS ) ImageNtHeader( ( PVOID ) GetModuleHandleA( 0 ) );

        DWORD ImageBaseCP = NtHeadersCurrentProcess->OptionalHeader.ImageBase;
        DWORD MaxSizeCP = NtHeadersCurrentProcess->OptionalHeader.ImageBase + NtHeadersCurrentProcess->OptionalHeader.SizeOfImage;

        for ( DWORD size = 0; size < dwRoutineSize; size++ )
        {
            DWORD *dwSection = ( DWORD* ) &pbSection[size];

            if ( *dwSection >= ImageBaseCP && *dwSection <= MaxSizeCP )
            {
                PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = ( PIMAGE_IMPORT_DESCRIPTOR ) ( RvaToVa( DosHeader , ImportEntry->VirtualAddress ) );
                if ( ImportDescriptor != nullptr )
                {
                    while ( ImportDescriptor->Name != 0 )
                    {
                        PCHAR ModuleName = ( PCHAR ) RvaToVa( ( PVOID ) DosHeader , ImportDescriptor->Name );

                        if ( ModuleName == nullptr )
                        {
                            continue;
                        }

                        if ( ImportDescriptor->FirstThunk != 0 )
                        {
                            PIMAGE_THUNK_DATA FirstThunkData = ( PIMAGE_THUNK_DATA ) RvaToVa( ( PVOID ) DosHeader , ImportDescriptor->FirstThunk );

                            DWORD i = 0;
                            while ( FirstThunkData->u1.AddressOfData != 0
                                    && FirstThunkData->u1.AddressOfData < NtHeaders->OptionalHeader.ImageBase + NtHeaders->OptionalHeader.SizeOfImage )
                            {
                                if ( IMAGE_SNAP_BY_ORDINAL( FirstThunkData->u1.Ordinal ) )
                                {
                                    PCHAR sOrdinal = ( PCHAR ) IMAGE_ORDINAL( FirstThunkData->u1.Ordinal );

                                    if ( sOrdinal == nullptr )
                                        continue;

                                    if ( FirstThunkData->u1.Function != 0 && !strcmp( "GetModuleHandleA" , sOrdinal ) )
                                    {
                                        *dwSection = NtHeaders->OptionalHeader.ImageBase + ImportDescriptor->FirstThunk + i;
                                        printf_s( "0x%X ->  0x%X -> %s -> %s \n" , ImportDescriptor->FirstThunk , FirstThunkData->u1.Function , ModuleName , sOrdinal );
                                    }
                                }
                                else
                                {
                                    PIMAGE_IMPORT_BY_NAME ImportByName = ( PIMAGE_IMPORT_BY_NAME ) RvaToVa( ( PVOID ) DosHeader , FirstThunkData->u1.AddressOfData );

                                    PCHAR NameOfFunc = ( PCHAR ) ImportByName->Name;

                                    if ( NameOfFunc == nullptr )
                                        continue;

                                    if ( FirstThunkData->u1.Function != 0 && !strcmp( "GetModuleHandleA" , NameOfFunc ) )
                                    {
                                        *dwSection = NtHeaders->OptionalHeader.ImageBase + ImportDescriptor->FirstThunk + i;
                                        printf_s( "0x%X ->  0x%X -> %s -> %s \n" , ImportDescriptor->FirstThunk , FirstThunkData->u1.Function , ModuleName , NameOfFunc );
                                    }
                                }

                                i += sizeof( DWORD );
                                FirstThunkData++;
                            }
                        }

                        ImportDescriptor++;
                    }
                }

                printf_s( "GetModuleHandleA call: 0x%X \n" , *dwSection );
            }
        }


        AddSection( ".ldr" , NtHeaders , DosHeader , dwRoutineSize , FSize , ( PBYTE ) pAllocatedRoutine );

        IMAGE_DATA_DIRECTORY BaseRelocationEntry = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

        PIMAGE_BASE_RELOCATION Relocation = ( PIMAGE_BASE_RELOCATION ) ( RvaToVa( ( PVOID ) DosHeader , BaseRelocationEntry.VirtualAddress ) );

        Relocation->SizeOfBlock += ( DWORD ) sizeof( IMAGE_BASE_RELOCATION );   //If we want our GetModuleHandle being at the right address...

        NtHeaders->OptionalHeader.AddressOfEntryPoint = SectionHeader[NtHeaders->FileHeader.NumberOfSections - 1].VirtualAddress;

        printf_s( "Encrypting...\n" );

        DWORD dwNewSectionSize = 0xFFFFF;
        PBYTE pbNewDataADRS = ( PBYTE ) malloc( dwNewSectionSize );

        PDWORD pdwNewDataADRS = ( PDWORD ) pbNewDataADRS;
        pbNewDataADRS[4] = 0xF7;
        pbNewDataADRS[5] = 0x24;
        pbNewDataADRS[6] = 0x37;
        pbNewDataADRS[7] = 2;
        pdwNewDataADRS[2] = SIGNATURE_CHECK;
        pdwNewDataADRS[3] = pdwNewDataADRS[2] ^ pdwNewDataADRS[1];
        pdwNewDataADRS[0] = dwOldEP ^ pdwNewDataADRS[3];

        printf( "EP changed: 0x%X -> 0x%X (0x%X) \n" , dwOldEP , NtHeaders->OptionalHeader.AddressOfEntryPoint , pdwNewDataADRS[0] ^ pdwNewDataADRS[3] );

        DWORD ImgStart = NtHeaders->OptionalHeader.ImageBase + SectionHeader[0].VirtualAddress;

        DWORD MaxSize = NtHeaders->OptionalHeader.ImageBase + NtHeaders->OptionalHeader.SizeOfImage;

        printf( "imgbase: (0x%X) -- (max) (0x%X) \n" , ImgStart , MaxSize );

        std::vector<DWORD> dwCalls;

        for ( WORD i = 0; i < OldNumberOfSections; i++ )
        {
            PBYTE pdbSection = ( PBYTE ) ( ( DWORD ) DosHeader + SectionHeader[i].PointerToRawData );

            if ( ( SectionHeader[i].VirtualAddress + SectionHeader[i].SizeOfRawData ) >= IATEntry->VirtualAddress
                 && ( SectionHeader[i].VirtualAddress <= IATEntry->VirtualAddress ) )
            {
                printf( "Found IAT %i \n" , i );
                rdata = i;
            }

            if ( ( SectionHeader[i].VirtualAddress + SectionHeader[i].SizeOfRawData ) >= RelocEntry->VirtualAddress
                 && ( SectionHeader[i].VirtualAddress <= RelocEntry->VirtualAddress ) )
            {
                printf( "Found RelocTable %i \n" , i );
                reloc = i;
            }

            if ( SectionHeader[i].Characteristics & IMAGE_SCN_CNT_CODE )
            {
                for ( DWORD size = 0; size < SectionHeader[i].SizeOfRawData; size++ )
                {
                    DWORD dwSection = *( DWORD* ) &pdbSection[size];

                    if ( dwSection >= ImgStart && dwSection <= MaxSize )
                    {
#ifdef DEBUGINFO
                        printf( "code: 0x%X -> " , dwSection );

                        printf( "data call detected (%X) --- 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X \n" ,
                                NtHeaders->OptionalHeader.ImageBase + SectionHeader[i].VirtualAddress + size
                                , pdbSection[size - 2]
                                , pdbSection[size - 1]
                                , pdbSection[size] , pdbSection[size + 1] , pdbSection[size + 2] , pdbSection[size + 3] );
#endif

                        pdwNewDataADRS[4 + Count] = size;
                        pdwNewDataADRS[4 + Count] *= size;
                        pdwNewDataADRS[4 + Count] += size;
                        pdwNewDataADRS[4 + Count] -= size & 0xFF;
                        pdwNewDataADRS[4 + Count] /= 4;
                        pdwNewDataADRS[4 + Count] ^= pdwNewDataADRS[3] ^ size ^ pdwNewDataADRS[4 + Count - 1];


                        Count++;
                        Wait = true;
                        CountBytes = 0;

                        bool CanAdd = true;
                        for ( DWORD size = 0; size < dwCalls.size(); size++ )
                        {
                            if ( dwCalls[size] == dwSection )
                            {
                                CanAdd = false;
                            }
                        }

                        if ( CanAdd )
                        {
                            dwCalls.push_back( dwSection );
                        }
                    }
                    else
                    {
                        if ( Wait )
                        {
                            CountBytes++;

                            if ( CountBytes >= 3 )
                            {
#ifdef DEBUGINFO
                                printf( "0x%02X 0x%02X 0x%02X 0x%02X ignored\n"
                                        , pdbSection[size - 3] , pdbSection[size - 2] , pdbSection[size - 1] , pdbSection[size] );

#endif
                                Wait = false;
                                CountBytes = 0;
                            }
                        }
                        else
                            pdbSection[size] ^= ( 0xFF - ( size & 0xFF ) )
                            ^ pbNewDataADRS[4]
                            ^ ( 0xFF - ( pdwNewDataADRS[4 + Count - 2] & 0xFF ) );
                    }
                }
            }

            SectionHeader[i].Characteristics = SectionHeader[i].Characteristics | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;
        }

        dwNewSectionSize = sizeof( DWORD ) * 4 + Count * sizeof( DWORD );

        AddSection( ".data" , NtHeaders , DosHeader , dwNewSectionSize , FSize , pbNewDataADRS );

        PBYTE pdbSection = ( PBYTE ) ( ( DWORD ) DosHeader + SectionHeader[NtHeaders->FileHeader.NumberOfSections - 1].PointerToRawData );

        for ( DWORD size = 0; size < SectionHeader[NtHeaders->FileHeader.NumberOfSections - 1].SizeOfRawData; size++ )
        {
            if ( size <= 1 ) continue;

            pdbSection[size] ^= ( size - ( size & 0xFF ) ) ^ pdbSection[size % 2];
        }


        printf( "New Sections: \n" );

        for ( int i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++ )
        {
            printf( "Section %s, Number %i (Raw 0x%X) (Virtual 0x%X) \n" , SectionHeader[i].Name , i ,
                    SectionHeader[i].PointerToRawData , SectionHeader[i].VirtualAddress );

            strcpy_s( ( char* ) SectionHeader[i].Name , 8 , "" );
        }

        printf_s( "New size of file: %i bytes -> new-old %i bytes. \n" , FSize , FSize - OldFSize );

        if ( !_WriteFile( cargs[1] , ( PBYTE ) DosHeader , FSize ) )
        {
            printf_s( "Couldn't write file. \n" );
            system( "pause" );
            free( DosHeader );
            VirtualFree( ( PVOID ) File , 0 , MEM_RELEASE );
            return 0;
        }

        printf_s( "Written file. \n" );
        system( "pause" );

        free( DosHeader );
        VirtualFree( ( PVOID ) File , 0 , MEM_RELEASE );

    }
}
