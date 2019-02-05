#pragma once

#include <windows.h>
#include <thread> 
#include <Iphlpapi.h>
#include <wininet.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <istream>
#include <stdio.h>
#include <psapi.h>
#include <TlHelp32.h>
#include <DbgHelp.h>
#include <Winternl.h>
#include <intrin.h>

#define BUFFER 0xFFFFF
typedef UINT16 uint16;
typedef UINT32 uint32;

#ifndef IMR_RELTYPE
#define IMR_RELTYPE(x)				((x >> 12) & 0xF)
#endif

#ifndef IMR_RELOFFSET
#define IMR_RELOFFSET(x)			(x & 0xFFF)
#endif

#define OBS_HASH 6

static __forceinline void PrintConsole( WORD Color , const char* Message , ... )
{
    SetConsoleTextAttribute( GetStdHandle( STD_OUTPUT_HANDLE ) ,
                             FOREGROUND_INTENSITY
                             | Color );

    va_list list;
    char buffer[0xFFFF] = "";
    va_start( list , Message );
    vsprintf_s( buffer , Message , list );
    va_end( list );

    WriteConsoleA( GetStdHandle( STD_OUTPUT_HANDLE ) , buffer , strlen( buffer ) , 0 , 0 );
}

static __forceinline void PrintConsoleNL()
{
    auto cline = OBFUSCATED4( "\n" );
    WriteConsoleA( GetStdHandle( STD_OUTPUT_HANDLE ) , cline , strlen( cline ) , 0 , 0 );
}

static __forceinline BYTE *x0r( BYTE *data , size_t size )
{
    UINT i2 = 0;
    UINT i3 = 0;
    UINT i4 = 16;
    UINT i5 = 32;

    for ( size_t i = 0; i < size; i++ )
    {
        i3++;
        i4--;

        if ( i5 < 1 )
        {
            i5 *= i4;
            i3++;
            i2 += i4;
        }

        if ( i4 < 1 )
        {
            i5--;
            i4 += i5;
            i3++;
            i2 -= i5;
        }

        if ( i3 > 255 )
        {
            i5--;
            i3 = 1;
            i4--;
            i2 *= i4;
        }

        if ( i2 > size )
        {
            i5--;
            i2 = 1;
            i2++;
        }

        i2 = i * i3 * ~i4;

        data[i] = ( data[i] ^ ( ( ( ~i * ( size - i2 ) / i3 + i4 * i5 - i4 ) ) ) & 0xFF );
    }

    return data;

}

static __forceinline BYTE* deobsfdata( BYTE*data , size_t &size )
{
    size_t addedsize = OBS_HASH;
    size_t newsize = size / addedsize;

    PBYTE odata = ( PBYTE ) malloc( size );
    memcpy( ( PVOID ) odata , data , size );

    BYTE* xdata = x0r( odata , size );

    BYTE *newdata = ( BYTE* ) malloc( newsize );

    bool Inverse = false , InverseForce = false;

    int Random = 1 , Wait = 1 , Add = OBS_HASH / 2;

    bool *CanBeWritten = new bool[size];

    for ( size_t i = 0; i < size; i++ )
    {
        CanBeWritten[i] = true;
    }

    bool FinishedDll = false;
    bool Force = false;

    size_t dll = 0;
    for ( size_t i = 0; i < size; i += Random )
    {

        if ( dll > newsize )
        {
            FinishedDll = true;
        }

        if ( FinishedDll )
            continue;

        size_t placeminus = size - i;
        size_t placeadd = i;

        if ( Inverse )
        {
            if ( CanBeWritten[placeminus] && !Force )
            {
                newdata[dll] = xdata[placeminus];
                CanBeWritten[placeminus] = false;
                //printf( "de: 6 %i\n" , Random );
            }
            else
            {
                if ( InverseForce )
                {
                    bool Inv = true;
                    for ( size_t newplace = placeminus; newplace < size; newplace++ )
                    {
                        if ( CanBeWritten[newplace] )
                        {
                            newdata[dll] = xdata[newplace];
                            CanBeWritten[newplace] = false;
                            Inv = false;
                            //printf( "de: 4 %i\n" , Random );
                            break;
                        }
                    }

                    if ( Inv )
                    {
                        for ( size_t newplace = placeminus; newplace >= 0; newplace-- )
                        {
                            if ( CanBeWritten[newplace] )
                            {
                                newdata[dll] = xdata[newplace];
                                CanBeWritten[newplace] = false;
                                Inv = false;
                                //printf( "de: 5 %i\n" , Random );
                                break;
                            }
                        }
                    }
                }
                else
                {
                    bool Inv = true;
                    for ( size_t newplace = placeminus; newplace < size; newplace++ )
                    {
                        if ( CanBeWritten[newplace] )
                        {
                            newdata[dll] = xdata[newplace];
                            CanBeWritten[newplace] = false;
                            Inv = false;
                            //printf( "de: 5 %i\n" , Random );
                            break;
                        }
                    }

                    if ( Inv )
                    {
                        for ( size_t newplace = placeminus; newplace >= 0; newplace-- )
                        {
                            if ( CanBeWritten[newplace] )
                            {
                                newdata[dll] = xdata[newplace];
                                CanBeWritten[newplace] = false;
                                Inv = false;
                                //printf( "de: 4 %i\n" , Random );
                                break;
                            }
                        }
                    }
                }
            }
        }
        else
        {
            if ( CanBeWritten[placeadd] && !Force )
            {
                newdata[dll] = xdata[placeadd];
                CanBeWritten[placeadd] = false;
                //printf( "de: 3 %i\n" , Random );
            }
            else
            {
                if ( InverseForce )
                {
                    bool Inv = true;

                    for ( size_t newplace = placeadd; newplace < size; newplace++ )
                    {
                        if ( CanBeWritten[newplace] )
                        {
                            newdata[dll] = xdata[newplace];
                            CanBeWritten[newplace] = false;
                            Inv = false;
                            //printf( "de: 1 %i\n" , Random );
                            break;
                        }
                    }

                    if ( Inv )
                    {
                        for ( size_t newplace = placeadd; newplace >= 0; newplace-- )
                        {
                            if ( CanBeWritten[newplace] )
                            {
                                newdata[dll] = xdata[newplace];
                                CanBeWritten[newplace] = false;
                                Inv = false;
                                //printf( "de: 2 %i\n" , Random );
                                break;
                            }
                        }
                    }
                }
                else
                {
                    bool Inv = true;

                    for ( size_t newplace = placeadd; newplace >= 0; newplace-- )
                    {
                        if ( CanBeWritten[newplace] )
                        {
                            newdata[dll] = xdata[newplace];
                            CanBeWritten[newplace] = false;
                            Inv = false;
                            //printf( "de: 2 %i\n" , Random );
                            break;
                        }
                    }

                    if ( Inv )
                    {
                        for ( size_t newplace = placeadd; newplace < size; newplace++ )
                        {
                            if ( CanBeWritten[newplace] )
                            {
                                newdata[dll] = xdata[newplace];
                                CanBeWritten[newplace] = false;
                                Inv = false;
                                //printf( "de: 1 %i\n" , Random );
                                break;
                            }
                        }
                    }
                }
            }
        }

        if ( Wait >= OBS_HASH / 2 + Add )
        {
            Inverse = !Inverse;
            Wait = 1;
        }
        else
        {
            Force = !Force;
            Wait++;
        }

        if ( Add <= -OBS_HASH / 2 )
        {
            Force = !Force;
            Add = OBS_HASH / 2;
        }
        else
        {
            Add--;
        }

        if ( Random >= OBS_HASH )
        {
            Random = 1;
        }
        else
        {
            Random++;
        }

        if ( Inverse )
        {
            Random = ( OBS_HASH + 1 ) - Random;
        }


        if ( Inverse == Force )
        {
            InverseForce = !InverseForce;
        }


        dll++;
    }

    // print_bytes( newdata , newsize , "newdata" );

    size = newsize;

    return newdata;
}

static __forceinline BYTE *obsfdata( BYTE*data , size_t &size )
{
    size_t addedsize = OBS_HASH;
    size_t newsize = size * addedsize;

    BYTE* newdata = ( BYTE* ) malloc( newsize );

    bool Inverse = false , InverseForce = false;

    int Random = 1 , Wait = 1 , Add = OBS_HASH / 2;

    bool *CanBeWritten = new bool[newsize];

    for ( size_t i = 0; i < newsize; i++ )
    {
        CanBeWritten[i] = true;
    }

    bool FinishedDll = false;
    bool Force = false;

    size_t dll = 0;
    for ( size_t i = 0; i < newsize; i += Random )
    {
        if ( dll > size )
        {
            FinishedDll = true;
        }

        if ( FinishedDll )
            continue;

        int placeminus = newsize - i;
        int placeadd = i;

        if ( Inverse )
        {
            if ( CanBeWritten[placeminus] && !Force )
            {
                newdata[placeminus] = data[dll];
                CanBeWritten[placeminus] = false;
                //printf( "e: 6 %i\n" , Random );
            }
            else
            {
                if ( InverseForce )
                {
                    bool Inv = true;
                    for ( size_t newplace = placeminus; newplace < newsize; newplace++ )
                    {
                        if ( CanBeWritten[newplace] )
                        {
                            newdata[newplace] = data[dll];
                            CanBeWritten[newplace] = false;
                            Inv = false;
                            //printf( "e: 4 %i\n" , Random );
                            break;
                        }
                    }

                    if ( Inv )
                    {
                        for ( size_t newplace = placeminus; newplace >= 0; newplace-- )
                        {
                            if ( CanBeWritten[newplace] )
                            {
                                newdata[newplace] = data[dll];
                                CanBeWritten[newplace] = false;
                                Inv = false;
                                //printf( "e: 5 %i\n" , Random );
                                break;
                            }
                        }
                    }
                }
                else
                {
                    bool Inv = true;
                    for ( size_t newplace = placeminus; newplace < newsize; newplace++ )
                    {
                        if ( CanBeWritten[newplace] )
                        {
                            newdata[newplace] = data[dll];
                            CanBeWritten[newplace] = false;
                            Inv = false;
                            //printf( "e: 5 %i\n" , Random );
                            break;
                        }
                    }

                    if ( Inv )
                    {
                        for ( size_t newplace = placeminus; newplace >= 0; newplace-- )
                        {
                            if ( CanBeWritten[newplace] )
                            {
                                newdata[newplace] = data[dll];
                                CanBeWritten[newplace] = false;
                                Inv = false;
                                //printf( "e: 4 %i\n" , Random );
                                break;
                            }
                        }
                    }
                }
            }
        }
        else
        {
            if ( CanBeWritten[placeadd] && !Force )
            {
                newdata[placeadd] = data[dll];
                CanBeWritten[placeadd] = false;
                //printf( "e: 3 %i\n" , Random );
            }
            else
            {
                if ( InverseForce )
                {
                    bool Inv = true;

                    for ( size_t newplace = placeadd; newplace < newsize; newplace++ )
                    {
                        if ( CanBeWritten[newplace] )
                        {
                            newdata[newplace] = data[dll];
                            CanBeWritten[newplace] = false;
                            Inv = false;
                            //printf( "e: 1 %i\n" , Random );
                            break;
                        }
                    }

                    if ( Inv )
                    {
                        for ( size_t newplace = placeadd; newplace >= 0; newplace-- )
                        {
                            if ( CanBeWritten[newplace] )
                            {
                                newdata[newplace] = data[dll];
                                CanBeWritten[newplace] = false;
                                Inv = false;
                                //printf( "e: 2 %i\n" , Random );
                                break;
                            }
                        }
                    }
                }
                else
                {
                    bool Inv = true;

                    for ( size_t newplace = placeadd; newplace >= 0; newplace-- )
                    {
                        if ( CanBeWritten[newplace] )
                        {
                            newdata[newplace] = data[dll];
                            CanBeWritten[newplace] = false;
                            Inv = false;
                            //printf( "e: 2 %i\n" , Random );
                            break;
                        }
                    }

                    if ( Inv )
                    {
                        for ( size_t newplace = placeadd; newplace < newsize; newplace++ )
                        {
                            if ( CanBeWritten[newplace] )
                            {
                                newdata[newplace] = data[dll];
                                CanBeWritten[newplace] = false;
                                Inv = false;
                                //printf( "e: 1 %i\n" , Random );
                                break;
                            }
                        }
                    }
                }
            }
        }

        if ( Wait >= OBS_HASH / 2 + Add )
        {
            Inverse = !Inverse;
            Wait = 1;
        }
        else
        {
            Force = !Force;
            Wait++;
        }

        if ( Add <= -OBS_HASH / 2 )
        {
            Force = !Force;
            Add = OBS_HASH / 2;
        }
        else
        {
            Add--;
        }

        if ( Random >= OBS_HASH )
        {
            Random = 1;
        }
        else
        {
            Random++;
        }

        if ( Inverse )
        {
            Random = ( OBS_HASH + 1 ) - Random;
        }

        if ( Inverse == Force )
        {
            InverseForce = !InverseForce;
        }

        dll++;
    }

    for ( size_t i = 0; i < newsize; i++ )
    {
        srand( ( UINT ) time( nullptr ) + i );

        if ( CanBeWritten[i] )
        {
            newdata[i] = rand() % 0xFF;
        }
    }

    BYTE *xnewdata = x0r( newdata , newsize );

    size = newsize;

    return  xnewdata;

}

class CDllMain
{
public:

    CDllMain( PVOID _EntryPoint , PVOID _Module , PVOID _Reason , PVOID _Reserved )
    {
        EntryPoint = _EntryPoint;
        Module = _Module;
        Reason = _Reason;
        Reserved = _Reserved;
    }

    PVOID EntryPoint;
    PVOID Module , Reason , Reserved;
};

static BYTE DllMain_Start[] =
{ 0x8B , 0x44 , 0x24 , 0x04 , 0xFF , 0x70 , 0x0C , 0xFF , 0x70 , 0x08 , 0xFF , 0x70 , 0x04 , 0x8B , 0x00 , 0xFF
, 0xD0 , 0xC2 , 0x04 , 0x00 , 0xCC , 0xCC , 0xCC , 0xCC , 0xCC , 0xCC , 0xCC , 0xCC , 0xCC , 0xCC , 0xCC , 0xCC };


static __forceinline PVOID RvaToVa( PVOID vBase , DWORD vRva )
{
    return ImageRvaToVa( ImageNtHeader( vBase ) , vBase , vRva , 0 );
}

static __forceinline void print_bytes( const void *data , size_t size , const char*str )
{
    UCHAR * bytes = ( UCHAR* ) data;
    printf( "BYTE %s[] = { " , str );
    for ( SIZE_T i = 0; i < size; i++ )
    {
        if ( i == size - 1 )
            printf( "0x%02X" , bytes[i] );
        else
            printf( "0x%02X ," , bytes[i] );
    }
    printf( " };\n" );
}

static __forceinline PVOID ReadFile( const char*path , size_t &size )
{
    FILE* File = nullptr;

    fopen_s( &File , path , "rb" );

    if ( File == nullptr )
    {
        return nullptr;
    }

    fseek( File , 0 , SEEK_END );
    size = ( int ) ftell( File );
    rewind( File );

    PVOID buffer = VirtualAlloc( 0 , size , MEM_COMMIT | MEM_RESERVE , PAGE_READWRITE );

    size_t result = fread( buffer , 1 , size , File );

    fclose( File );

    return buffer;

}

static __forceinline DWORD GetProtectionOfSection( PIMAGE_SECTION_HEADER Section )
{
    DWORD dwCharacteristics = Section->Characteristics;

    DWORD dwResult = 0;

    if ( dwCharacteristics & IMAGE_SCN_MEM_NOT_CACHED )
    {
        dwResult |= PAGE_NOCACHE;
    }

    if ( dwCharacteristics & IMAGE_SCN_MEM_EXECUTE )
    {
        if ( dwCharacteristics & IMAGE_SCN_MEM_READ )
        {
            if ( dwCharacteristics & IMAGE_SCN_MEM_WRITE )
            {
                dwResult |= PAGE_EXECUTE_READWRITE;
            }
            else
            {
                dwResult |= PAGE_EXECUTE_READ;
            }
        }
        else if ( dwCharacteristics & IMAGE_SCN_MEM_WRITE )
        {
            dwResult |= PAGE_EXECUTE_WRITECOPY;
        }
        else
        {
            dwResult |= PAGE_EXECUTE;
        }
    }
    else if ( dwCharacteristics & IMAGE_SCN_MEM_READ )
    {
        if ( dwCharacteristics & IMAGE_SCN_MEM_WRITE )
        {
            dwResult |= PAGE_READWRITE;
        }
        else
        {
            dwResult |= PAGE_READONLY;
        }
    }
    else if ( dwCharacteristics & IMAGE_SCN_MEM_WRITE )
    {
        dwResult |= PAGE_WRITECOPY;
    }
    else
    {
        dwResult |= PAGE_NOACCESS;
    }

    return dwResult;
}

//http://stackoverflow.com/questions/27303062/strstr-function-like-that-ignores-upper-or-lower-case

static __forceinline char* stristr( char* str1 , const char* str2 )
{
    char* p1 = str1;
    const char* p2 = str2;
    char* r = *p2 == 0 ? str1 : 0;

    while ( *p1 != 0 && *p2 != 0 )
    {
        if ( tolower( *p1 ) == tolower( *p2 ) )
        {
            if ( r == 0 )
            {
                r = p1;
            }

            p2++;
        }
        else
        {
            p2 = str2;
            if ( tolower( *p1 ) == tolower( *p2 ) )
            {
                r = p1;
                p2++;
            }
            else
            {
                r = 0;
            }
        }

        p1++;
    }

    return *p2 == 0 ? r : 0;
}


static __forceinline DWORD Align( DWORD size , DWORD align , DWORD addr = 0 )
{
    if ( !( size % align ) )
        return addr + size;

    return addr + ( size / align + 1 ) * align;
}


static __forceinline bool _WriteFile( const char*path , PBYTE pBuffer , size_t &size )
{

    char pathbuffer[MAX_PATH];
    strcpy_s( pathbuffer , path );

    FILE* File = nullptr;

    fopen_s( &File , pathbuffer , "wb+" );

    if ( File == nullptr )
    {
        return 0;
    }

    size_t result = fwrite( pBuffer , 1 , size , File );
    if ( result == 0 )
        return nullptr;

    fclose( File );

    return true;
}


static __forceinline DWORD VaToRawOffset( PIMAGE_DOS_HEADER DosHeader , PIMAGE_NT_HEADERS NtHeaders , DWORD Va , PIMAGE_SECTION_HEADER SectionHeaderF = nullptr )
{
    PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION( NtHeaders );

    for ( WORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++ )
    {
        if ( Va >= SectionHeader[i].VirtualAddress )
        {
            if ( ( Va - SectionHeader[i].VirtualAddress ) <= SectionHeader[i].Misc.VirtualSize )
            {
                SectionHeaderF = &SectionHeader[i];
                return ( Va - SectionHeader[i].VirtualAddress ) + SectionHeader[i].PointerToRawData;
            }
        }
    }

    return 0x0;
}

static __forceinline DWORD RawToVaOffset( PIMAGE_DOS_HEADER DosHeader , PIMAGE_NT_HEADERS NtHeaders , DWORD Raw , PIMAGE_SECTION_HEADER SectionHeaderF = nullptr )
{
    PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION( NtHeaders );

    for ( WORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++ )
    {
        if ( Raw >= SectionHeader[i].PointerToRawData )
        {
            if ( ( Raw - SectionHeader[i].PointerToRawData ) <= SectionHeader[i].SizeOfRawData )
            {
                SectionHeaderF = &SectionHeader[i];
                return ( Raw - SectionHeader[i].PointerToRawData ) + SectionHeader[i].VirtualAddress;
            }
        }
    }

    return 0x0;
}
