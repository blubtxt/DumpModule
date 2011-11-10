#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>

HANDLE hSnapshot = NULL;
HANDLE hProcess  = NULL;

PROCESSENTRY32 pe32;
MODULEENTRY32 me32;

int iProcessCount = NULL;
int iModuleCount = NULL;

char szProcessName[256];
char szModuleName[256];
char szDumpPath[256];

BOOL bNoProcessName = NULL;
BOOL bNoModuleName = NULL;

DWORD dwBuffer;
HANDLE hToken;
TOKEN_PRIVILEGES tpToken;
LUID luid;

int main( int argc, char * argv[] )
{
	printf( "*******************************************************************************\n" );
	printf( "*\n* Module Dumper by blub.txt \n" );
	printf( "* This Tool dumps a module of the specified process memory to a file on Hardrive*\n*\n" );
	printf( "* Usage: DumpModule.exe ProcessName ModuleName DumpPath \n" );
	printf( "* Example: DumpModule.exe steam.exe Steam.dll C:\\test.dump \n*\n" );
	printf( "* If you don`t refer a process name you get a list of the current process,      * the same with modules\n*\n" );
	printf( "*******************************************************************************\n\n" );

	if( argv[1] == NULL )
		bNoProcessName = 1;
	else
	{
		strcpy( szProcessName, argv[1] );

		if( argv[2] == NULL )
			bNoModuleName = 1;
		else
		{
			strcpy( szModuleName, argv[2] );
			strcpy( szDumpPath, argv[3] );
		}
	}

	hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );

	if( hSnapshot == INVALID_HANDLE_VALUE )
	{
		CloseHandle( hSnapshot );
		return 0;
	}

	pe32.dwSize = sizeof( PROCESSENTRY32 );

	if( !Process32First( hSnapshot, &pe32 ) )
	{
		CloseHandle( hSnapshot );
		return 0;
	}

	while( Process32Next( hSnapshot, &pe32 ) )
	{
		if( bNoProcessName == 1)
			printf( "%s \n", pe32.szExeFile );
		
		else if( !lstrcmp( pe32.szExeFile, szProcessName ) )
		{
			printf( "Process found! %s \n", szProcessName );

			hProcess = OpenProcess( PROCESS_ALL_ACCESS, false, pe32.th32ProcessID );

			if( OpenProcessToken( hProcess, TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &hToken) == 0 )
			{
				CloseHandle( hProcess);
				return 0;
			}

			if( ( LookupPrivilegeValue( 0, SE_SECURITY_NAME, &luid ) == 0) || ( LookupPrivilegeValue( 0, SE_DEBUG_NAME, &luid ) == 0 ) )
			{
				CloseHandle( hProcess );
				return 0;	
			}

			tpToken.PrivilegeCount = 1;
			tpToken.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			tpToken.Privileges[0].Luid = luid;

			AdjustTokenPrivileges( hToken, false, &tpToken, sizeof( tpToken ), NULL, 0 );

			hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, pe32.th32ProcessID );

			me32.dwSize = sizeof( MODULEENTRY32 );

			if ( !Module32First( hSnapshot, &me32 ) )
			{
				CloseHandle( hSnapshot );
				return 0;
			}
				
			while( Module32Next( hSnapshot, &me32) )
			{
				if( bNoModuleName == 1 )
					printf( "%s \n", me32.szModule );

				else if( !lstrcmp( me32.szModule, szModuleName ) )
				{
					LPVOID lpBuffer;
					LPDWORD  dwBytesWritten;
					HANDLE hDrop;

					printf( "Module found! %s \n", szModuleName );
					printf( "- Base Address: 0x%x \n", me32.modBaseAddr );
					printf( "- Base Size: %d \n", me32.modBaseSize );

					lpBuffer = VirtualAlloc( NULL, me32.modBaseSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );

					ReadProcessMemory( hProcess, me32.modBaseAddr, lpBuffer, me32.modBaseSize,  NULL );
				
					hDrop = CreateFile( szDumpPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

					if( hDrop != INVALID_HANDLE_VALUE )
					{
						WriteFile( hDrop, lpBuffer, me32.modBaseSize, dwBytesWritten, NULL );
					}

					VirtualFree( lpBuffer, NULL, MEM_RELEASE );

					CloseHandle( hDrop );
					CloseHandle( hSnapshot );
					CloseHandle( hProcess );

					return 1;				
				}
			}
		}
	}

	CloseHandle( hSnapshot );
	Sleep( 5 );
	
	return 1;
}

