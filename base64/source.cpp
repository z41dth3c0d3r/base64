#include <iostream>
#include <vector>
#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>
#include <winbase.h>
#include <strsafe.h>
#include <tchar.h>

void DisplayError(LPTSTR lpszFunction);

TCHAR *ReadFileData(TCHAR *cFileName) {
    HANDLE hFile;
    TCHAR *tFileData = NULL;
    hFile = CreateFileW(cFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Error opening the input file.\n");
        return NULL;
    }
    printf("[+] Opened the file successfully.\n");
    DWORD inputFileSize = GetFileSize(hFile, NULL);
    if (inputFileSize == INVALID_FILE_SIZE) {
        printf("[-] Error getting input file size.\n");
        CloseHandle(hFile);
        return NULL;
    }

    tFileData = static_cast<TCHAR*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ((inputFileSize + 1) * sizeof(TCHAR))));

    if (!tFileData) {
        printf("[-] Error occured when allocating memory in heap.\n");
        CloseHandle(hFile);
        return NULL;
    }

    printf("[+] Size of the file : %d bytes.\n", inputFileSize);
    DWORD bytesRead;
    if (!ReadFile(hFile, tFileData, inputFileSize, &bytesRead, NULL)) {
        printf("[-] Error reading from the input file.\n");
        CloseHandle(hFile);
        HeapFree(GetProcessHeap(), 0, tFileData);
        return NULL;
    }
    
    tFileData[inputFileSize] = _T('\0');

    printf("[+] Read bytes from the input file : %d bytes.\n", bytesRead);
    CloseHandle(hFile);


    return tFileData;
}

BOOL WriteDataToFile(TCHAR *tData, TCHAR *tWriteFileName) {
    HANDLE hFile = CreateFile(tWriteFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        _tprintf(TEXT("[-] Unable to create or open file  \"%s\" for write.\n"), tWriteFileName);
        return FALSE;
    }

    DWORD dwBytesWritten;
    DWORD dwBytesToWrite = static_cast<DWORD>(wcslen(tData) * sizeof(TCHAR));

    if (!WriteFile(
        hFile,
        tData,
        dwBytesToWrite,
        &dwBytesWritten,
        NULL
    )) {
        CloseHandle(hFile);
        return FALSE;
    }

    _tprintf(TEXT("[+] Written bytes to file %s: %d bytes.\n"), tWriteFileName, dwBytesWritten);

    if (dwBytesWritten != dwBytesToWrite)
        printf("[-] Written size and actual size doesn't match.\n");
    else
        printf("[+] Written size and actual size match.\n");

    CloseHandle(hFile);

    printf("[+] Successfully writen the Base64 encoded data to file.\n");


    return TRUE;
}

TCHAR *Base64Encode(TCHAR* tData) {

    TCHAR *tBase64EncodedData = NULL;

    HCRYPTPROV hCryptProv = 0;
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        printf("[-] Error on CryptAcquireContext.\n");
        return tBase64EncodedData;
    }
    
    int wideStringLength = wcslen(tData);

    int utf8Length = WideCharToMultiByte(CP_UTF8, 0, tData, wideStringLength, NULL, 0, NULL, NULL);
    if (utf8Length == 0) {
        _tprintf(TEXT("[-] Conversion failed.\n"));
        return NULL;
    }

    unsigned char* ucData = new unsigned char[utf8Length + 1];

    if (WideCharToMultiByte(CP_UTF8, 0, tData, wideStringLength, reinterpret_cast<LPSTR>(ucData), utf8Length, NULL, NULL) == 0) {
        _tprintf(TEXT("[-] Conversion failed.\n"));
        delete[] ucData;
        return NULL;
    }

    ucData[utf8Length] = '\0';  // Null-terminate the UTF-8 string

    DWORD base64Size = 0;
    if (!CryptBinaryToString(ucData, utf8Length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &base64Size)) {
        printf("[-] Error getting Base64 encoded size.\n");
        delete[] ucData;
        return NULL;
    }

    printf("[+] Base64 encoded data size: %d bytes.\n", base64Size);

    tBase64EncodedData = static_cast<wchar_t*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ((base64Size + 1) * sizeof(TCHAR))));

    if (!tBase64EncodedData) {
        printf("[-] Error occured when allocating memory in heap.\n");
        delete[] ucData;
        return NULL;
    }

    if (!CryptBinaryToString(ucData, utf8Length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, tBase64EncodedData, &base64Size)) {
        printf("[-] Error Base64 encoding the input data.\n");
        HeapFree(GetProcessHeap(), 0, tBase64EncodedData);
        delete[] ucData;
        return NULL;
    }

    delete[] ucData;

    return tBase64EncodedData;
}

TCHAR *Base64Decode(TCHAR *tEncodedData) {
    TCHAR *tBase64DecodedData = NULL;
    unsigned char* ucBase64DecodedData = NULL;
    DWORD dwDecodedDataSize = 0;

    if (!CryptStringToBinary(tEncodedData, 0, CRYPT_STRING_BASE64, NULL, &dwDecodedDataSize, NULL, NULL)) {
        printf("[-] Error getting Base64 decoded size.\n");
        return NULL;
    }
    printf("[+] Decoded data size : %d bytes.\n", dwDecodedDataSize);

    ucBase64DecodedData = static_cast<unsigned char*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwDecodedDataSize));

    if (!ucBase64DecodedData) {
        printf("[-] Error occured when allocating memory in heap.\n");
        return NULL;
    }

    if (!CryptStringToBinary(tEncodedData, 0, CRYPT_STRING_BASE64, ucBase64DecodedData, &dwDecodedDataSize, nullptr, nullptr)) {
        printf("[-] Error Base64 decoding the data.\n");
        HeapFree(GetProcessHeap(), 0, ucBase64DecodedData);
        return NULL;
    }

    int utf8StringLength = static_cast<int>(strlen(reinterpret_cast<const char*>(ucBase64DecodedData)));

    int wideLength = MultiByteToWideChar(CP_UTF8, 0, reinterpret_cast<const char*>(ucBase64DecodedData), utf8StringLength, NULL, 0);
    if (wideLength == 0) {
        _tprintf(TEXT("[-] Conversion failed.\n"));
        HeapFree(GetProcessHeap(), 0, ucBase64DecodedData);
        return NULL;
    }

    tBase64DecodedData = new TCHAR[wideLength + 1];
    if (MultiByteToWideChar(CP_UTF8, 0, reinterpret_cast<const char*>(ucBase64DecodedData), utf8StringLength, tBase64DecodedData, wideLength) == 0) {
        _tprintf(TEXT("[-] Conversion failed.\n"));
        delete[] tBase64DecodedData;
        HeapFree(GetProcessHeap(), 0, ucBase64DecodedData);
        return NULL;
    }

    tBase64DecodedData[wideLength] = L'\0';
    HeapFree(GetProcessHeap(), 0, ucBase64DecodedData);

    return tBase64DecodedData;
}

void PrintUsage(void)
{
    printf("\nUsage : base64.exe [options]\n\n");
    printf("Options\n");
    printf("-------\n");
    printf("\t -i [path_to_file]        : Input data from a file.\n");
    printf("\t -iS [input_data]         : Input data from command line.\n");
    printf("\t -o [output_file_name]    : Output file name.\n");
    printf("\t -oS                      : Output will be printed on screen.\n");
    printf("\t -e                       : To encode the data to base64.\n");
    printf("\t -d                       : To decode the data from base64.\n");
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 5) {
        PrintUsage();
        return EXIT_SUCCESS;
    }

    TCHAR* tInputFileName = NULL;
    TCHAR* tOutputFileName = NULL;
    TCHAR* tInputData = NULL;
    TCHAR* tOutputData = NULL;
    BOOL bInputFromScreen = FALSE;
    BOOL bOutputToScreen = FALSE;
    BOOL bEncode = FALSE;
    BOOL bDecode = FALSE;

    for (int i = 0;i < argc; i++) {
        if (wcscmp(argv[i], L"-i") == 0)
            tInputFileName = argv[i + 1];
        if (wcscmp(argv[i], L"-iS") == 0) {
            bInputFromScreen = TRUE;
            tInputData = argv[i + 1];
        }
        if (wcscmp(argv[i], L"-o") == 0)
            tOutputFileName = argv[i + 1];
        if (wcscmp(argv[i], L"-oS") == 0)
            bOutputToScreen = TRUE;
        if (wcscmp(argv[i], L"-e") == 0)
            bEncode = TRUE;
        if (wcscmp(argv[i], L"-d") == 0)
            bDecode = TRUE;
    }

    if (tInputFileName == NULL && !bInputFromScreen) {
        printf("[-] '-i' or '-iS' missing from the command line argument!\n[+] Exiting!\n");
        return EXIT_FAILURE;
    }
    if (tOutputFileName == NULL && !bOutputToScreen) {
        printf("[-] '-o' or '-oS' missing from the command line argument!\n[+] Exiting!\n");
        return EXIT_FAILURE;
    }
    if (!bEncode && !bDecode) {
        printf("[-] '-e' or '-d' missing from the command line!\n[+] Exiting!\n");
        return EXIT_FAILURE;
    }
   
    if (tInputFileName != NULL) {
        tInputData = ReadFileData(tInputFileName);
    }


    if (tInputData == NULL) return EXIT_FAILURE;

    if (bEncode) {
        tOutputData = Base64Encode(tInputData);
    }
    else if (bDecode) {
        tOutputData = Base64Decode(tInputData);
    }

    if (tOutputData == NULL) return EXIT_FAILURE;

    if (bOutputToScreen) {
        if (bEncode) printf("[+] Encoded data : ");
        else printf("[+] Decoded data : ");

        _tprintf(TEXT("%ls\n"), tOutputData);
    }
    else if (tOutputFileName != NULL) {
        WriteDataToFile(tOutputData, tOutputFileName);
    }
    else {
        TCHAR *tOutputFileNameBuffer = static_cast<TCHAR*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 19));

        if (!tOutputFileNameBuffer) {
            printf("[-] Memory allocation failed for output filename buffer.\n");
            return EXIT_FAILURE;
        }

        if (bEncode)
            wcscpy_s(tOutputFileNameBuffer, 18, TEXT("base64_encoded.txt"));
        else
            wcscpy_s(tOutputFileNameBuffer, 18, TEXT("base64_decoded.txt"));

        tOutputFileNameBuffer[18] = '\0';

        WriteDataToFile(tOutputData, tOutputFileNameBuffer);

        HeapFree(GetProcessHeap(), 0, tOutputFileNameBuffer);
    }

    // HeapFree(GetProcessHeap(), 0, tOutputData);

    // if (bEncode) HeapFree(GetProcessHeap(), 0, tInputData);
    // else delete[] tInputData;

    return 0;
}

void DisplayError(LPTSTR lpszFunction)
// Routine Description:
// Retrieve and output the system error message for the last-error code
{
    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = GetLastError();

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf,
        0,
        NULL);

    lpDisplayBuf =
        (LPVOID)LocalAlloc(LMEM_ZEROINIT,
            (lstrlen((LPCTSTR)lpMsgBuf)
                + lstrlen((LPCTSTR)lpszFunction)
                + 40) // account for format string
            * sizeof(TCHAR));

    if (FAILED(StringCchPrintf((LPTSTR)lpDisplayBuf,
        LocalSize(lpDisplayBuf) / sizeof(TCHAR),
        TEXT("%s failed with error code %d saying \n \t%s"),
        lpszFunction,
        dw,
        lpMsgBuf)))
    {
        printf("[-] FATAL ERROR: Unable to output error code.\n");
    }

    _tprintf(TEXT("[-] ERROR: %s\n"), (LPCTSTR)lpDisplayBuf);

    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
}