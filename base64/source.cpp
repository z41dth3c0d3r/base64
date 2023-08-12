#include <windows.h>
#include <stdio.h>
#include <tchar.h>


LPTSTR ReadFileData(LPTSTR lptFileName) {
    HANDLE hFile;
    LPTSTR lptFileData = NULL;
    hFile = CreateFileW(lptFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Error opening the input file.\n");
        return NULL;
    }
    _tprintf(TEXT("[+] Opened the file \"%s\" successfully.\n"), lptFileName);
    DWORD cbinputFileSize = GetFileSize(hFile, NULL);
    if (cbinputFileSize == INVALID_FILE_SIZE) {
        printf("[-] Error getting input file size.\n");
        CloseHandle(hFile);
        return NULL;
    }

    lptFileData = static_cast<LPTSTR>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (cbinputFileSize + 1) * sizeof(TCHAR)));

    if (!lptFileData) {
        printf("[-] Error occured when allocating memory in heap.\n");
        CloseHandle(hFile);
        return NULL;
    }

    printf("[+] Size of the file : %d bytes.\n", cbinputFileSize);
    DWORD bytesRead;
    if (!ReadFile(hFile, lptFileData, cbinputFileSize, &bytesRead, NULL)) {
        printf("[-] Error reading from the input file.\n");
        CloseHandle(hFile);
        HeapFree(GetProcessHeap(), 0, lptFileData);
        return NULL;
    }
    
    lptFileData[cbinputFileSize] = TEXT('\0');

    printf("[+] Read bytes from the input file : %d bytes.\n", bytesRead);
    CloseHandle(hFile);


    return lptFileData;
}

BOOL WriteDataToFile(LPTSTR lptData, LPTSTR lptWriteFileName) {
    HANDLE hFile = CreateFile(lptWriteFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        _tprintf(TEXT("[-] Unable to create or open file  \"%s\" for write.\n"), lptWriteFileName);
        return FALSE;
    }

    DWORD cbBytesWritten = 0;
    DWORD cbBytesToWrite = static_cast<DWORD>(_tcslen(lptData) * sizeof(TCHAR));

    if (!WriteFile(
        hFile,
        lptData,
        cbBytesToWrite,
        &cbBytesWritten,
        NULL
    )) {
        CloseHandle(hFile);
        return FALSE;
    }

    _tprintf(TEXT("[+] Written bytes to file \"%s\": %d bytes.\n"), lptWriteFileName, cbBytesWritten);

    if (cbBytesWritten != cbBytesToWrite)
        printf("[-] Written size and actual size doesn't match.\n");
    else
        printf("[+] Written size and actual size match.\n");

    CloseHandle(hFile);

    printf("[+] Successfully writen the Base64 encoded data to file.\n");


    return TRUE;
}

LPTSTR Base64Encode(LPTSTR lptData) {

    LPTSTR lptBase64EncodedData = NULL;

    DWORD cbDataLength = _tcslen(lptData);

    DWORD cbBase64Size = 0;
    if (!CryptBinaryToString((const BYTE*)lptData, cbDataLength * sizeof(TCHAR), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &cbBase64Size)) {
        printf("[-] Error getting Base64 encoded size.\n");
        return NULL;
    }

    printf("[+] Base64 encoded data size: %d bytes.\n", cbBase64Size);

    lptBase64EncodedData = static_cast<LPTSTR>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbBase64Size * sizeof(TCHAR)));

    if (!lptBase64EncodedData) {
        printf("[-] Error occured when allocating memory in heap.\n");
        return NULL;
    }

    if (!CryptBinaryToString((const BYTE*)lptData, cbDataLength * sizeof(TCHAR), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, lptBase64EncodedData, &cbBase64Size)) {
        printf("[-] Error Base64 encoding the input data.\n");
        HeapFree(GetProcessHeap(), 0, lptBase64EncodedData);
        return NULL;
    }

    return lptBase64EncodedData;
}

LPTSTR Base64Decode(LPTSTR lptEncodedData) {
    LPTSTR lptBase64DecodedData = NULL;
    DWORD cbDecodedDataSize = 0;

    DWORD cbEncodedDataLength = _tcslen(lptEncodedData);

    if (!CryptStringToBinary(lptEncodedData, cbEncodedDataLength, CRYPT_STRING_BASE64, NULL, &cbDecodedDataSize, NULL, NULL)) {
        printf("[-] Error getting Base64 decoded size.\n");
        return NULL;
    }
    printf("[+] Decoded data size : %d bytes.\n", cbDecodedDataSize);

    lptBase64DecodedData = static_cast<LPTSTR>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbDecodedDataSize * sizeof(TCHAR)));
    
    if (!lptBase64DecodedData) {
        printf("[-] Error occured when allocating memory in heap.\n");
        return NULL;
    }

    if (!CryptStringToBinary(lptEncodedData, cbEncodedDataLength, CRYPT_STRING_BASE64, (BYTE *)lptBase64DecodedData, &cbDecodedDataSize, NULL, NULL)) {
        printf("[-] Error Base64 decoding the data.\n");
        HeapFree(GetProcessHeap(), 0, lptBase64DecodedData);
        return NULL;
    }

    return lptBase64DecodedData;
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

int _tmain(int argc, TCHAR* argv[]) {
    if (argc < 4) {
        PrintUsage();
        return EXIT_SUCCESS;
    }

    LPTSTR lptInputFileName = NULL;
    LPTSTR tOutputFileName = NULL;
    LPTSTR lptInputData = NULL;
    LPTSTR lptOutputData = NULL;
    BOOL bInputFromScreen = FALSE;
    BOOL bOutputToScreen = FALSE;
    BOOL bEncode = FALSE;
    BOOL bDecode = FALSE;

    for (int i = 0;i < argc; i++) {
        if (_tcscmp(argv[i], TEXT("-i")) == 0)
        {
            if(i + 1 != argc)
                lptInputFileName = argv[i + 1];
        }
        if (_tcscmp(argv[i], TEXT("-iS")) == 0) {
            if (i + 1 != argc) {
                bInputFromScreen = TRUE;
                lptInputData = argv[i + 1];
            }
        }
        if (_tcscmp(argv[i], TEXT("-o")) == 0) {
            if (i + 1 != argc)
                tOutputFileName = argv[i + 1];
        }
        if (_tcscmp(argv[i], TEXT("-oS")) == 0)
            bOutputToScreen = TRUE;
        if (_tcscmp(argv[i], TEXT("-e")) == 0)
            bEncode = TRUE;
        if (_tcscmp(argv[i], TEXT("-d")) == 0)
            bDecode = TRUE;
    }

    if (lptInputFileName == NULL && !bInputFromScreen) {
        printf("[-] '-i' or '-iS' missing from the command line argument!\n[+] Exiting!\n");
        return EXIT_FAILURE;
    }

    if (!bEncode && !bDecode) {
        printf("[-] '-e' or '-d' missing from the command line!\n[+] Exiting!\n");
        return EXIT_FAILURE;
    }
   
    if (lptInputFileName != NULL) {
        lptInputData = ReadFileData(lptInputFileName);
    }

    if (lptInputData == NULL) return EXIT_FAILURE;

    if (bEncode) {
        lptOutputData = Base64Encode(lptInputData);
    }
    else if (bDecode) {
        lptOutputData = Base64Decode(lptInputData);
    }

    if (lptOutputData == NULL) return EXIT_FAILURE;

    if (bOutputToScreen) {
        if (bEncode) printf("[+] Encoded data : ");
        else printf("[+] Decoded data : ");

        _tprintf(TEXT("%ls\n"), lptOutputData);
    }
    else if (tOutputFileName != NULL) {
        WriteDataToFile(lptOutputData, tOutputFileName);
    }
    else {
        LPTSTR tOutputFileNameBuffer = static_cast<LPTSTR>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 19 * sizeof(TCHAR)));

        if (!tOutputFileNameBuffer) {
            printf("[-] Memory allocation failed for output filename buffer.\n");
            return EXIT_FAILURE;
        }

        if (bEncode)
            _tcscpy_s(tOutputFileNameBuffer, 19, TEXT("base64_encoded.txt"));
        else
            _tcscpy_s(tOutputFileNameBuffer, 19, TEXT("base64_decoded.txt"));

        WriteDataToFile(lptOutputData, tOutputFileNameBuffer);

        HeapFree(GetProcessHeap(), 0, tOutputFileNameBuffer);
    }
    HeapFree(GetProcessHeap(), 0, lptOutputData);
    if(!bInputFromScreen && lptInputFileName != NULL)
        HeapFree(GetProcessHeap(), 0, lptInputData);

    return EXIT_SUCCESS;
}