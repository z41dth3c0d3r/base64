#include <iostream>
#include <vector>
#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>
#include <winbase.h>
#include <strsafe.h>
#include <tchar.h>

void DisplayError(LPTSTR lpszFunction);

LPCWSTR CharPtrToLPCWSTR(char* cFileName) {
    int bufferSize = MultiByteToWideChar(CP_UTF8, 0, cFileName, -1, NULL, 0);
    if (bufferSize == 0) {
        // Error occurred in conversion
        return NULL;
    }

    // Allocate memory for the wide-string
    wchar_t* wWriteFileName = new wchar_t[bufferSize];
    if (MultiByteToWideChar(CP_UTF8, 0, cFileName, -1, wWriteFileName, bufferSize) == 0) {
        // Error occurred in conversion
        delete[] wWriteFileName;
        return NULL;
    }

    return wWriteFileName;
}

std::vector<BYTE> ReadFileData(char* cFileName) {
    HANDLE hFile;
    std::vector<BYTE> vbFileData;
    LPCWSTR lpFileName = CharPtrToLPCWSTR(cFileName);
    hFile = CreateFile(lpFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Error opening the input file.\n");
        return vbFileData;
    }
    printf("[+] Opened the file successfully.\n");
    DWORD inputFileSize = GetFileSize(hFile, NULL);
    if (inputFileSize == INVALID_FILE_SIZE) {
        printf("[-] Error getting input file size.\n");
        CloseHandle(hFile);
        delete[] lpFileName;
        return vbFileData;
    }

    printf("[+] Size of the file : %d bytes.\n", inputFileSize);
    vbFileData.resize(inputFileSize);
    DWORD bytesRead;
    if (!ReadFile(hFile, vbFileData.data(), inputFileSize, &bytesRead, NULL)) {
        printf("[-] Error reading from the input file.\n");
        CloseHandle(hFile);
        delete[] lpFileName;
        return vbFileData;
    }
    std::wstring wEncodedString(reinterpret_cast<const wchar_t*>(vbFileData.data()), vbFileData.size() / sizeof(wchar_t));
    printf("[+] Read bytes from the input file : %d bytes.\n", bytesRead);
    CloseHandle(hFile);

    delete[] lpFileName;

    return vbFileData;
}

BOOL WriteDataToFile(std::vector<BYTE> vbData, char* cWriteFileName) {
    LPCWSTR lpFileName = CharPtrToLPCWSTR(cWriteFileName);
    HANDLE hFile = CreateFile(lpFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Unable to create or open file  \"%s\" for write.\n", cWriteFileName);
        delete[] lpFileName;
        return FALSE;
    }

    DWORD dwBytesWritten;

    if (!WriteFile(
        hFile,
        vbData.data(),
        static_cast<DWORD>(vbData.size()),
        &dwBytesWritten,
        NULL
    )) {
        CloseHandle(hFile);
        delete[] lpFileName;
        return FALSE;
    }
    printf("[+] Written bytes to file %s: %d bytes.\n", cWriteFileName, dwBytesWritten);
    if (dwBytesWritten != vbData.size())
        printf("[-] Written size and actual size doesn't match.\n");
    else
        printf("[+] Written size and actual size match.\n");
    CloseHandle(hFile);

    printf("[+] Successfully writen the Base64 encoded data to file.\n");

    delete[] lpFileName;

    return TRUE;
}

std::vector<BYTE> Base64Encode(std::vector<BYTE> vbData) {
    std::vector<BYTE> vbBase64EncodedData;
    HCRYPTPROV hCryptProv = 0;
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        printf("[-] Error on CryptAcquireContext.\n");
        return vbBase64EncodedData;
    }

    DWORD base64Size = 0;
    if (!CryptBinaryToStringW(vbData.data(), static_cast<DWORD>(vbData.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &base64Size)) {
        printf("[-] Error getting Base64 encoded size.\n");
        return vbBase64EncodedData;
    }

    printf("[+] Base64 encoded data size: %d bytes.\n", base64Size);
    vbBase64EncodedData.resize(base64Size * sizeof(TCHAR));

    if (!CryptBinaryToStringW(vbData.data(), static_cast<DWORD>(vbData.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, reinterpret_cast<LPWSTR>(vbBase64EncodedData.data()), &base64Size)) {
        printf("[-] Error Base64 encoding the input data.\n");
        return vbBase64EncodedData;
    }

    return vbBase64EncodedData;
}

std::vector<BYTE> Base64Decode(std::vector<BYTE>& vbEncodedData) {
    std::vector<BYTE> vbBase64DecodedData;
    DWORD dwDecodedDataSize = 0;
    std::wstring wEncodedString(reinterpret_cast<const wchar_t*>(vbEncodedData.data()), vbEncodedData.size() / sizeof(wchar_t));

    if (!CryptStringToBinaryW(wEncodedString.c_str(), 0, CRYPT_STRING_BASE64, NULL, &dwDecodedDataSize, NULL, NULL)) {
        printf("[-] Error getting Base64 decoded size.\n");
        return vbBase64DecodedData;
    }
    printf("[+] Decoded data size : %d bytes.\n", dwDecodedDataSize);

    vbBase64DecodedData.resize(dwDecodedDataSize);

    if (!CryptStringToBinaryW(wEncodedString.c_str(), 0, CRYPT_STRING_BASE64, vbBase64DecodedData.data(), &dwDecodedDataSize, nullptr, nullptr)) {
        printf("[-] Error Base64 decoding the data.\n");
        return vbBase64DecodedData;
    }

    return vbBase64DecodedData;
}

std::vector<BYTE> Base64Decode(LPCWSTR vbEncodedData) {
    std::vector<BYTE> vbBase64DecodedData;
    DWORD dwDecodedDataSize = 0;

    if (!CryptStringToBinaryW(vbEncodedData, 0, CRYPT_STRING_BASE64, NULL, &dwDecodedDataSize, NULL, NULL)) {
        printf("[-] Error getting Base64 decoded size.\n");
        return vbBase64DecodedData;
    }
    printf("[+] Decoded data size : %d bytes.\n", dwDecodedDataSize);

    vbBase64DecodedData.resize(dwDecodedDataSize);

    if (!CryptStringToBinaryW(vbEncodedData, 0, CRYPT_STRING_BASE64, vbBase64DecodedData.data(), &dwDecodedDataSize, nullptr, nullptr)) {
        printf("[-] Error Base64 decoding the data.\n");
        return vbBase64DecodedData;
    }
    delete[] vbEncodedData;
    return vbBase64DecodedData;
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

std::vector<BYTE> CharPtrToVector(const char* str) {
    std::vector<BYTE> result;
    size_t strLength = strlen(str);
    result.resize(strLength);
    for (size_t i = 0; i < strLength; ++i) {
        result[i] = static_cast<BYTE>(str[i]);
    }
    return result;
}

int main(int argc, char* argv[]) {
    if (argc < 5) {
        PrintUsage();
        return EXIT_SUCCESS;
    }

    char* cInputFileName = NULL;
    char* cOutputFileName = NULL;
    char* cInputData = NULL;
    BOOL bInputFromScreen = FALSE;
    BOOL bOutputToScreen = FALSE;
    BOOL bEncode = FALSE;
    BOOL bDecode = FALSE;

    for (int i = 0;i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0)
            cInputFileName = argv[i + 1];
        if (strcmp(argv[i], "-iS") == 0) {
            bInputFromScreen = TRUE;
            cInputData = argv[i + 1];
        }
        if (strcmp(argv[i], "-o") == 0)
            cOutputFileName = argv[i + 1];
        if (strcmp(argv[i], "-oS") == 0)
            bOutputToScreen = TRUE;
        if (strcmp(argv[i], "-e") == 0)
            bEncode = TRUE;
        if (strcmp(argv[i], "-d") == 0)
            bDecode = TRUE;
    }

    if (cInputFileName == NULL && !bInputFromScreen) {
        printf("[-] '-i' or '-iS' missing from the command line argument!\n[+] Exiting!\n");
        return EXIT_FAILURE;
    }
    if (cOutputFileName == NULL && !bOutputToScreen) {
        printf("[-] '-o' or '-oS' missing from the command line argument!\n[+] Exiting!\n");
        return EXIT_FAILURE;
    }
    if (!bEncode && !bDecode) {
        printf("[-] '-e' or '-d' missing from the command line!\n[+] Exiting!\n");
        return EXIT_FAILURE;
    }

    LPCWSTR lpInputData = NULL;
    std::vector<BYTE> vbInputData;
    std::vector<BYTE> vbOutputData;

    if (bInputFromScreen && cInputData != NULL) {
        if (bDecode)
            lpInputData = CharPtrToLPCWSTR(cInputData);
        else
            vbInputData = CharPtrToVector(cInputData);
    }
    else if (cInputFileName != NULL) {
        vbInputData = ReadFileData(cInputFileName);
    }

    if (bEncode) {
        vbOutputData = Base64Encode(vbInputData);
    }
    else if (bDecode) {
        if (bInputFromScreen)
            vbOutputData = Base64Decode(lpInputData);
        else
            vbOutputData = Base64Decode(vbInputData);
    }

    if (vbOutputData.empty()) return EXIT_FAILURE;

    if (bOutputToScreen) {
        std::string resultString;
        for (BYTE byte : vbOutputData) {
            if (byte == '\0' || byte == 0) continue;
            resultString += static_cast<char>(byte);
        }
        resultString += '\0';
        if (bEncode) std::cout << "[+] Encoded data : ";
        else std::cout << "[+] Decoded data : ";
        std::cout << resultString << std::endl;

    }
    else if (cOutputFileName != NULL) {
        WriteDataToFile(vbOutputData, cOutputFileName);
    }
    else {
        char* cOutputFileNameBuffer = static_cast<char*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 19));

        if (!cOutputFileNameBuffer) {
            printf("[-] Memory allocation failed for output filename buffer.\n");
            return EXIT_FAILURE;
        }

        if (bEncode)
            strcpy_s(cOutputFileNameBuffer, 18, "base64_encoded.txt");
        else
            strcpy_s(cOutputFileNameBuffer, 18, "base64_decoded.txt");

        cOutputFileNameBuffer[18] = '\0';

        WriteDataToFile(vbOutputData, cOutputFileNameBuffer);

        HeapFree(GetProcessHeap(), 0, cOutputFileNameBuffer);
    }

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