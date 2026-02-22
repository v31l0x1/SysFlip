#include <helper.h>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")


unsigned short ChkSum(unsigned int checkSum, void *fileBase, int len) {

    int *data;
    int sum;

    if(len && fileBase != NULL) {
        data = (int *)fileBase;
        do {
            sum = *(unsigned short *)data + checkSum;
            data = (int *)((char *)data + 2);
            checkSum = (unsigned short)sum + (sum >> 16);
        } while (--len);
    }

    return checkSum + (checkSum >> 16);
}

unsigned int peCheckSum(void *fileBase, unsigned int fileSize) {
    
    void *remainData;
    int remainDataSize;
    unsigned int peHeaderSize;
    unsigned int headerCheckSum;
    unsigned int peHeaderCheckSum;
    unsigned int fileCheckSum;
    PIMAGE_NT_HEADERS ntHeaders;

    ntHeaders = ImageNtHeader(fileBase);
    if (ntHeaders) {
        headerCheckSum = ntHeaders->OptionalHeader.CheckSum;
        peHeaderSize = (unsigned int)ntHeaders - (unsigned int)fileBase + ((unsigned int)&ntHeaders->OptionalHeader.CheckSum - (unsigned int)ntHeaders);
        remainDataSize = (fileSize - peHeaderSize - 4) >> 1;
        remainData = &ntHeaders->OptionalHeader.Subsystem;
        peHeaderCheckSum = ChkSum(0, fileBase, peHeaderSize >> 1);
        fileCheckSum = ChkSum(peHeaderCheckSum, remainData, remainDataSize);

        if (fileSize & 1) {
            fileCheckSum += (unsigned short)*((char *)fileBase + fileSize - 1);
        }
    }  else {
        fileCheckSum = 0;
    }

    return (fileSize + fileCheckSum);
}

wchar_t* genKey(void) {
    static wchar_t key[17];
    int i;

    memset(key, 0, sizeof(key));
    srand((unsigned)time(NULL));

    for (i = 0; i < 16; ++i) {
        key[i] = L'0' + (rand() % 72);
    }
    key[16] = L'\0';

    return key;
}

wchar_t* genRandomBytes(size_t length) {
    
    const wchar_t* st = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789,.-#'?!";
    size_t s_len = 26 * 2 + 10 + 7;
    wchar_t *r_str;
    size_t n;

    unsigned int key;

    srand((unsigned)time(NULL));
    r_str = (wchar_t*)malloc(sizeof(wchar_t) * (length + 1));

    if (!r_str) {
        return NULL;
    }

    for (n = 0; n < length; n++) {
        key = rand() % s_len;
        r_str[n] = st[key];
    }

    r_str[length] = L'\0';

    return r_str;
}

void* mymemcpy(void *dest, const void *src, size_t bytes) {
    unsigned char *d = (unsigned char *)dest;

    const unsigned char *s = (const unsigned char *)src;

    while (bytes-- > 0)
        d[bytes] = s[bytes];
    
    return dest;
}

wchar_t* getFileName(const wchar_t* filePath) {    
    
    wchar_t *sepd;
    int i = 0;
    int l_sep = 0;
    wchar_t sep;

    sepd = (wcsrchr(filePath, L'/') != NULL) ? wcsrchr(filePath, L'/') : wcsrchr(filePath, L'\\');
    if (!sepd) {
        return filePath;
    }

    sep = sepd[0];

    if (*filePath) {
        while (filePath[i]) {
            if (filePath[i] == sep)
                l_sep = i;
            i++;
        }
        return filePath[l_sep] == sep ? &filePath[l_sep + 1] : filePath;
    }

    return filePath;
}

void cryptRc4(unsigned char* data, long dataLen, wchar_t* key, long keyLen, unsigned char* result) {
    
    unsigned char T[256];
    unsigned char S[256];
    unsigned char tmp;
    int j = 0, t = 0, i = 0;
    long x;

    for (i = 0; i < 256; i++) {
        S[i] = (unsigned char)i;
        T[i] = (unsigned char)(wchar_t)key[i % keyLen];
    }

    for (i = 0; i < 256; i++) {
        j = (j + S[i] + T[i]) % 256;
        tmp = S[j];
        S[j] = S[i];
        S[i] = tmp;
    }

    j = 0;
    i = 0;
    for (x = 0; x < dataLen; x++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;

        tmp = S[j];
        S[j] = S[i];
        S[i] = tmp;

        t = (S[i] + S[j]) % 256;

        result[x] = data[x] ^ S[t];
    }
}

int sha1hash(BYTE *peBlob, wchar_t *sha1Buf, DWORD dwBufferLen) {
    HCRYPTPROV h_prov = 0;
    HCRYPTHASH h_hash = 0;
    BYTE rgb_hash[SHA1LEN];
    DWORD cb_hash = 0;
    DWORD i;

    if (!CryptAcquireContext(&h_prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return 0;
    }

    if (!CryptCreateHash(h_prov, CALG_SHA1, 0, 0, &h_hash)) {
        CryptReleaseContext(h_prov, 0);
        return 0;
    }

    if (!CryptHashData(h_hash, peBlob, dwBufferLen, 0)) {
        CryptReleaseContext(h_prov, 0);
        CryptDestroyHash(h_hash);
        return 0;
    }

    cb_hash = SHA1LEN;
    if (CryptGetHashParam(h_hash, HP_HASHVAL, rgb_hash, &cb_hash, 0)) {
        for (i = 0; i < cb_hash; i++) {
            swprintf_s(sha1Buf + (i * 2), 3, L"%02x", rgb_hash[i]);
        }
    } else {
        CryptDestroyHash(h_hash);
        CryptReleaseContext(h_prov, 0);
        return 0;
    }

    CryptDestroyHash(h_hash);
    CryptReleaseContext(h_prov, 0);

    return 1;
}

int is_wow64(HANDLE processHandle) {
    int is_wow64 = 0;
    typedef int(WINAPI *PFNIsWow64Process) (HANDLE, int*);
    PFNIsWow64Process fn_is_wow64_process;

    fn_is_wow64_process = (PFNIsWow64Process)GetProcAddress(GetModuleHandle(L"kernel32"), "IsWow64Process");

    if (NULL != fn_is_wow64_process) {
        fn_is_wow64_process(processHandle, &is_wow64);
    }

    return is_wow64;
}

DWORD vertifyPESig(const wchar_t* filePath, HANDLE fileHandle) {

    DWORD error = ERROR_SUCCESS;
    BOOL wintrust_called = FALSE;
    GUID generic_action_id = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA_EXT wintrust_data = {0};
    WINTRUST_FILE_INFO file_info = {0};
    WINTRUST_SIGNATURE_SETTINGS signature_settings = {0};
    DWORD x;

    wintrust_data.cbStruct = sizeof(WINTRUST_DATA_EXT);
    wintrust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    wintrust_data.dwUIChoice = WTD_UI_NONE;
    wintrust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    wintrust_data.dwUnionChoice = WTD_CHOICE_FILE;

    file_info.cbStruct = sizeof(WINTRUST_FILE_INFO);
    file_info.hFile = fileHandle;
    file_info.pcwszFilePath = filePath;
    wintrust_data.pFile = &file_info;

    signature_settings.cbStruct = sizeof(WINTRUST_SIGNATURE_SETTINGS);
    signature_settings.dwFlags = WSS_GET_SECONDARY_SIG_COUNT | WSS_VERIFY_SPECIFIC;
    signature_settings.dwIndex = 0;
    wintrust_data.pSignatureSettings = &signature_settings;

    error = WinVerifyTrust(NULL, &generic_action_id, (PWINTRUST_DATA)&wintrust_data);
    wintrust_called = TRUE;

    if (error != ERROR_SUCCESS) {
        goto cleanup;
    }

    for (x = 1; x <= wintrust_data.pSignatureSettings->cSecondarySigs; x++) {
        wintrust_data.dwStateAction = WTD_STATEACTION_CLOSE;
        error = WinVerifyTrust(NULL, &generic_action_id, (PWINTRUST_DATA)&wintrust_data);

        if (error != ERROR_SUCCESS) {
            wintrust_called = FALSE;
            goto cleanup;
        }

        wintrust_data.hWVTStateData = NULL;
        wintrust_data.dwStateAction = WTD_STATEACTION_VERIFY;
        wintrust_data.pSignatureSettings->dwIndex = x;
        error = WinVerifyTrust(NULL, &generic_action_id, (PWINTRUST_DATA)&wintrust_data);

        if (error != ERROR_SUCCESS) {
            goto cleanup;
        }
    }

cleanup:
    if (wintrust_called != FALSE) {
        wintrust_data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &generic_action_id, (PWINTRUST_DATA)&wintrust_data);
    }

    return error;
}