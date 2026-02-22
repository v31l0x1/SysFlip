#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>
#include <dbghelp.h>
#include <softpub.h>
#include <wintrust.h>
#include <time.h>

#define SHA1LEN 20

/* WinTrust Signature Settings - for Windows Vista and later */
typedef struct {
    DWORD cbStruct;
    DWORD dwFlags;
    DWORD dwIndex;
    DWORD cSecondarySigs;
    PVOID *pSecondarySigs;
} WINTRUST_SIGNATURE_SETTINGS;

#define WSS_GET_SECONDARY_SIG_COUNT 0x00000200
#define WSS_VERIFY_SPECIFIC         0x00000040

/* Extended WINTRUST_DATA with signature settings support */
typedef struct {
    DWORD cbStruct;
    LPVOID pPolicyCallbackData;
    LPVOID pSIPClientData;
    DWORD dwUIChoice;
    DWORD fdwRevocationChecks;
    DWORD dwUnionChoice;
    union {
        WINTRUST_FILE_INFO *pFile;
        WINTRUST_CATALOG_INFO *pCatalog;
        WINTRUST_BLOB_INFO *pBlob;
        WINTRUST_SGNR_INFO *pSgnr;
        WINTRUST_CERT_INFO *pCert;
    };
    DWORD dwStateAction;
    HANDLE hWVTStateData;
    WCHAR *pwszURLReference;
    DWORD dwProvFlags;
    DWORD dwUIContext;
    WINTRUST_SIGNATURE_SETTINGS *pSignatureSettings;
} WINTRUST_DATA_EXT;

unsigned int peCheckSum(void *fileBase, unsigned int fileSize);
wchar_t* genRandomBytes(size_t length);
wchar_t* genKey(void);
void* mymemcpy(void *dest, const void *src, size_t bytes);
void cryptRc4(unsigned char* data, long dataLen, wchar_t* key, long keyLen, unsigned char* result);
int is_wow64(HANDLE processHandle);
int sha1hash(BYTE *peBlob, wchar_t *sha1Buf, DWORD dwBufferLen);
DWORD vertifyPESig(const wchar_t* filePath, HANDLE fileHandle);
wchar_t* getFileName(const wchar_t* filePath);