#!/usr/bin/env python3
"""
payload-embedder.py

A script to embed a binary payload into a target file, such as embedding a payload into an image.

Usage:
    python payload-embedder.py <target_file> <payload_file> <output_file>

Example:
    python payload-embedder.py original.png payload.bin embedded.png
"""

import sys
import os

def embed_payload_into_file(target_file_path, payload_file_path, output_file_path):
    """
    Embeds the payload binary data into the target file and writes the combined data to a new output file.

    :param target_file_path: Path to the target file (e.g., original.png)
    :param payload_file_path: Path to the payload binary file to embed (e.g., payload.bin)
    :param output_file_path: Path for the new output file with embedded payload (e.g., embedded.png)
    """
    # Check if target file exists
    if not os.path.isfile(target_file_path):
        print(f"Error: Target file '{target_file_path}' does not exist.")
        sys.exit(1)

    # Check if payload binary file exists
    if not os.path.isfile(payload_file_path):
        print(f"Error: Payload binary file '{payload_file_path}' does not exist.")
        sys.exit(1)

    # Check if output file already exists to prevent accidental overwrites
    if os.path.exists(output_file_path):
        response = input(f"Warning: Output file '{output_file_path}' already exists. Overwrite? (y/n): ")
        if response.lower() != 'y':
            print("Operation canceled by the user.")
            sys.exit(0)

    try:
        # Open the target file in binary read mode
        with open(target_file_path, 'rb') as target_file:
            target_data = target_file.read()
            target_size = len(target_data)
            print(f"Target File: Read {target_size} bytes from '{target_file_path}'.")

        # Open the payload binary file in binary read mode
        with open(payload_file_path, 'rb') as payload_file:
            payload_data = payload_file.read()
            payload_size = len(payload_data)
            print(f"Payload File: Read {payload_size} bytes from '{payload_file_path}'.")

        # Combine the target data with the payload data
        combined_data = target_data + payload_data
        combined_size = len(combined_data)

        # Write the combined data to the new output file
        with open(output_file_path, 'wb') as output_file:
            output_file.write(combined_data)
            print(f"Embedded File: Wrote {combined_size} bytes to '{output_file_path}'.")

        print("Payload embedded successfully.")

    except IOError as e:
        print(f"I/O error occurred: {e}")
        sys.exit(1)

def print_usage():
    """
    Prints the usage instructions.
    """
    print("Usage:")
    print("    python payload-embedder.py <target_file> <payload_file> <output_file>")
    print("\nExample:")
    print("    python payload-embedder.py original.png payload.bin embedded.png")

def main():
    # Check for correct number of arguments
    if len(sys.argv) != 4:
        print("[!] Necessary arguments missing.\n")
        print_usage()
        sys.exit(1)

    target_file = sys.argv[1]
    payload_file = sys.argv[2]
    output_file = sys.argv[3]

    embed_payload_into_file(target_file, payload_file, output_file)

if __name__ == "__main__":
    main()
