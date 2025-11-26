#!/usr/bin/env python3

import argparse
import sys
import os
import hashlib

def calculate_chunk_size(output_filename, target_width=80):
    """
    Calculates a chunk size (bytes per line) that attempts to keep
    the total line length around target_width.
    """

    overhead = len("echo -ne \"\" >> \"\"") + len(output_filename) 
    
    available_space = target_width - overhead
    
    # Each byte takes 4 characters: \xNN
    calculated_size = available_space // 4
    
    # Ensure no less than 4 bytes per chunk
    return max(4, calculated_size)

def main():
    parser = argparse.ArgumentParser(
        description="Convert a binary file into a series of echo commands."
    )
    
    parser.add_argument(
        "input_file", 
        help="The binary file to read."
    )
    
    parser.add_argument(
        "-o", "--output-file",
        dest="output_file",
        help="The filename that the generated script will write to (default: same as input)."
    )
    
    parser.add_argument(
        "-c", "--chunk-size", 
        type=int, 
        help="Number of bytes per echo command. (default: auto-calculated for ~80 char lines)"
    )
    
    parser.add_argument(
        "--no-verify", 
        action="store_false", 
        dest="verify",
        help="Disable the verification checksum check at the end."
    )
    
    # Set default for verify to True
    parser.set_defaults(verify=True)

    args = parser.parse_args()

    # Validate input file
    if not os.path.isfile(args.input_file):
        parser.print_help(sys.stderr)
        sys.stderr.write(f"\nError: Input file '{args.input_file}' not found.\n")
        sys.exit(1)

    # Determine output filename (for the echo commands)
    target_filename = args.output_file if args.output_file else os.path.basename(args.input_file)

    # Determine chunk size
    chunk_size = args.chunk_size
    if chunk_size is None:
        chunk_size = calculate_chunk_size(target_filename)

    # Initialize hashing
    sha256 = hashlib.sha256()

    try:
        with open(args.input_file, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                
                # Update hash
                if args.verify:
                    sha256.update(chunk)

                # Convert to hex string \xNN\xNN...
                # We double escape the backslash so it prints as a literal \x in the output
                hex_str = "".join(f"\\x{b:02x}" for b in chunk)
                
                # Print the command
                print(f'echo -ne "{hex_str}" >> "{target_filename}"')

    except IOError as e:
        sys.stderr.write(f"Error reading file: {e}\n")
        sys.exit(1)

    # Generate verification block
    if args.verify:
        original_checksum = sha256.hexdigest()
        print(f'\nactual=$(sha256sum "{target_filename}")')
        print('actual=${actual%% *}')
        print(f'if [ "$actual" = "{original_checksum}" ]; then echo "file verification succeeded"; else echo "file verification failed"; fi')

if __name__ == "__main__":
    main()
