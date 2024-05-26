#!/usr/bin/python3

import sys

def print_hex(filename):
    try:
        with open(filename, "rb") as file:
            data = file.read()
            hex_data = data.hex()
            line = 0
            for i in range(0, len(hex_data), 2):
                if line >= 20:
                    line = 0
                    print()
                line += 1
                print(f"0x{hex_data[i:i+2]}", end=', ')
            print()
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found")

# Example usage:
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <filename>")
        sys.exit(1)
    
    filename = sys.argv[1]
    print_hex(filename)
