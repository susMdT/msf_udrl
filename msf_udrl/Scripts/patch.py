#GPT LMFAO
import sys
import os
import struct

def patch(input_file_path, rdll_path):

    r_data = bytearray()  # Create a bytearray to store the data. Super janky
    with open(rdll_path, 'rb') as input_file:
        while True:
            byte = input_file.read(1)  # Read one byte from the input file
            if not byte:  # End of file
                break
            r_data.extend(byte)  # Append the  byte to the bytearray

    s_data = bytearray()  # Create a bytearray to store the data. Super janky
    with open(input_file_path, 'rb') as input_file:
        while True:
            byte = input_file.read(1)  # Read one byte from the input file
            if not byte:  # End of file
                break
            s_data.extend(byte)  # Append the  byte to the bytearray

    packed_total_length = struct.pack('<I', len(r_data))

    print("[+] Shellcode + RDLL is {} bytes".format(len(s_data)))
    print("[+] RDLL+Overlay is {} bytes".format(len(r_data)))

    s_data_first_half = s_data[: len(s_data) - len(r_data) ]
    r_data_first_half = r_data[:47]
    r_data_other_half = r_data[51:]
    
    with open(input_file_path, 'wb') as f:
        f.write(s_data_first_half)
        f.write(r_data_first_half)
        f.write(packed_total_length)
        f.write(r_data_other_half)

    

def get_file_length(file_path):
    with open(file_path, 'rb') as file:
        file.seek(0, 2)  # Move to the end of the file
        length = file.tell()  # Get the current position, which is the total file length
    return length

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python patch.py <input_file_path> <reflective dll>")
        sys.exit(1)

    input_file_path = sys.argv[1]
    rdll_path = sys.argv[2]

    patch(input_file_path, rdll_path)
