class file_detector:
    def __init__(self, path):
        global file
        file = open(path, "rb")
        self.path = path

    def get_file_type(self):
        # --- 1) Check PNG ---
        file.seek(0)
        header = file.read(8)
        if header == b'\x89PNG\r\n\x1a\n':
            return "PNG File"
        # --- 2) Check BMP ---
        file.seek(0)
        header = file.read(2)
        if header == b'BM':
            return "BMP File"

        # --- 3) Check PE (EXE/DLL) ---
        if is_pe():
            if is_dll():
                return "DLL File"
            else:
                return "EXE File"

        # --- 4) Unknown ---
        return "Unknown File Type"


# ---------------- PE FUNCTIONS  ----------------

def get_pe_offset():
    hex_3c = 0x3c
    file.seek(hex_3c)
    offset = file.read(4)
    return offset

def is_pe():
    offset = get_pe_offset()
    integer_value = int.from_bytes(offset, byteorder='little', signed=False)
    file.seek(integer_value)
    pe_bytes = file.read(4)
    try:
        pe_str = pe_bytes.decode("utf-8")
    except:
        return False
    if pe_str == "PE\0\0":
        return True
    return False

def get_charechteristic():
    offset = get_pe_offset()
    offset_int = int.from_bytes(offset, byteorder='little', signed=False)
    offset_int += 4
    offset_int += 18
    file.seek(offset_int)
    charechteristic = file.read(2)
    charechteristic_int = int.from_bytes(charechteristic, byteorder='little', signed=False)
    return charechteristic_int

def is_dll():
    charechteristic = get_charechteristic()
    return (charechteristic & 0x2000) != 0


# ---------------- MAIN ----------------

def main():
    while True:
        path = input("where is your file? 'quit' to quit: ")
        if path == 'quit':
            print("bye...")
            break

        try:
            fb = file_detector(path)
            ext = fb.get_file_type()
            print(ext)
        except FileNotFoundError:
            print("File not found.")
        except Exception as e:
            print("Error:", e)

main()


