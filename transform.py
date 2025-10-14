def convert_hex_string(s: str) -> str:
    s = s.replace("\\x", "")
    bytes_list = [s[i:i+2] for i in range(0, len(s), 2)]
    converted = ["??" if b.upper() == "2A" else b.upper() for b in bytes_list]
    return " ".join(converted)

def convert_hex_string2(s: str) -> str:
    s = s.replace(" ", "\\x")
    bytes_list = [s[i:i+2] for i in range(0, len(s), 2)]
    converted = ["2A" if b == "??" else b for b in bytes_list]
    return "".join(converted)

def convert_to_c_array(s: str) -> str:
    s = s.replace("\\x", "")
    bytes_list = [s[i:i+2] for i in range(0, len(s), 2)]
    converted = []
    for b in bytes_list:
        if b.upper() == "2A":
            converted.append("'*'")   # 0x2A -> '*'
        else:
            converted.append(f"0x{b.upper()}")
    return "{ " + ", ".join(converted) + " }"

data = r""
c_array_str = convert_to_c_array(data)

print(convert_hex_string(data))
print(c_array_str, ";")

