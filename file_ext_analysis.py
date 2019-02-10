# https://www.filesignatures.net/, http://forensic-proof.com/archives/300, http://forensic-proof.com/archives/323 등을
# 참고하여 작성


def get_file_ext(data):
    ext = find_21_byte_signature(data)
    if ext:
        return ext

    ext = find_19_byte_signature(data)
    if ext:
        return ext

    ext = find_11_byte_signature(data)
    if ext:
        return ext

    ext = find_8_byte_signature(data)
    if ext:
        return ext

    ext = find_7_byte_signature(data)
    if ext:
        return ext

    ext = find_6_byte_signature(data)
    if ext:
        return ext

    ext = find_5_byte_signature(data)
    if ext:
        return ext

    ext = find_4_byte_signature(data)
    if ext:
        return ext

    ext = find_3_byte_signature(data)
    if ext:
        return ext

    ext = find_2_byte_signature(data)
    if ext:
        return ext

    return False


def find_2_byte_signature(data):
    signature = int.from_bytes(data[:2], byteorder='big')
    ext = None

    if ext is not None:
        return ext
    else:
        return {
            0x424D: "bmp",
            0x4D5A: "exe",
            0x1A0B: "pak",
            0x60EA: "arj",
            0xDCDC: "cpl",
            0xFFFE: "reg"
        }.get(signature, False)


def find_3_byte_signature(data):
    signature = int.from_bytes(data[:3], byteorder='big')
    ext = None

    if ext is not None:
        return ext
    else:
        return {
            0x492049: "tif",
            0x494433: "mp3",
            0x1F8B08: "gz",
            0x464C56: "flv",
            0x435753: "swf", 0x465753: "swf"
        }.get(signature, False)


def find_4_byte_signature(data):
    signature = int.from_bytes(data[:4], byteorder='big')
    ext = None

    if signature == 0x52494646:  # Resource Interchange File Format
        if b'\x57\x41\x56\x45\x66\x6D\x74\x20' in data:  # WAVEfmt
            ext = "wav"
        elif b'\x41\x56\x49\x20\x4C\x49\x53\x54' in data:  # AVI LIST
            ext = "avi"
        elif b'\x43\x44\x44\x41\x66\x6D\x74\x20' in data:  # CDDAfmt
            ext = "cda"
        elif b'\x51\x4C\x43\x4D\x66\x6D\x74\x20' in data:  # QLCMfmt
            ext = "qcp"
        elif b'\x52\x4D\x49\x44\x64\x61\x74\x61' in data:  # RMIDdata
            ext = "rmi"

    if ext is not None:
        return ext
    else:
        return {
            0x47494638: "gif",
            0x0D444F43: "doc", 0xDBA52D00: "doc",
            0x25504446: "pdf",
            0x504B0304: "zip", 0x504B0506: "zip", 0x504B0708: "zip",
            0x00000100: "ico",
            0x00000200: "cur",
            0x49492A00: "tif", 0x4D4D002A: "tif", 0x4D4D002B: "tif",
            0xFFD8FFE0: "jpg", 0xFFD8FFE1: "jpg", 0xFFD8FFE8: "jpg",
            0xFFD8FFE2: "jpeg", 0xFFD8FFE3: "jpeg",
            0xD7CDC69A: "wmf",
            0x01000000: "emf",
            0xC5D0D3C6: "eps",
            0x5041434B: "pak",
            0x49536328: "cab", 0x4D534346: "cab",
            0x5A4F4F20: "zoo",
            0x000001BA: "mpg", 0x000001B3: "mpg",
            0x4D546864: "mid",
            0x2E524D46: "rm",
            0x72656766: "dat", 0x43524547: "dat", 0x574D4D50: "dat", 0x50455354: "dat", 0x736C682E: "dat", 0x736C6821: "dat",
            0xEB3C902A: "img", 0x53434D49: "img"
        }.get(signature, False)


def find_5_byte_signature(data):
    signature = int.from_bytes(data[:5], byteorder='big')
    ext = None

    if ext is not None:
        return ext
    else:
        return {
            0x2E7261FD00: "ra",
            0x7573746172: "tar",
            0x4344303031: "iso"
        }.get(signature, False)


def find_6_byte_signature(data):
    signature = int.from_bytes(data[:6], byteorder='big')
    ext = None

    if ext is not None:
        return ext
    else:
        return {
            0x7B5C72746631: "rtf",
            0x377ABCAF271C: "7z",
            0x504943540008: "img"
        }.get(signature, False)


def find_7_byte_signature(data):
    signature = int.from_bytes(data[:7], byteorder='big')
    ext = None

    if ext is not None:
        return ext
    else:
        return {
            0x526172211A0700: "rar",
            0x727473703A2F2F: "ram",
            0x424C4932323351: "bin",
            0x52454745444954: "reg"
        }.get(signature, False)


def find_8_byte_signature(data):
    signature = int.from_bytes(data[:8], byteorder='big')
    ext = None

    if signature == 0xD0CF11E0A1B11AE1:  # Compound File Binary Format
        if b'\x48\x57\x50\x20\x44\x6F\x63\x75\x6D\x65\x6E\x74\x20\x46\x69\x6C\x65' in data:
            ext = "hwp"
        elif b'\x57\x6F\x72\x64\x2E\x44\x6F\x63\x75\x6D\x65\x6E\x74\x2E' in data:
            ext = "doc"
        elif b'\xFE\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\x57\x00\x6F\x00\x72\x00\x6B\x00' \
             b'\x62\x00\x6F\x00\x6F\x00\x6B\x00' in data:
            ext = "xls"
        elif b'\x50\x00\x6F\x00\x77\x00\x65\x00\x72\x00\x50\x00\x6F\x00\x69\x00\x6E\x00\x74\x00' \
             b'\x20\x00\x44\x00\x6F\x00\x63\x00\x75\x00\x6D\x00\x65\x00\x6E\x00\x74' in data:
            ext = "ppt"
        else:
            ext = "office"

    elif signature == 0x504B030414000600:  # MS Office 2007 documents
        if b'\x77\x6F\x72\x64\x2F\x5F\x72\x65\x6C\x73\x2F\x64\x6F\x63\x75\x6D\x65\x6E\x74\x2E' \
           b'\x78\x6D\x6C\x2E\x72\x65\x6C\x73' in data:  # word/_rels/document.xml.rels
            ext = "docx"
        elif b'\x78\x6C\x2F\x5F\x72\x65\x6C\x73\x2F\x77\x6F\x72\x6B\x62\x6F\x6F\x6B\x2E\x78\x6D' \
             b'\x6C\x2E\x72\x65\x6C\x73' in data:  # xl/_rels/workbook.xml.rels
            ext = "xlsx"
        elif b'\x70\x70\x74\x2F\x5F\x72\x65\x6C\x73\x2F\x70\x72\x65\x73\x65\x6E\x74\x61\x74\x69' \
             b'\x6F\x6E\x2E\x78\x6D\x6C\x2E\x72\x65\x6C\x73' in data:  # ppt/_rels/presentation.xml.rels
            ext = "pptx"
        else:
            ext = "office"

    elif signature == 0x3026B2758E66CF11:  # Windows Media Audio|Video File
        if b'\x41\x00\x73\x00\x70\x00\x65\x00\x63\x00\x74\x00\x52\x00\x61\x00\x74\x00\x69\x00' \
           b'\x6F\x00' in data:  # AspectRatio
            ext = "wmv"
        else:
            ext = "wma"

    if ext is not None:
        return ext
    else:
        return {
            0x89504E470D0A1A0A: "png",
            0x504B030414000100: "zip",
            0xCF11E0A1B11AE100: "doc",
            0x252150532D41646F: "eps",
            0x0000001866747970: "mp4",
            0x664C614300000022: "flac",
            0x4F67675300020000: "ogg",
            0x2E524D4600000012: "ra",
            0x1A45DFA393428288: "mkv",
            0x55464F4F72626974: "dat", 0x4E41565452414646: "dat", 0x52415A4154444231: "dat", 0x1A52545320434F4D: "dat",
            0x504E4349554E444F: "dat", 0x496E6E6F20536574: "dat", 0x436C69656E742055: "dat", 0x4552465353415645: "dat",
            0x415647365F496E74: "dat", 0xA90D000000000000: "dat",
            0x4C00000001140200: "lnk",
            0x0764743264647464: "dtd"
        }.get(signature, False)


def find_11_byte_signature(data):
    signature = int.from_bytes(data[:11], byteorder='big')
    ext = None

    if ext is not None:
        return ext
    else:
        return {
            0x00000020667479704D3441: "m4a",
        }.get(signature, False)


def find_19_byte_signature(data):
    signature = int.from_bytes(data[:19], byteorder='big')
    ext = None

    if ext is not None:
        return ext
    else:
        return {
            0x48575020446F63756D656E742046696C652056: "hwp",
        }.get(signature, False)


def find_21_byte_signature(data):
    signature = int.from_bytes(data[:21], byteorder='big')
    ext = None

    if ext is not None:
        return ext
    else:
        return {
            0x3C3F786D6C2076657273696F6E3D22312E30223F3E: "xml"
        }.get(signature, False)
