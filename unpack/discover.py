KNOWN_QUERY = b"ZwQueryInformationProcess\0"


def transform(data, key):
    result = bytearray()
    for index, value in enumerate(data):
        shift = index & 31
        rotated = ((key << shift) | (key >> ((32 - shift) & 31))) & 0xffffffff
        result.append(value ^ ((rotated + index) & 255))
    return bytes(result)


def recover_keys(data):

    results = {}
    for plain in (KNOWN_QUERY, b"NtQueryInformationProcess\0"):
        for offset in range(len(data) - len(plain) + 1):
            first = data[offset] ^ plain[0]
            second = ((data[offset + 1] ^ plain[1]) - 1) & 255
            if second & 254 != (first << 1) & 254:
                continue
            third = ((data[offset + 2] ^ plain[2]) - 2) & 255
            if third & 254 != (second << 1) & 254:
                continue
            stream = [first, second, third]
            for index in range(3, len(plain)):
                value = ((data[offset + index] ^ plain[index]) - index) & 255
                if value & 254 != (stream[-1] << 1) & 254:
                    break
                stream.append(value)
            if len(stream) != len(plain):
                continue
            key = first
            for index in range(1, 25):
                key |= (stream[index] & 1) << (32 - index)
            if transform(data[offset:offset + len(plain)], key) == plain:
                results.setdefault(key, []).append(offset)
    return results
