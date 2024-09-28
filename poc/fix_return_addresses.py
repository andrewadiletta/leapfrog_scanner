def get_return_addresses():
    try:
        out = []
        with open("return_addresses.out", "r") as f:
            prefixes = ["555", "7ff"]
            # make sure they start with one of the prefixes, then convert to int and return as a list
            for line in f:
                if any(line.strip().startswith(prefix) for prefix in prefixes):
                    out.append(int(line.strip(), 16))
        return out
    except ValueError as e:
        pass

def filter_duplicates(addresses):
    return list(dict.fromkeys(addresses))

import re
def read_trace_file():
    address_pattern = re.compile(r'^(0x[0-9a-fA-F]+):')
    addresses = set()
    try:
        with open("itrace.out", "r") as f:
            for line in f:
                match = address_pattern.match(line)
                if match:
                    address = int(match.group(1), 16)
                    addresses.add(address)
    except Exception as e:
        pass
    return addresses

def filter_addresses_in_trace(addresses, trace):
    return [addr for addr in addresses if addr in trace]


ALL_ADDRESSES = []
def get_filtered_return_addresses():

    addresses = get_return_addresses()
    addresses = filter_duplicates(addresses)
    
    trace = read_trace_file()
    ALL_ADDRESSES.extend(list(trace))
    print(len(ALL_ADDRESSES))
    addresses = filter_addresses_in_trace(addresses, trace)

    for address in addresses:
        for j in range(12):
            with open("itrace.in", "a") as f:
                f.write(f"{hex(address)} {hex(address ^ (1 << j))}\n")

    return addresses

get_filtered_return_addresses()