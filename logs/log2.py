import os
import re
import json

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

full_path = os.path.join(CURRENT_DIR, 'log.txt')
with open(full_path, 'r') as f:
    data = f.read()

streams = {}

chunks = re.split(r'\s*-{5,}\s*', data)
print(f"Number of chunks: {len(chunks)}")

for chunk in chunks:
    name_match = re.search(r'name\s*:\s*(\S+)', chunk)
    type_match = re.search(r'type\s*:\s*(\S+)', chunk)
    length_match = re.search(r'length\s*:\s*(\d+)', chunk)
    hash_match = re.search(r'hash\s*:\s*\[(\d+),\s*(\d+),\s*(\d+),\s*(\d+)\]', chunk)
    count_match = re.search(r'count\s*:\s*(\d+)', chunk)
    port_match = re.search(r'port:\s*(\d+)', chunk)
    bytes_match = re.search(r'bytes\s*:\s*\[(.*?)\]', chunk, re.DOTALL)
    inject_match = re.search(r'inject\s*:\s*(\S+)', chunk)

    if bytes_match:
        bytes_content = bytes_match.group(1)
        bytes_list = [int(b.strip()) for b in bytes_content.split(',')]
        formatted_bytes = ' '.join(f"{b:3d}" for b in bytes_list)
    else:
        print("Bytes field not found")
        continue

    if name_match and type_match and count_match and port_match and bytes_match and inject_match:
        port = port_match.group(1)
        name = name_match.group(1)
        type_ = type_match.group(1)
        count = count_match.group(1)
        inject = inject_match.group(1)
        
        if port not in streams:
            streams[port] = {"recv": [], "send": []}

        injected_text = " : injected" if inject.upper() == "TRUE" else ""
        log_entry = f"[{formatted_bytes}] : {name}{injected_text}"

        if type_.lower() == "recv":
            streams[port]["recv"].append(log_entry)
        elif type_.lower() == "send":
            streams[port]["send"].append(log_entry)

    elif port_match:
        print(f"Switched to port: {port_match.group(1)}")

def filter_entry(entry):
    return not any(ping_pong in entry for ping_pong in ["TozPing", "TozPong"])

# Add enumeration to the stored data and filter out TozPing and TozPong
for port, data in streams.items():
    for direction in ["recv", "send"]:
        filtered_entries = [entry for entry in data[direction] if filter_entry(entry)]
        streams[port][direction] = [f"{i:4d} {entry}" for i, entry in enumerate(filtered_entries, 1)]

print("Final Streams Dictionary (excluding TozPing and TozPong):")
for port, data in streams.items():
    print(f"Port {port}:")
    print("  Recv:")
    for entry in data['recv']:
        print(f"    {entry}")
    print("  Send:")
    for entry in data['send']:
        print(f"    {entry}")
    print()

# Write the full data (including TozPing and TozPong) to the JSON file
full_path = os.path.join(CURRENT_DIR, "streams2.json")
with open(full_path, 'w') as f:
    json.dump(streams, f, indent=4)

print(f"Filtered data (excluding TozPing and TozPong) written to {full_path}")

print("Script execution completed.")