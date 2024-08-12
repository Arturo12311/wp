import os
import re
import json
import os
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

recieved = set()
sent = set()
unknown_ops = set()


with open("c:/al/logs/log_20240809_112154.log", 'r') as f:
    data = f.read()

streams = {}

chunks = re.split(r'\s*-{5,}\s*', data)
print(f"Number of chunks: {len(chunks)}")

for chunk in chunks:
    port_match = re.search(r'port\s*:\s*(\d+)', chunk)
    name_match = re.search(r'name\s*:\s*(\S+)', chunk)
    stream_match = re.search(r'stream\s*:\s*(\S+)', chunk)
    bytes_match = re.search(r'bytes\s*:\s*\[(.*?)\]', chunk, re.DOTALL)
    inject_match = re.search(r'injected\s*:\s*(\S+)', chunk)
    op_match = re.search(r'op\s*:\s*(\d+)', chunk)

    if bytes_match:
        bytes_content = bytes_match.group(1)
        bytes_list = [int(b.strip()) for b in bytes_content.split(',')]
        formatted_bytes = ' '.join(f"{b:3d}" for b in bytes_list)
    else:
        print("Bytes field not found")
        continue

    # print(port_match)
    # print(name_match)
    # print(stream_match)
    # print(formatted_bytes)
    # print(inject_match)

    if port_match and name_match and stream_match and op_match:
        port = port_match.group(1)
        name = name_match.group(1)
        stream = stream_match.group(1)
        inject = inject_match.group(1) if inject_match else "None"
        op = op_match.group(1)
        
        if port not in streams:
            streams[port] = {"recv": [], "send": []}

        injected_text = " : injected" if inject.upper() == "TRUE" else ""
        log_entry = f"[{formatted_bytes}] : {name}{injected_text}"

        if stream.lower() == "recv":
            streams[port]["recv"].append(log_entry)
            recieved.add(name)
        elif stream.lower() == "send":
            streams[port]["send"].append(log_entry)
            sent.add(name)

        if name == "unknown":
            unknown_ops.add(str(op))


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
full_path = os.path.join(CURRENT_DIR, "streams5.json")
with open(full_path, 'w') as f:
    json.dump(streams, f, indent=4)

print(f"Filtered data (excluding TozPing and TozPong) written to {full_path}")

print("Script execution completed.")

for i in recieved:
    print(i)
for i in sent:
    print(i)
print(len(unknown_ops))
for i in unknown_ops:
    print(i)