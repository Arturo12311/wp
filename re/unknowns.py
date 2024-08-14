import os
import re
import json
import os
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

with open("c:/al/logs/unknown-name-packets.txt", 'r') as f:
    data = f.read()

chunks = re.split(r'\s*-{5,}\s*', data)
print(f"Number of chunks: {len(chunks)}")

unknown_ops = set()
for chunk in chunks:
    name_match = re.search(r'name\s*:\s*(\S+)', chunk)
    op_match = re.search(r'op\s*:\s*(\d+)', chunk)

    if  name_match  and op_match:
        name = name_match.group(1)
        op = op_match.group(1)
        
        if op not in unknown_ops and name == "unknown":
            unknown_ops.add(op)

main_dict = {i: op for i, op in enumerate(unknown_ops)}

full_path = os.path.join(CURRENT_DIR, "unknown_ops.json")
with open(full_path, 'w') as f:
    json.dump(main_dict, f, indent=4)

print(f"unknown ops written to {full_path}")

print("Script execution completed.")
