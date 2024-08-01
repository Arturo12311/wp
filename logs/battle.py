import os 

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

full_path = os.path.join(CURRENT_DIR, 'battle.txt')
with open(full_path, 'r') as f:
    data = f.read()

import re
pattern = r'HEADER:\s*name\s*:\s*(\S+)'
matches = re.findall(pattern, data, re.DOTALL)
matches = set(matches)
for match in matches:
    print(match)

