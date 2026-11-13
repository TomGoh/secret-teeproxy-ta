#!/usr/bin/env python3
"""从 wfuzz.json 提取 fuzz.entrypoints[].name 到输出文件（每行一个）。

用法:
    python3 extract_entrypoints_list.py [wfuzz.json] [entrypoints_list.txt]
"""

import json
import sys
from pathlib import Path


def extract_entrypoints_list(wfuzz_path='wfuzz.json',
                             list_output_path='entrypoints_list.txt'):
    """Write fuzz.entrypoints[].name values to entrypoints_list.txt."""
    with open(wfuzz_path, 'r', encoding='utf-8') as f:
        wfuzz_data = json.load(f)

    fuzz_node = wfuzz_data.get('fuzz', {}) or {}
    entrypoints_node = fuzz_node.get('entrypoints', []) or []

    names = []
    for entry in entrypoints_node:
        name = entry.get('name') if isinstance(entry, dict) else None
        if name:
            names.append(name)

    with open(list_output_path, 'w', encoding='utf-8') as f:
        for name in names:
            f.write(name + '\n')

    print(f"wrote entrypoint list: {list_output_path}")
    print(f"extracted {len(names)} entrypoint(s)")
    return names


def main():
    wfuzz_file = 'wfuzz.json'
    list_output_file = 'entrypoints_list.txt'

    if len(sys.argv) > 1:
        wfuzz_file = sys.argv[1]
    if len(sys.argv) > 2:
        list_output_file = sys.argv[2]

    if not Path(wfuzz_file).exists():
        print(f"error: input file not found: {wfuzz_file}", file=sys.stderr)
        sys.exit(1)

    extract_entrypoints_list(wfuzz_file, list_output_file)


if __name__ == '__main__':
    main()
