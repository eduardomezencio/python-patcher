#!/usr/bin/env python3
"""IPS Patcher."""

from args_parser import parse_args
from ips_patch import IPSPatch


def apply(args):
    """Applies patch to a file."""
    with open(args.in_file, 'rb') as in_file:
        with open(args.out_file, 'wb') as out_file:
            patch = IPSPatch.from_file(args.patch_file)
            data = in_file.read()
            patched = patch.apply(data)
            out_file.write(patched)


def create(args):
    """Creates a patch from the difference between two files."""
    with open(args.original_file, 'rb') as original_file:
        with open(args.modified_file, 'rb') as modified_file:
            original_data = original_file.read()
            modified_data = modified_file.read()
            patch = IPSPatch.from_diff(original_data, modified_data)
            patch.to_file(args.out_file)


def main():
    """IPS Patcher main function."""
    args = parse_args()
    commands = {c.__name__: c for c in (apply, create)}
    commands[args.command](args)


if __name__ == '__main__':
    main()
