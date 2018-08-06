"""Parser for command line arguments."""

import argparse
import sys


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Program for creating and applying IPS patches.')
    subparsers = parser.add_subparsers(title='subcommands')

    apply = subparsers.add_parser('apply', aliases=['a'])
    apply.add_argument('patch_file', type=str,
                       help='file containing the IPS patch')
    apply.add_argument('in_file', type=str,
                       help='file to be patched')
    apply.add_argument('out_file', type=str,
                       help='file to receive the patched output')
    apply.set_defaults(command='apply')

    create = subparsers.add_parser('create', aliases=['c'])
    create.add_argument('original_file', type=str,
                        help='file on which the patch would be applied')
    create.add_argument('modified_file', type=str,
                        help='file that would result from applying the patch '
                             'to original_file')
    create.add_argument('out_file', type=str,
                        help='file to write the patch to')
    create.set_defaults(command='create')

    if len(sys.argv) == 1:
        return parser.parse_args(['-h'])

    return parser.parse_args()
