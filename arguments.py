import crypto
import exceptions

import argparse
import getpass
import io
import os
import re


class Arguments:

    def __init__(self):

        # Define arguments
        parser = argparse.ArgumentParser(
            prog='HSync',
            description='Backup app, focused on deduplicating data.',
        )

        # TODO: Add argument for verbosity!

        # Encryption arguments
        encrypt_group = parser.add_mutually_exclusive_group(required=False)
        encrypt_group.add_argument('--no-encryption', action='store_true', help='Do not encrypt file list.')
        encrypt_group.add_argument('-kf', '--key-file', metavar='key-file', help='File that contains encryption key.')

        action_subparsers = parser.add_subparsers(dest='action', help='Actions')

        # Backup subcommand
        action_backup_parser = action_subparsers.add_parser('backup', help='Perform backup')
        # Source and destinations
        action_backup_parser.add_argument('source', help='Source directory to backup')
        action_backup_parser.add_argument('destination', help='Destination URL for backup')
        action_backup_parser.add_argument(
            '-e', '--exclude',
            action='append',
            type=str,
            help='Excludes a path. Can be absolute or part of path. Can contain * for wildcards.',
            dest='excludes',
        )

        # Restore subcommand
        action_restore_parser = action_subparsers.add_parser('restore', help='Restore from backup')
        action_restore_parser.add_argument('source', help='Source backup URL')
        action_restore_parser.add_argument('destination', help='Destination directory for restore')

        # Parse
        args = parser.parse_args()

        # Validate action
        if args.action not in ['backup', 'restore']:
            raise exceptions.FatalError('No action given!')
        self.action = args.action

        # Store arguments
        self.source = getattr(args, 'source', None)
        self.destination = getattr(args, 'destination', None)
        self.excludes = []
        for raw_exclude in getattr(args, 'excludes', None) or []:
            regex = re.escape(raw_exclude)
            regex = regex.replace('\\*', '.*')
            if raw_exclude.startswith('/'):
                regex = f'^{regex}'
            self.excludes.append(re.compile(regex))

        # Read possible encryption key
        self.master_key = None
        if args.key_file:
            with open(os.path.expanduser(args.key_file), 'r') as file:
                master_key_raw = file.read().strip().encode('utf8')
            self.master_key = crypto.sha256_hash(io.BytesIO(master_key_raw))
        # If no key is given, and the encryption is still needed, ask key
        elif not args.no_encryption:
            master_key_raw = getpass.getpass('Please enter encryption key: ')
            master_key_raw_confirm = getpass.getpass('Confirm encryption key: ')
            if master_key_raw != master_key_raw_confirm:
                raise exceptions.FatalError('Keys do not match!')
            master_key_raw = master_key_raw.strip().encode('utf8')
            self.master_key = crypto.sha256_hash(io.BytesIO(master_key_raw))
