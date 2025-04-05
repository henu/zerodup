#!/usr/bin/env python3
import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import datetime
import getpass
import hashlib
import json
import os
import re
import stat
import sys
import time


UNIX_USERNAME_RE_RAW = '([a-zA-Z0-9][a-zA-Z0-9._-]{0,30}[a-zA-Z0-9])'
HOST_RE_RAW = '((?:[a-zA-Z0-9-]+\\.)+[a-zA-Z0-9-]+|^(?:\\d{1,3}\\.){3}\\d{1,3})'
TIMESTAMP_RE_RAW = '\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(?:Z|(?:[+-]\\d{2}:\\d{2}))?'

STORAGE_SFTP_URL_RE = re.compile(f'^[sS][fF][tT][pP]://((?P<username>{UNIX_USERNAME_RE_RAW})@)?(?P<host>{HOST_RE_RAW})(?P<path>/.*)$')
STORAGE_LOCAL_URL_RE = re.compile(f'^[fF][iI][lL][eE]://?(?P<path>/.*)$')

FILELIST_RE = re.compile(f'^(?P<identifier>.*)_(?P<timestamp>{TIMESTAMP_RE_RAW})$')


class CorruptedData(Exception):
    pass


class FatalError(Exception):
    def __init__(self, msg):
        super().__init__(msg)


def sha256_hash(b):
    hasher = hashlib.sha256()
    hasher.update(b)
    return hasher.digest()


def aes_cbc_encrypt(cleartext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padding = 16 - len(cleartext) % 16
    cleartext_padded = cleartext + bytes([padding] * padding)
    return encryptor.update(cleartext_padded) + encryptor.finalize()


def aes_cbc_decrypt(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        cleartext_padded = decryptor.update(ciphertext) + decryptor.finalize()
    except ValueError as err:
        raise CorruptedData() from err
    padding = cleartext_padded[-1]
    return cleartext_padded[:-padding]


class FileList:

    def __init__(self, contents=None, encryption_key=None):
        self.items = {}

        if contents and encryption_key:
            iv = contents[0:16]
            try:
                contents = aes_cbc_decrypt(contents[16:], encryption_key, iv)
            except CorruptedData:
                # Maybe older file lists did not have encryption. Ignore for now.
                pass

        if contents:
            try:
                for line in contents.split(b'\n'):
                    # Read single line JSON, or skip if the line is empty
                    if not line:
                        continue
                    data = json.loads(line)

                    # Ignore invalid items
                    if 'path' not in data:
                        continue
                    if data['type'] == 'link':
                        if 'target' not in data:
                            continue
                    elif data['type'] == 'file':
                        pass
                    elif data['type'] == 'dir':
                        pass
                    else:
                        continue

                    # Add item
                    path = data['path']
                    del data['path']
                    self.items[path] = data
            except UnicodeDecodeError as err:
                raise CorruptedData from err

    def get_item(self, path):
        return self.items.get(path)

    def get_items(self):
        items_arr = []
        for path, data in self.items.items():
            data = data.copy()
            data['path'] = path
            items_arr.append(data)
        return items_arr

    def add_dir(self, path, mtime, perms):
        self.items[path] = {
            'type': 'dir',
            'mtime': mtime,
            'perms': perms,
        }

    def add_file(self, path, size, mtime, perms, hash_, crypthash):
        self.items[path] = {
            'type': 'file',
            'size': size,
            'mtime': mtime,
            'perms': perms,
            'hash': hash_,
            'crypthash': crypthash,
        }

    def add_link(self, path, target):
        self.items[path] = {
            'type': 'link',
            'target': target,
        }

    def to_bytes(self, encryption_key):
        result = b''
        for path, data in sorted(self.items.items()):
            data = data.copy()
            data['path'] = path
            result += json.dumps(data).encode('ascii') + b'\n'

        if encryption_key:
            iv = os.urandom(16)
            result = iv + aes_cbc_encrypt(result, encryption_key, iv)

        return result


class Storage:

    def makedirs(self, path):
        if not path or path == '/':
            return
        if not self.exists(path):
            parent = os.path.dirname(path)
            self.makedirs(parent)
            self.mkdir(path)


class LocalStorage(Storage):

    def __init__(self, path):
        self.root, self.identifier = os.path.split(path)

    def get_identifier(self):
        return self.identifier

    def exists(self, path):
        return os.path.lexists(self._fix_path(path))

    def listdir(self, path):
        return os.listdir(self._fix_path(path))

    def mkdir(self, path):
        return os.mkdir(self._fix_path(path))

    def read(self, path):
        with open(self._fix_path(path), 'rb') as f:
            return f.read()

    def write(self, path, contents):
        with open(self._fix_path(path), 'wb') as f:
            f.write(contents)

    def _fix_path(self, path):
        while path and path.startswith('/'):
            path = path[1:]
        return os.path.join(self.root, path)


def build_storage_engine(url):

    # SFTP
    sftp_match = STORAGE_SFTP_URL_RE.match(url)
    if sftp_match:
        username = sftp_match.groupdict()['username']
        host = sftp_match.groupdict()['host']
        path = sftp_match.groupdict()['path']
        return SftpStorage(username, host, path)

    # Local
    local_match = STORAGE_LOCAL_URL_RE.match(url)
    if local_match:
        path = local_match.groupdict()['path']
        return LocalStorage(path)

    raise RuntimeError(f'URL {url} not supported!')


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

        # Store arguments
        self.action = args.action
        self.source = args.source
        self.destination = args.destination
        self.excludes = []
        if hasattr(args, 'excludes'):
            for raw_exclude in args.excludes or []:
                regex = re.escape(raw_exclude)
                regex = regex.replace('\\*', '.*')
                if raw_exclude.startswith('/'):
                    regex = f'^{regex}'
                self.excludes.append(re.compile(regex))

        # Read possible encryption key
        self.master_key = None
        if args.key_file:
            with open(os.path.expanduser(args.key_file), 'r') as f:
                master_key_raw = f.read().strip().encode('utf8')
            self.master_key = sha256_hash(master_key_raw)
        # If no key is given, and the encryption is still needed, ask key
        elif not args.no_encryption:
            master_key_raw = getpass.getpass('Please enter encryption key: ')
            master_key_raw_confirm = getpass.getpass('Confirm encryption key: ')
            if master_key_raw != master_key_raw_confirm:
                raise FatalError('Keys do not match!')
            master_key_raw = master_key_raw.strip().encode('utf8')
            self.master_key = sha256_hash(master_key_raw)


class Syncer:

    def __init__(self, storage_url):
        self.storage = build_storage_engine(storage_url)


    def do_backup(self, source, master_key, excludes):

        latest_filelist = self._find_latest_filelist(master_key)

        source_abs = os.path.abspath(os.path.expanduser(source))
        new_filelist = FileList()
        self._scan_recursively(source_abs, '', new_filelist, latest_filelist, excludes)

        # Write filelist to storage
        new_filelist_name = '{}_{}'.format(
            self.storage.get_identifier(),
            datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )
        self.storage.write(new_filelist_name, new_filelist.to_bytes(master_key))

    def do_restore(self, destination, master_key):

        # Get latest filelist. This is required for successful restore
        latest_filelist = self._find_latest_filelist(master_key)
        if not latest_filelist:
            raise FatalError('No backup found!')

        # Make sure the destination exists and is empty
        destination_abs = os.path.abspath(os.path.expanduser(destination))
        if os.path.lexists(destination_abs):
            if not os.path.isdir(destination_abs):
                raise FatalError('Destination must be a directory!')
            if os.listdir(destination_abs):
                raise FatalError('Destination must be an empty directory!')
        else:
            os.makedirs(destination_abs)

        # Start restore
        for item in latest_filelist.get_items():
            print(item['path'])

            # Get absolute path, and make sure parent directory exists
            item_path_abs = os.path.join(destination_abs, item['path'])
            parent = os.path.dirname(item_path_abs)
            if not os.path.lexists(parent):
                os.makedirs(parent)

            # Create directory
            if item['type'] == 'dir':
                if not os.path.lexists(item_path_abs):
                    if 'perms' in item:
                        os.makedirs(item_path_abs, mode=item['perms'])
                    else:
                        os.makedirs(item_path_abs)
                elif 'perms' in item:
                    os.chmod(item_path_abs, item['perms'])

            # Create file
            elif item['type'] == 'file':
                # Decrypt file
                item_encrypted_path = self._get_storage_path(item['crypthash'])
                item_encrypted_bytes = self.storage.read(item_encrypted_path)
                item_hash = bytes.fromhex(item['hash'])
                item_bytes = aes_cbc_decrypt(item_encrypted_bytes, item_hash, item_hash[:16])
                with open(item_path_abs, 'wb') as f:
                    f.write(item_bytes)
                if 'perms' in item:
                    os.chmod(item_path_abs, item['perms'])

            # Create symlink
            elif item['type'] == 'link':
                os.symlink(item['target'], item_path_abs)

            else:
                raise FatalError('Invalid type: ' + item['type'])

            # Set modification (and access) time. Unfortunately this does not work with symlinks
            if 'mtime' in item and item['type'] != 'link':
                os.utime(item_path_abs, (time.time(), item['mtime']))

    def _get_storage_path(self, crypthash_hex):
        return 'storage/{}/{}/{}/{}/{}'.format(
            crypthash_hex[0:2],
            crypthash_hex[2:4],
            crypthash_hex[4:6],
            crypthash_hex[6:8],
            crypthash_hex,
        )

    def _find_latest_filelist(self, master_key):
        # Find the most recent filelist and download it. Go files in
        # reversed order, hoping to find the most recent filelist first.
        latest_filelist = None
        latest_filelist_timestamp = None
        for file in sorted(self.storage.listdir('/'), reverse=True):
            # Check if this is a filelist
            filelist_match = FILELIST_RE.match(file)
            if filelist_match:
                if filelist_match.groupdict()['identifier'] == self.storage.get_identifier():
                    timestamp = datetime.datetime.fromisoformat(filelist_match.groupdict()['timestamp'])
                    if latest_filelist_timestamp is None or latest_filelist_timestamp < timestamp:
                        try:
                            latest_filelist = FileList(self.storage.read(file), master_key)
                            latest_filelist_timestamp = timestamp
                        except CorruptedData as err:
                            raise FatalError(f'Unable to open file list "{file}"! Is it encrypted with a different key?') from err
        return latest_filelist

    def _scan_recursively(self, path_abs, path_rel, new_filelist, old_filelist, excludes):

        for child in sorted(os.listdir(path_abs)):
            child_abs = os.path.join(path_abs, child)
            child_rel = os.path.join(path_rel, child)

            # Check if this path should be excluded
            exclude = False
            for exclude_re in excludes:
                if exclude_re.search(child_abs):
                    exclude = True
                    break
            if exclude:
                continue

            # Symlink
            if os.path.islink(child_abs):
                link_target = os.readlink(child_abs)
                print(f'{child_rel} -> {link_target}')
                new_filelist.add_link(child_rel, link_target)
                continue

            # Skip devices, pipes, sockets, etc.
            child_stat = os.lstat(child_abs)
            child_mode = child_stat.st_mode
            child_perms = stat.S_IMODE(child_mode)
            if stat.S_ISBLK(child_mode) or stat.S_ISCHR(child_mode) or stat.S_ISFIFO(child_mode) or stat.S_ISSOCK(child_mode):
                print(f'{child_rel}: SKIP')
                continue

            # Regular file
            if os.path.isfile(child_abs):
                # Check if file already exists in old list and has identical size and
                # modification time. In this case, consider it as the same file.
                if old_filelist:
                    data = old_filelist.get_item(child_rel)
                    if data and data['type'] == 'file' and data['size'] == child_stat.st_size and data['mtime'] == child_stat.st_mtime:
                        print(f'{child_rel}: No changes')
                        new_filelist.add_file(child_rel, child_stat.st_size, child_stat.st_mtime, child_perms, data['hash'], data['crypthash'])
                        continue

                # Data was not same, so create a new file. First find out its hashes.
                # TODO: If the file is huge, do this on disk rather than in memory!
                with open(child_abs, 'rb') as f:
                    child_bytes = f.read()

                # Normal hash
                child_hash = sha256_hash(child_bytes)

                # Encrypt data
                child_bytes_encrypted = aes_cbc_encrypt(child_bytes, child_hash, child_hash[:16])

                # Get encrypted hash
                child_crypthash_hex = sha256_hash(child_bytes_encrypted).hex().lower()

                # Write encrypted file to storage, unless it already exists there
                child_storagepath = self._get_storage_path(child_crypthash_hex)
                if self.storage.exists(child_storagepath):
                    print(f'{child_rel}: No upload needed')
                else:
                    print(f'{child_rel}: Uploading...')
                    self.storage.makedirs(os.path.dirname(child_storagepath))
                    self.storage.write(child_storagepath, child_bytes_encrypted)

                # Add file to filelist
                new_filelist.add_file(child_rel, child_stat.st_size, child_stat.st_mtime, child_perms, child_hash.hex().lower(), child_crypthash_hex)

                continue

            # Directory
            if os.path.isdir(child_abs):
                print(child_rel)
                new_filelist.add_dir(child_rel, child_stat.st_mtime, child_perms)
                self._scan_recursively(child_abs, child_rel, new_filelist, old_filelist, excludes)
                continue

if __name__ == '__main__':

    try:

        args = Arguments()

        if args.action == 'backup':
            syncer = Syncer(args.destination)
            syncer.do_backup(args.source, args.master_key, args.excludes)

        elif args.action == 'restore':
            syncer = Syncer(args.source)
            syncer.do_restore(args.destination, args.master_key)

    except FatalError as err:
        print(f'ERROR: {err}')
        sys.exit(1)
