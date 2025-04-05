#!/usr/bin/env python3
import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import datetime
import hashlib
import json
import os
import re
import stat


UNIX_USERNAME_RE_RAW = '([a-zA-Z0-9][a-zA-Z0-9._-]{0,30}[a-zA-Z0-9])'
HOST_RE_RAW = '((?:[a-zA-Z0-9-]+\\.)+[a-zA-Z0-9-]+|^(?:\\d{1,3}\\.){3}\\d{1,3})'
TIMESTAMP_RE_RAW = '\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(?:Z|(?:[+-]\\d{2}:\\d{2}))?'

STORAGE_SFTP_URL_RE = re.compile(f'^[sS][fF][tT][pP]://((?P<username>{UNIX_USERNAME_RE_RAW})@)?(?P<host>{HOST_RE_RAW})(?P<path>/.*)$')
STORAGE_LOCAL_URL_RE = re.compile(f'^[fF][iI][lL][eE]://?(?P<path>/.*)$')

FILELIST_RE = re.compile(f'^(?P<identifier>.*)_(?P<timestamp>{TIMESTAMP_RE_RAW})$')


class FileList:

    def __init__(self, contents=None):
        self.items = {}

        if contents:
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

    def get_item(self, path):
        return self.items.get(path)

    def add_dir(self, path):
        self.items[path] = {
            'type': 'dir',
        }

    def add_file(self, path, size, mtime, hash_, crypthash):
        self.items[path] = {
            'type': 'file',
            'size': size,
            'mtime': mtime,
            'hash': hash_,
            'crypthash': crypthash,
        }

    def add_link(self, path, target):
        self.items[path] = {
            'type': 'link',
            'target': target,
        }

    def to_bytes(self):
        result = b''
        for path, data in sorted(self.items.items()):
            data = data.copy()
            data['path'] = path
            result += json.dumps(data).encode('ascii') + b'\n'
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
        # Source and destinations
        parser.add_argument('source')
        parser.add_argument('destination')
        # Exclude option
        parser.add_argument(
            '-e', '--exclude',
            action='append',
            type=str,
            help='Excludes a path. Can be absolute or part of path. Can contain * for wildcards.',
            dest='excludes',
        )

        # Parse
        args = parser.parse_args()

        # Store arguments
        self.source = args.source
        self.destination = args.destination
        self.excludes = []
        for raw_exclude in args.excludes or []:
            regex = re.escape(raw_exclude)
            regex = regex.replace('\\*', '.*')
            if raw_exclude.startswith('/'):
                regex = f'^{regex}'
                self.excludes.append(re.compile(regex))


class Syncer:

    def __init__(self, args):
        self.args = args

        self.storage = build_storage_engine(self.args.destination)

    def run(self):
        # TODO: Encrypt filelist!

        # Find the most recent filelist and download it.
        root_files = self.storage.listdir('/')
        latest_filelist = None
        latest_filelist_timestamp = None
        for file in root_files:
            # Check if this is a filelist
            filelist_match = FILELIST_RE.match(file)
            if filelist_match:
                if filelist_match.groupdict()['identifier'] == self.storage.get_identifier():
                    timestamp = datetime.datetime.fromisoformat(filelist_match.groupdict()['timestamp'])
                    if latest_filelist_timestamp is None or latest_filelist_timestamp < timestamp:
                        latest_filelist_timestamp = timestamp
                        latest_filelist = file
        if latest_filelist:
            latest_filelist = FileList(self.storage.read(latest_filelist))

        source_abs = os.path.abspath(os.path.expanduser(self.args.source))
        new_filelist = FileList()
        self._scan_recursively(source_abs, '', new_filelist, latest_filelist)

        # Write filelist to storage
        new_filelist_name = '{}_{}'.format(
            self.storage.get_identifier(),
            datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )
        self.storage.write(new_filelist_name, new_filelist.to_bytes())

    def _scan_recursively(self, path_abs, path_rel, new_filelist, old_filelist):
        # TODO: Obey excludes!

        for child in sorted(os.listdir(path_abs)):
            child_abs = os.path.join(path_abs, child)
            child_rel = os.path.join(path_rel, child)

            # Symlink
            if os.path.islink(child_abs):
                link_target = os.readlink(child_abs)
                print(f'{child_rel} -> {link_target}')
                new_filelist.add_link(child_rel, link_target)
                continue

            # Skip devices, pipes, sockets, etc.
            child_stat = os.stat(child_abs)
            child_mode = child_stat.st_mode
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
                        new_filelist.add_file(child_rel, child_stat.st_size, child_stat.st_mtime, data['hash'], data['crypthash'])
                        continue

                # Data was not same, so create a new file. First find out its hashes.
                # TODO: If the file is huge, do this on disk rather than in memory!
                with open(child_abs, 'rb') as f:
                    child_bytes = f.read()

                # Normal hash
                hash_hasher = hashlib.sha256()
                hash_hasher.update(child_bytes)
                child_hash = hash_hasher.digest()

                # Encrypt data
                iv = child_hash[:16]
                cipher = Cipher(algorithms.AES(child_hash), modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                padding = 16 - len(child_bytes) % 16
                child_bytes_padded = child_bytes + bytes([padding] * padding)
                child_bytes_encrypted = encryptor.update(child_bytes_padded) + encryptor.finalize()

                # Get encrypted hash
                crypthash_hasher = hashlib.sha256()
                crypthash_hasher.update(child_bytes_encrypted)
                child_crypthash_hex = crypthash_hasher.hexdigest().lower()

                # Write encrypted file to storage, unless it already exists there
                child_storagepath = 'storage/{}/{}/{}/{}/{}'.format(
                    child_crypthash_hex[0:2],
                    child_crypthash_hex[2:4],
                    child_crypthash_hex[4:6],
                    child_crypthash_hex[6:8],
                    child_crypthash_hex,
                )
                if self.storage.exists(child_storagepath):
                    print(f'{child_rel}: No upload needed')
                else:
                    print(f'{child_rel}: Uploading...')
                    self.storage.makedirs(os.path.dirname(child_storagepath))
                    self.storage.write(child_storagepath, child_bytes_encrypted)

                # Add file to filelist
                new_filelist.add_file(child_rel, child_stat.st_size, child_stat.st_mtime, child_hash.hex().lower(), child_crypthash_hex)

                continue

            # Directory
            if os.path.isdir(child_abs):
                print(child_rel)
                new_filelist.add_dir(child_rel)
                self._scan_recursively(child_abs, child_rel, new_filelist, old_filelist)
                continue

if __name__ == '__main__':

    args = Arguments()

    syncer = Syncer(args)

    syncer.run()
