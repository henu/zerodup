#!/usr/bin/env python3
import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import datetime
import getpass
import hashlib
import io
import json
import os
import re
import stat
import sys
import tempfile
import time


UNIX_USERNAME_RE_RAW = '([a-zA-Z0-9][a-zA-Z0-9._-]{0,30}[a-zA-Z0-9])'
HOST_RE_RAW = '((?:[a-zA-Z0-9-]+\\.)+[a-zA-Z0-9-]+|^(?:\\d{1,3}\\.){3}\\d{1,3})'
TIMESTAMP_RE_RAW = '\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(?:Z|(?:[+-]\\d{2}:\\d{2}))?'

STORAGE_SFTP_URL_RE = re.compile(f'^[sS][fF][tT][pP]://((?P<username>{UNIX_USERNAME_RE_RAW})@)?(?P<host>{HOST_RE_RAW})(?P<path>/.*)$')
STORAGE_LOCAL_URL_RE = re.compile(f'^[fF][iI][lL][eE]://?(?P<path>/.*)$')

FILELIST_RE = re.compile(f'^(?P<identifier>.*)_(?P<timestamp>{TIMESTAMP_RE_RAW})$')


STREAM_CHUNK_SIZE = 10 * 1024 * 1024


class BigBuffer:

    DEFAULT_MEMORY_LIMIT = 10 * 1024 * 1024

    @classmethod
    def set_memory_limit(cls, limit):
        cls.custom_memory_limit = limit

    def __init__(self):
        # In memory buffer
        self.buf = b''
        # On disk buffer
        self.file = None
        self.file_size = None
        # Used on both memory and disk
        self.read_pos = 0

    def write(self, data):
        # If not converted to file, and there is still space left
        memory_limit = getattr(BigBuffer, 'custom_memory_limit', BigBuffer.DEFAULT_MEMORY_LIMIT)
        if not self.file and len(self.buf) + len(data) < memory_limit:
            self.buf += data
            return

        # If file is not created, then create it now
        if not self.file:
            # Initialize a new file
            self.file = tempfile.NamedTemporaryFile('w+b')
            # Empty buffer to it
            self.file.write(self.buf)
            self.file_size = len(self.buf)
            self.buf = None

        # Add new data to the end of file
        self.file.seek(0, os.SEEK_END)
        self.file.write(data)
        self.file_size += len(data)

    def read(self, size=-1):
        # If data is stored on file
        if self.file:
            self.file.seek(self.read_pos)
            read_amount = self.file_size - self.read_pos
            if size >= 0:
                read_amount = min(read_amount, size)
            self.read_pos += read_amount
            return self.file.read(read_amount)

        # If data is stored in memory, and everything is requested
        if size < 0 or size >= len(self.buf):
            result = self.buf[self.read_pos:]
            self.read_pos = len(self.buf)
            return result

        # If data is stored in memory, and only part is requested
        result = self.buf[self.read_pos:self.read_pos + size]
        self.read_pos += size
        return result

    def seek(self, offset, whence=0):
        if whence == 0:
            if self.file:
                self.read_pos = max(0, min(self.file_size, offset))
            else:
                self.read_pos = max(0, min(len(self.buf), offset))
        elif whence == 2:
            if self.file:
                self.read_pos = max(0, min(self.file_size, self.file_size + offset))
            else:
                self.read_pos = max(0, min(len(self.buf), len(self.buf) + offset))
        else:
            raise RuntimeError(f'Unsupported "whence" value: {whence}')

    def tell(self):
        return self.read_pos

    def close(self):
        if self.file:
            self.file.close()
        self.file = None
        self.file_size = None
        self.buf = None
        self.read_pos = None

    def truncate(self, size):
        if self.file:
            size = min(size, self.file_size)
            self.file.truncate(size)
            self.file_size = size
        elif self.buf is not None:
            size = min(size, len(self.buf))
            self.buf = self.buf[:size]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class CorruptedData(Exception):
    pass


class FatalError(Exception):
    def __init__(self, msg):
        super().__init__(msg)


def sha256_hash(stream):
    hasher = hashlib.sha256()
    while chunk := stream.read(STREAM_CHUNK_SIZE):
        hasher.update(chunk)
    return hasher.digest()


def aes_cbc_encrypt(cleartext_stream, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    cleartext_stream.seek(0, 2)
    padding = 16 - cleartext_stream.tell() % 16
    cleartext_stream.seek(0)
    ciphertext_stream = BigBuffer()
    while chunk := cleartext_stream.read(STREAM_CHUNK_SIZE):
        ciphertext_stream.write(encryptor.update(chunk))
    ciphertext_stream.write(encryptor.update(bytes([padding] * padding)))
    ciphertext_stream.write(encryptor.finalize())
    return ciphertext_stream


def aes_cbc_decrypt(ciphertext_stream, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    cleartext_stream = BigBuffer()
    try:
        while chunk := ciphertext_stream.read(STREAM_CHUNK_SIZE):
            cleartext_stream.write(decryptor.update(chunk))
        cleartext_stream.write(decryptor.finalize())
    except ValueError as err:
        cleartext_stream.close()
        raise CorruptedData() from err
    # Remove padding
    cleartext_stream.seek(-1, 2)
    content_size = cleartext_stream.tell() + 1
    padding = cleartext_stream.read(1)[0]
    cleartext_stream.seek(0)
    cleartext_stream.truncate(content_size - padding)
    return cleartext_stream


class FileList:

    def __init__(self, contents_stream=None, encryption_key=None):
        self.items = {}

        contents = None
        if contents_stream:
            if encryption_key:
                iv = contents_stream.read(16)
                try:
                    decrypted_stream = aes_cbc_decrypt(contents_stream, encryption_key, iv)
                    contents = decrypted_stream.read()
                    decrypted_stream.close()
                except CorruptedData:
                    # Maybe older file lists did not have encryption. Ignore for now.
                    pass
            else:
                contents = contents_stream.read()
            contents_stream.close()

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

    def to_stream(self, encryption_key):
        result_bytes = b''
        for path, data in sorted(self.items.items()):
            data = data.copy()
            data['path'] = path
            result_bytes += json.dumps(data).encode('ascii') + b'\n'

        if encryption_key:
            iv = os.urandom(16)
            encrypted = aes_cbc_encrypt(io.BytesIO(result_bytes), encryption_key, iv)
            result_stream = BigBuffer()
            result_stream.write(iv)
            while chunk := encrypted.read(STREAM_CHUNK_SIZE):
                result_stream.write(chunk)
            encrypted.close()
            return result_stream

        return io.BytesIO(result_bytes)


class Storage:

    def makedirs(self, path):
        if not path or path == '/':
            return
        if not self.exists(path):
            parent = os.path.dirname(path)
            self.makedirs(parent)
            self.mkdir(path)

    def close(self):
        pass


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
        result = BigBuffer()
        with open(self._fix_path(path), 'rb') as file:
            while chunk := file.read(STREAM_CHUNK_SIZE):
                result.write(chunk)
        return result

    def write(self, path, stream):
        with open(self._fix_path(path), 'wb') as file:
            while chunk := stream.read(STREAM_CHUNK_SIZE):
                file.write(chunk)

    def _fix_path(self, path):
        while path and path.startswith('/'):
            path = path[1:]
        return os.path.join(self.root, path)


class SftpStorage(Storage):

    def __init__(self, username, host, path):
        import paramiko

        self.root, self.identifier = os.path.split(path)

        # Open SFTP connection
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.load_system_host_keys()
        try:
            self.ssh_client.connect(host, username=username)
        except paramiko.ssh_exception.AuthenticationException:
            # Try again with password
            password = getpass.getpass(f'Please enter password for {username}@{host}: ')
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.load_system_host_keys()
            try:
                self.ssh_client.connect(host, username=username, password=password)
            except paramiko.ssh_exception.AuthenticationException:
                raise FatalError(f'Access denied for {username}@{host}!')
        self.sftp_client = self.ssh_client.open_sftp()

    def get_identifier(self):
        return self.identifier

    def exists(self, path):
        try:
            self.sftp_client.stat(self._fix_path(path))
            return True
        except FileNotFoundError:
            return False

    def listdir(self, path):
        return self.sftp_client.listdir(self._fix_path(path))

    def mkdir(self, path):
        self.sftp_client.mkdir(self._fix_path(path))

    def read(self, path):
        result = BigBuffer()
        with self.sftp_client.open(self._fix_path(path), 'rb') as file:
            while chunk := file.read(STREAM_CHUNK_SIZE):
                result.write(chunk)
        return result

    def write(self, path, stream):
        with self.sftp_client.open(self._fix_path(path), 'wb') as file:
            while chunk := stream.read(STREAM_CHUNK_SIZE):
                file.write(chunk)

    def close(self):
        self.sftp_client.close()
        self.ssh_client.close()

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

        # Validate action
        if args.action not in ['backup', 'restore']:
            raise FatalError('No action given!')
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
            self.master_key = sha256_hash(io.BytesIO(master_key_raw))
        # If no key is given, and the encryption is still needed, ask key
        elif not args.no_encryption:
            master_key_raw = getpass.getpass('Please enter encryption key: ')
            master_key_raw_confirm = getpass.getpass('Confirm encryption key: ')
            if master_key_raw != master_key_raw_confirm:
                raise FatalError('Keys do not match!')
            master_key_raw = master_key_raw.strip().encode('utf8')
            self.master_key = sha256_hash(io.BytesIO(master_key_raw))


class Syncer:

    def __init__(self, storage_url):
        self.storage = build_storage_engine(storage_url)

    def close(self):
        self.storage.close()

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
        new_filelist_stream = new_filelist.to_stream(master_key)
        self.storage.write(new_filelist_name, new_filelist_stream)
        new_filelist_stream.close()

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
                item_encrypted_stream = self.storage.read(item_encrypted_path)
                item_hash = bytes.fromhex(item['hash'])
                item_stream = aes_cbc_decrypt(item_encrypted_stream, item_hash, item_hash[:16])
                item_encrypted_stream.close()
                with open(item_path_abs, 'wb') as item_file:
                    while chunk := item_stream.read(STREAM_CHUNK_SIZE):
                        item_file.write(chunk)
                item_stream.close()
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
            crypthash_hex[0],
            crypthash_hex[1],
            crypthash_hex[2],
            crypthash_hex[3],
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

                # Data was not same, so create a new file.
                with open(child_abs, 'rb') as child_file:
                    # Normal hash.
                    child_hash = sha256_hash(child_file)

                    # Encrypt data
                    child_file.seek(0)
                    child_file_encrypted = aes_cbc_encrypt(child_file, child_hash, child_hash[:16])

                # Get encrypted hash
                child_crypthash_hex = sha256_hash(child_file_encrypted).hex().lower()

                # Write encrypted file to storage, unless it already exists there
                child_storagepath = self._get_storage_path(child_crypthash_hex)
                if self.storage.exists(child_storagepath):
                    print(f'{child_rel}: No upload needed')
                else:
                    print(f'{child_rel}: Uploading...')
                    self.storage.makedirs(os.path.dirname(child_storagepath))
                    child_file_encrypted.seek(0)
                    self.storage.write(child_storagepath, child_file_encrypted)

                # Close buffer
                child_file_encrypted.close()

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

        # If free memory info is available, then use 10 % of that for buffers
        try:
            import psutil
            memory_available = psutil.virtual_memory().available
            memory_limit = max(10 * 1024 * 1024, psutil.virtual_memory().available // 10)
            BigBuffer.set_memory_limit(memory_limit)
        except:
            pass

        args = Arguments()

        if args.action == 'backup':
            syncer = Syncer(args.destination)
            syncer.do_backup(args.source, args.master_key, args.excludes)
            syncer.close()

        elif args.action == 'restore':
            syncer = Syncer(args.source)
            syncer.do_restore(args.destination, args.master_key)
            syncer.close()

    except FatalError as err:
        print(f'ERROR: {err}')
        sys.exit(1)
