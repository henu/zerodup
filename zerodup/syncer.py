from . import constants
from . import crypto
from . import exceptions
from . import filelist
from . import storages
from . import utils

import os
import stat
import time


class Syncer:

    def __init__(self, storage_url):
        self.storage = storages.build_storage_engine(storage_url)
        self.existing_entries = set()

    def close(self):
        self.storage.close()

    def do_backup(self, source, master_key, excludes):

        latest_filelist = self._find_latest_filelist(master_key)

        source_abs = os.path.abspath(os.path.expanduser(source))
        new_filelist = filelist.FileList()
        self._scan_recursively(source_abs, '', new_filelist, latest_filelist, excludes)

        # Write filelist to storage
        self.storage.upload_new_filelist(new_filelist.to_stream(master_key))

    def do_restore(self, destination, master_key):

        # Get latest filelist. This is required for successful restore
        latest_filelist = self._find_latest_filelist(master_key)
        if not latest_filelist:
            raise exceptions.FatalError('No backup found!')

        # Make sure the destination exists and is empty
        destination_abs = os.path.abspath(os.path.expanduser(destination))
        if os.path.lexists(destination_abs):
            if not os.path.isdir(destination_abs):
                raise exceptions.FatalError('Destination must be a directory!')
            if os.listdir(destination_abs):
                raise exceptions.FatalError('Destination must be an empty directory!')
        else:
            os.makedirs(destination_abs)

        # Start restore
        for item in latest_filelist.get_items():
            utils.print_limited(item['path'])

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
                item_encrypted_stream = self.storage.download_entry(item['crypthash'])
                item_hash = bytes.fromhex(item['hash'])
                item_stream = crypto.aes_cbc_decrypt(item_encrypted_stream, item_hash, item_hash[:16])
                item_encrypted_stream.close()
                with open(item_path_abs, 'wb') as item_file:
                    while chunk := item_stream.read(constants.STREAM_CHUNK_SIZE):
                        item_file.write(chunk)
                item_stream.close()
                if 'perms' in item:
                    os.chmod(item_path_abs, item['perms'])

            # Create symlink
            elif item['type'] == 'link':
                os.symlink(item['target'], item_path_abs)

            else:
                raise exceptions.FatalError('Invalid type: ' + item['type'])

            # Set modification (and access) time. Unfortunately this does not work with symlinks
            if 'mtime' in item and item['type'] != 'link':
                os.utime(item_path_abs, (time.time(), item['mtime']))

    def _find_latest_filelist(self, master_key):
        latest_filelist = self.storage.download_latest_filelist()
        if latest_filelist:
            try:
                return filelist.FileList(latest_filelist, master_key)
            except exceptions.CorruptedData as err:
                raise exceptions.FatalError('Unable to open latest file list! Is it encrypted with a different key?') from err
        return None

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
                utils.print_limited(f'{child_rel}', ' -> ', f'{link_target}')
                new_filelist.add_link(child_rel, link_target)
                continue

            # Skip devices, pipes, sockets, etc.
            try:
                child_stat = os.lstat(child_abs)
            except FileNotFoundError:
                utils.print_limited(f'{child_rel}: NOT FOUND!')
                continue
            child_mode = child_stat.st_mode
            child_perms = stat.S_IMODE(child_mode)
            if stat.S_ISBLK(child_mode) or stat.S_ISCHR(child_mode) or stat.S_ISFIFO(child_mode) or stat.S_ISSOCK(child_mode):
                utils.print_limited(f'{child_rel}: SKIP')
                continue

            # Regular file
            if os.path.isfile(child_abs):
                # Check if file already exists in old list and has identical size and
                # modification time. In this case, consider it as the same file.
                if old_filelist:
                    data = old_filelist.get_item(child_rel)
                    if data and data['type'] == 'file' and data['size'] == child_stat.st_size and data['mtime'] == child_stat.st_mtime:
                        utils.print_limited(f'{child_rel}: No changes')
                        new_filelist.add_file(child_rel, child_stat.st_size, child_stat.st_mtime, child_perms, data['hash'], data['crypthash'])
                        continue

                # Data was not same, so create a new file.
                try:
                    with open(child_abs, 'rb') as child_file:
                        # Normal hash.
                        child_hash = crypto.sha256_hash(child_file)

                        # Encrypt data
                        child_file.seek(0)
                        child_file_encrypted = crypto.aes_cbc_encrypt(child_file, child_hash, child_hash[:16])
                except FileNotFoundError:
                    utils.print_limited(f'{child_rel}: NOT FOUND!')
                    continue

                # Get encrypted hash
                child_crypthash_hex = crypto.sha256_hash(child_file_encrypted).hex().lower()

                # Write encrypted file to storage, unless it already exists there
                if child_crypthash_hex in self.existing_entries:
                    utils.print_limited(f'{child_rel}: No upload needed')
                elif self.storage.entry_exists(child_crypthash_hex):
                    self.existing_entries.add(child_crypthash_hex)
                    utils.print_limited(f'{child_rel}: No upload needed')
                else:
                    self.storage.upload_entry(child_crypthash_hex, child_file_encrypted, f'{child_rel}: Uploading: ')

                # Close buffer
                child_file_encrypted.close()

                # Add file to filelist
                new_filelist.add_file(child_rel, child_stat.st_size, child_stat.st_mtime, child_perms, child_hash.hex().lower(), child_crypthash_hex)

                continue

            # Directory
            if os.path.isdir(child_abs):
                utils.print_limited(child_rel)
                new_filelist.add_dir(child_rel, child_stat.st_mtime, child_perms)
                self._scan_recursively(child_abs, child_rel, new_filelist, old_filelist, excludes)
                continue
