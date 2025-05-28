from . import bigbuffer
from . import constants
from . import crypto
from . import exceptions

import io
import json
import os


class FileList:

    def __init__(self, contents_stream=None, encryption_key=None):
        self.items = {}

        contents = None
        if contents_stream:
            if encryption_key:
                iv = contents_stream.read(16)
                try:
                    decrypted_stream = crypto.aes_ctr_decrypt(contents_stream, encryption_key, iv)
                    contents = decrypted_stream.read()
                    decrypted_stream.close()
                except exceptions.CorruptedData:
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
                raise exceptions.CorruptedData from err

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
        # Use bytearray, because concatenating bytes is extremely slow
        result_bytes = bytearray()
        for path, data in sorted(self.items.items()):
            data = data.copy()
            data['path'] = path
            result_bytes.extend(json.dumps(data).encode('ascii') + b'\n')
        result_bytes = bytes(result_bytes)

        # If encryption is requested
        if encryption_key:
            iv = os.urandom(16)
            encrypted = crypto.aes_ctr_encrypt(io.BytesIO(result_bytes), encryption_key, iv)
            result_stream = bigbuffer.BigBuffer()
            result_stream.write(iv)
            while chunk := encrypted.read(constants.STREAM_CHUNK_SIZE):
                result_stream.write(chunk)
            encrypted.close()
            return result_stream

        return io.BytesIO(result_bytes)
