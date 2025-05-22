import os
import tempfile


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

        self.closed = False

    def cloned_new_instance(self):
        clone = BigBuffer()
        clone.buf = self.buf
        clone.file = self.file
        clone.file_size = self.file_size
        clone.read_pos = 0
        clone.closed = False
        return clone

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

    def seekable(self):
        return True

    def seek(self, offset, whence=os.SEEK_SET):
        if whence == os.SEEK_SET:
            if self.file:
                self.read_pos = max(0, min(self.file_size, offset))
            else:
                self.read_pos = max(0, min(len(self.buf), offset))
        elif whence == os.SEEK_END:
            if self.file:
                self.read_pos = max(0, min(self.file_size, self.file_size + offset))
            else:
                self.read_pos = max(0, min(len(self.buf), len(self.buf) + offset))
        else:
            raise RuntimeError(f'Unsupported "whence" value: {whence}')

        return self.read_pos

    def tell(self):
        return self.read_pos

    def close(self):
        self.closed = True

    def truncate(self, size):
        if self.file:
            size = min(size, self.file_size)
            self.file.truncate(size)
            self.file_size = size
        elif self.buf is not None:
            size = min(size, len(self.buf))
            self.buf = self.buf[:size]

    def flush(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
