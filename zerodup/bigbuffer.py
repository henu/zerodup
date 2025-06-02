import os
import tempfile


class BigBuffer:

    DEFAULT_MEMORY_LIMIT = 10 * 1024 * 1024

    @classmethod
    def set_memory_limit(cls, limit):
        cls.custom_memory_limit = limit

    def __init__(self):
        # In memory buffer
        # TODO: Use bytearray instead!
        self.buf = b''
        # On disk buffer
        self.file = None
        self.file_size = None
        # Used on both memory and disk
        self.pos = 0

        self.closed = False

    def cloned_new_instance(self):
        clone = BigBuffer()
        clone.buf = self.buf
        clone.file = self.file
        clone.file_size = self.file_size
        clone.pos = 0
        clone.closed = False
        return clone

    def write(self, data):
        # If not converted to file, and there is still space left
        memory_limit = getattr(BigBuffer, 'custom_memory_limit', BigBuffer.DEFAULT_MEMORY_LIMIT)
        if not self.file and self.pos + len(data) < memory_limit:
            # If writing after the end of the buffer
            if self.pos > len(self.buf):
                self.buf += b'\0' * (self.pos - len(self.buf))
            # If writing to the end of the buffer
            if self.pos == len(self.buf):
                self.buf += data
            # If replacing the tail of the buffer
            elif self.pos + len(data) >= len(self.buf):
                self.buf = self.buf[:self.pos] + data
            # If writing to the middle of the buffer
            else:
                self.buf = self.buf[:self.pos] + data + self.buf[self.pos + len(data):]
            self.pos += len(data)
            return

        # If file is not created, then create it now
        if not self.file:
            # Initialize a new file
            self.file = tempfile.NamedTemporaryFile('w+b')
            # Empty buffer to it
            self.file.write(self.buf)
            self.file_size = len(self.buf)
            self.buf = None

        # If writing after the end of data
        if self.pos > self.file_size:
            size_increase = self.pos - self.file_size
            self.file.seek(self.file_size)
            self.file.write(b'\0' * size_increase)
            self.file_size += size_increase
        # Write to file. This is simpler than with buffer
        self.file.seek(self.pos)
        self.file.write(data)
        self.file_size = max(self.pos + len(data), self.file_size)
        self.pos += len(data)

    def read(self, size=-1):
        # If data is stored on file
        if self.file:
            self.file.seek(self.pos)
            read_amount = self.file_size - self.pos
            if size >= 0:
                read_amount = min(read_amount, size)
            self.pos += read_amount
            return self.file.read(read_amount)

        # If data is stored in memory, and everything is requested
        if size < 0 or size >= len(self.buf):
            result = self.buf[self.pos:]
            self.pos = len(self.buf)
            return result

        # If data is stored in memory, and only part is requested
        result = self.buf[self.pos:self.pos + size]
        self.pos += size
        return result

    def seekable(self):
        return True

    def seek(self, offset, whence=os.SEEK_SET):
        if whence == os.SEEK_SET:
            self.pos = max(0, offset)
        elif whence == os.SEEK_END:
            if self.file:
                self.pos = max(0, self.file_size + offset)
            else:
                self.pos = max(0, len(self.buf) + offset)
        else:
            raise RuntimeError(f'Unsupported "whence" value: {whence}')

        return self.pos

    def tell(self):
        return self.pos

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
