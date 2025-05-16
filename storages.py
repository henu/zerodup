import bigbuffer
import constants
import exceptions

import datetime
import getpass
import os
import re


def build_storage_engine(url):

    UNIX_USERNAME_RE_RAW = '([a-zA-Z0-9][a-zA-Z0-9._-]{0,30}[a-zA-Z0-9])'
    HOST_RE_RAW = '((?:[a-zA-Z0-9-]+\\.)+[a-zA-Z0-9-]+|^(?:\\d{1,3}\\.){3}\\d{1,3})'

    STORAGE_B2_URL_RE = re.compile('^[bB]2://(?P<app_key_id>[0-9a-zA-Z\\-/]+):(?P<app_key>[0-9a-zA-Z\\-/]+):(?P<bucket>[0-9a-zA-Z\\-]+):(?P<identifier>[0-9a-zA-Z\\-]+)$')
    STORAGE_LOCAL_URL_RE = re.compile('^[fF][iI][lL][eE]://?(?P<path>/.*)$')
    STORAGE_SFTP_URL_RE = re.compile(f'^[sS][fF][tT][pP]://((?P<username>{UNIX_USERNAME_RE_RAW})@)?(?P<host>{HOST_RE_RAW})(?P<path>/.*)$')

    # Backblaze
    b2_match = STORAGE_B2_URL_RE.match(url)
    if b2_match:
        app_key_id = b2_match.groupdict()['app_key_id']
        app_key = b2_match.groupdict()['app_key']
        bucket = b2_match.groupdict()['bucket']
        identifier = b2_match.groupdict()['identifier']
        return BackBlazeStorage(app_key_id, app_key, bucket, identifier)

    # Local
    local_match = STORAGE_LOCAL_URL_RE.match(url)
    if local_match:
        path = local_match.groupdict()['path']
        return LocalStorage(path)

    # SFTP
    sftp_match = STORAGE_SFTP_URL_RE.match(url)
    if sftp_match:
        username = sftp_match.groupdict()['username']
        host = sftp_match.groupdict()['host']
        path = sftp_match.groupdict()['path']
        return SftpStorage(username, host, path)

    raise RuntimeError(f'URL "{url}" is not supported!')


class Storage:

    def upload_new_filelist(self, stream):
        raise NotImplementedError()

    def download_latest_filelist(self):
        raise NotImplementedError()

    def entry_exists(self, crypthash_hex):
        raise NotImplementedError()

    def upload_entry(self, crypthash_hex, stream, progress_prefix=None):
        raise NotImplementedError()

    def download_entry(self, crypthash_hex):
        raise NotImplementedError()

    def close(self):
        pass


class DirectoryBasedStorage(Storage):

    def __init__(self, path):
        self.root, self.identifier = os.path.split(path)

    def get_identifier(self):
        raise NotImplementedError()

    def exists(self, path):
        raise NotImplementedError()

    def listdir(self, path):
        raise NotImplementedError()

    def mkdir(self, path):
        raise NotImplementedError()

    def read(self, path):
        raise NotImplementedError()

    def write(self, path, stream, progress_prefix=None):
        raise NotImplementedError()

    def upload_new_filelist(self, stream):
        new_filelist_name = '{}_{}'.format(
            self.get_identifier(),
            datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )
        self.write(new_filelist_name, stream)
        stream.close()

    def download_latest_filelist(self):
        # Find the most recent filelist and download it. Go files in
        # reversed order, hoping to find the most recent filelist first.
        latest_filelist = None
        latest_filelist_timestamp = None
        for file in sorted(self.listdir('/'), reverse=True):
            # Check if this is a filelist
            filelist_match = DirectoryBasedStorage._FILELIST_RE.match(file)
            if filelist_match:
                if filelist_match.groupdict()['identifier'] == self.get_identifier():
                    timestamp = datetime.datetime.fromisoformat(filelist_match.groupdict()['timestamp'])
                    if latest_filelist_timestamp is None or latest_filelist_timestamp < timestamp:
                        # TODO: Why this is read immediately?
                        latest_filelist = self.read(file)
                        latest_filelist_timestamp = timestamp
        return latest_filelist

    def entry_exists(self, crypthash_hex):
        path = self._get_storage_path(crypthash_hex)
        return self.exists(path)

    def upload_entry(self, crypthash_hex, stream, progress_prefix=None):
        path = self._get_storage_path(crypthash_hex)
        self._makedirs(os.path.dirname(path))
        stream.seek(0)
        self.write(path, stream, progress_prefix)

    def download_entry(self, crypthash_hex):
        path = self._get_storage_path(crypthash_hex)
        return self.read(path)

    _TIMESTAMP_RE_RAW = '\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(?:Z|(?:[+-]\\d{2}:\\d{2}))?'
    _FILELIST_RE = re.compile(f'^(?P<identifier>.*)_(?P<timestamp>{_TIMESTAMP_RE_RAW})$')

    def _fix_path(self, path):
        while path and path.startswith('/'):
            path = path[1:]
        return os.path.join(self.root, path)

    def _get_storage_path(self, crypthash_hex):
        return 'storage/{}/{}/{}/{}/{}'.format(
            crypthash_hex[0],
            crypthash_hex[1],
            crypthash_hex[2],
            crypthash_hex[3],
            crypthash_hex,
        )

    def _makedirs(self, path):
        if not path or path == '/':
            return
        if not self.exists(path):
            parent = os.path.dirname(path)
            self._makedirs(parent)
            self.mkdir(path)


class LocalStorage(DirectoryBasedStorage):

    def get_identifier(self):
        return self.identifier

    def exists(self, path):
        return os.path.lexists(self._fix_path(path))

    def listdir(self, path):
        return os.listdir(self._fix_path(path))

    def mkdir(self, path):
        return os.mkdir(self._fix_path(path))

    def read(self, path):
        result = bigbuffer.BigBuffer()
        with open(self._fix_path(path), 'rb') as file:
            while chunk := file.read(constants.STREAM_CHUNK_SIZE):
                result.write(chunk)
        return result

    def write(self, path, stream, progress_prefix=None):
        if progress_prefix:
            stream_size = _get_stream_size(stream)
            print(f'{progress_prefix}0 %', end='', flush=True)
            stream_read = 0
        with open(self._fix_path(path), 'wb') as file:
            while chunk := stream.read(constants.STREAM_CHUNK_SIZE):
                file.write(chunk)
                if progress_prefix:
                    stream_read += len(chunk)
                    write_progress = int(100 * stream_read / stream_size)
                    print(f'\r{progress_prefix}{write_progress} %', end='', flush=True)
        if progress_prefix:
            print()


class SftpStorage(DirectoryBasedStorage):

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
                raise exceptions.FatalError(f'Access denied for {username}@{host}!')
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
        result = bigbuffer.BigBuffer()
        with self.sftp_client.open(self._fix_path(path), 'rb') as file:
            while chunk := file.read(constants.STREAM_CHUNK_SIZE):
                result.write(chunk)
        return result

    def write(self, path, stream, progress_prefix=None):
        if progress_prefix:
            stream_size = _get_stream_size(stream)
            print(f'{progress_prefix}0 %', end='', flush=True)
            stream_read = 0
        with self.sftp_client.open(self._fix_path(path), 'wb') as file:
            while chunk := stream.read(constants.STREAM_CHUNK_SIZE):
                file.write(chunk)
                if progress_prefix:
                    stream_read += len(chunk)
                    write_progress = int(100 * stream_read / stream_size)
                    print(f'\r{progress_prefix}{write_progress} %', end='', flush=True)
        if progress_prefix:
            print()

    def close(self):
        self.sftp_client.close()
        self.ssh_client.close()


class BackBlazeStorage(Storage):

    def __init__(self, app_key_id, app_key, bucket, identifier):
        from b2sdk.v2 import AuthInfoCache, B2Api, InMemoryAccountInfo
        info = InMemoryAccountInfo()
        self.b2_api = B2Api(info, cache=AuthInfoCache(info))
        self.b2_api.authorize_account('production', app_key_id, app_key)
        self.bucket = self.b2_api.get_bucket_by_name(bucket)
        self.identifier = identifier

        # Asking if entries exist or not makes a lot of API calls. That's why there is this cache system for this
        self.entry_existence_cache = set()
        self.entry_existence_cache_new = set()
        for file_version, folder_name in self.bucket.ls('entry_existence_cache/'):
            timestamp = datetime.datetime.fromisoformat(os.path.basename(file_version.file_name))
            # If file is too old, then delete it
            if timestamp < datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=30):
                self.bucket.delete_file_version(file_version.id_, file_version.file_name)
            # If file is new enough, then read its contents to cache
            else:
                buf = bigbuffer.BigBuffer()
                df = self.bucket.download_file_by_id(file_version.id_)
                df.save(buf)
                buf.seek(0)
                for crypthash_hex in buf.read().decode('ascii').splitlines():
                    crypthash_hex = crypthash_hex.strip()
                    if crypthash_hex:
                        self.entry_existence_cache.add(crypthash_hex)

    def upload_new_filelist(self, stream):
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        from b2sdk.v2 import UploadSourceStream
        stream_size = _get_stream_size(stream)
        b2_stream = UploadSourceStream(self.BigBufferOpener(stream), stream_size)
        stream.seek(0)
        self.bucket.upload(b2_stream, f'filelists/{self.identifier}/{now}')

    def download_latest_filelist(self):
        # Find the most recent filelist
        latest_filelist_name = None
        latest_filelist_timestamp = None
        for file_version, folder_name in self.bucket.ls(f'filelists/{self.identifier}/'):
            timestamp = datetime.datetime.fromisoformat(os.path.basename(file_version.file_name))
            if latest_filelist_timestamp is None or latest_filelist_timestamp < timestamp:
                latest_filelist_name = file_version.file_name
                latest_filelist_timestamp = timestamp
        if latest_filelist_name:
            latest_filelist_stream = bigbuffer.BigBuffer()
            latest_filelist_df = self.bucket.download_file_by_name(latest_filelist_name)
            latest_filelist_df.save(latest_filelist_stream)
            latest_filelist_stream.seek(0)
            return latest_filelist_stream
        return None

    def entry_exists(self, crypthash_hex):
        # First check cache
        if crypthash_hex in self.entry_existence_cache or crypthash_hex in self.entry_existence_cache_new:
            return True
        # Then check from the cloud
        from b2sdk.exception import FileNotPresent
        try:
            info = self.bucket.get_file_info_by_name(f'entries/{crypthash_hex}')
            self._add_to_entry_existence_cache_new(crypthash_hex)
            return True
        except FileNotPresent:
            return False

    def upload_entry(self, crypthash_hex, stream, progress_prefix=None):
        from b2sdk.v2 import UploadSourceStream, AbstractProgressListener

        # Construct a progress listener, if requested
        progress_listener = None
        if progress_prefix:
            class ProgressListener(AbstractProgressListener):

                def __init__(self, progress_prefix):
                    self.progress_prefix = progress_prefix

                def set_total_bytes(self, total_byte_count):
                    self.total_byte_count = total_byte_count

                def bytes_completed(self, byte_count):
                    progress = int(100 * byte_count / self.total_byte_count)
                    print(f'\r{self.progress_prefix}{progress} %', end='', flush=True)

                def close(self):
                    pass

            progress_listener = ProgressListener(progress_prefix)

        # Prepare stream
        stream_size = _get_stream_size(stream)
        b2_stream = UploadSourceStream(self.BigBufferOpener(stream), stream_size)

        # Upload
        self.bucket.upload(b2_stream, f'entries/{crypthash_hex}', progress_listener=progress_listener)

        if progress_prefix:
            print()

        # If cache is not aware of this, then update it
        if crypthash_hex not in self.entry_existence_cache and crypthash_hex not in self.entry_existence_cache_new:
            self._add_to_entry_existence_cache_new(crypthash_hex)

    def download_entry(self, crypthash_hex):
        stream = bigbuffer.BigBuffer()
        df = self.bucket.download_file_by_name(f'entries/{crypthash_hex}')
        df.save(stream)
        stream.seek(0)
        return stream

    def close(self):
        pass

    def _add_to_entry_existence_cache_new(self, crypthash_hex):
        from b2sdk.v2 import UploadSourceStream
        self.entry_existence_cache_new.add(crypthash_hex)
        # If cache has grown too big, then upload it to cloud
        if len(self.entry_existence_cache_new) >= 1000:
            # Upload to cloud
            buf = bigbuffer.BigBuffer()
            for crypthash_hex in sorted(self.entry_existence_cache_new):
                buf.write((crypthash_hex + '\n').encode('ascii'))
            buf_size = _get_stream_size(buf)
            b2_stream = UploadSourceStream(lambda: buf, buf_size)
            buf.seek(0)
            now = datetime.datetime.now(datetime.timezone.utc).isoformat()
            self.bucket.upload(b2_stream, f'entry_existence_cache/{now}')
            # Add to old cache, and clear the new one
            self.entry_existence_cache |= self.entry_existence_cache_new
            self.entry_existence_cache_new = set()

    class BigBufferOpener:

        def __init__(self, stream):
            self.stream = stream

        def __call__(self):
            return self.stream.cloned_new_instance()


def _get_stream_size(stream):
    pos = stream.tell()
    stream.seek(0, os.SEEK_END)
    stream_size = stream.tell()
    stream.seek(pos)
    return stream_size
