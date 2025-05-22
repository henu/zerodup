#!/usr/bin/env python3
from . import arguments
from . import bigbuffer
from . import exceptions
from . import syncer

import sys


def main():

    try:

        # If free memory info is available, then use 10 % of that for buffers
        try:
            import psutil
            memory_available = psutil.virtual_memory().available
            memory_limit = max(10 * 1024 * 1024, psutil.virtual_memory().available // 10)
            bigbuffer.BigBuffer.set_memory_limit(memory_limit)
        except:
            pass

        args = arguments.Arguments()

        if args.action == 'backup':
            syncr = syncer.Syncer(args.destination)
            syncr.do_backup(args.source, args.master_key, args.excludes)
            syncr.close()

        elif args.action == 'restore':
            syncr = syncer.Syncer(args.source)
            syncr.do_restore(args.destination, args.master_key)
            syncr.close()

    except exceptions.FatalError as err:
        print(f'ERROR: {err}')
        sys.exit(1)


if __name__ == '__main__':
    main()
