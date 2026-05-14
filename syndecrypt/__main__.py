"""
synology-decrypt:
 an open source (and executable) description of
 Synology's Cloud Sync encryption algorithm

Usage:
  syndecrypt [-p <password-file> | -k <private.pem>] [-a] [--verify]
             [--skip-larger-than=<size>] [--skip-smaller-than=<size>]
             [-O <directory>] <input>...
  syndecrypt (-h | --help)

Options:
  -O <directory> --output-directory=<directory>
                           Output directory [default: output]
  -p <password-file> --password-file=<password-file>
                           The file containing the decryption password
  -k <private.pem> --key-file=<private.pem>
                           The file containing the decryption private key
  -a --archive             Preserve source metadata on decrypted output:
                           mode, mtime, atime, and (when permitted) uid/gid.
                           Changing uid/gid usually requires root; chown
                           failures are silently skipped. ctime cannot be set
                           on Linux and is not preserved. Ignored with --verify.
  --skip-larger-than=<size>
                           Exclude any input file whose encrypted (on-disk)
                           size is strictly greater than <size>; the file is
                           not decrypted and not verified. SIZE accepts a
                           plain byte count or a suffix K/M/G/T (binary,
                           1K=1024), e.g. 1G, 500K, 1.5M. Note: csenc files
                           are LZ4-compressed, so the comparison is against
                           the encrypted size, not the decrypted size.
  --skip-smaller-than=<size>
                           Exclude any input file whose encrypted (on-disk)
                           size is strictly less than <size>. Same SIZE
                           format as the skip-larger-than flag. May be
                           combined with skip-larger-than to define a range
                           of sizes that are kept.
  --verify                 Check decryptability and file structure without
                           actually decrypting
  -h --help                Show this screen.

For more information, see https://github.com/marnix/synology-decrypt
"""
import docopt
import getpass
import os
import sys
import logging
import zipfile

import syndecrypt.files as files
import syndecrypt.util as util


def main(argv=None):
        arguments = docopt.docopt(__doc__, argv=argv)

        password_file_name = arguments['--password-file']
        if password_file_name != None:
                password = util._binary_contents_of(password_file_name).strip()
        else: password = None

        private_key_file_name = arguments['--key-file']
        if private_key_file_name != None:
                private_key = util._binary_contents_of(private_key_file_name)
        else: private_key = None

        # If neither password file nor private key is provided, prompt for password
        if password is None and private_key is None:
                password = getpass.getpass('Decryption password: ').encode('utf-8')

        output_dir = arguments['--output-directory']
        verify_mode = arguments['--verify']
        archive_mode = arguments['--archive']

        def _parse_size_arg(value, flag_name):
                if value is None:
                        return None
                try:
                        return util.parse_size(value)
                except ValueError as e:
                        sys.exit('syndecrypt: invalid value for %s: %r (%s)' % (flag_name, value, e))

        max_size = _parse_size_arg(arguments['--skip-larger-than'], '--skip-larger-than')
        min_size = _parse_size_arg(arguments['--skip-smaller-than'], '--skip-smaller-than')

        def _filtered_by_size(size_bytes):
                if max_size is not None and size_bytes > max_size:
                        return True
                if min_size is not None and size_bytes < min_size:
                        return True
                return False

        logging.getLogger().setLevel(logging.INFO)
        logging.basicConfig(format='%(levelname)s: %(message)s')

        succeeded = 0
        failed = 0
        skipped = 0

        def _track_verify(result):
                nonlocal succeeded, failed
                if result:
                        succeeded += 1
                else:
                        failed += 1

        def _track_decrypt(func, *args, **kwargs):
                nonlocal succeeded, failed
                try:
                        func(*args, **kwargs)
                        succeeded += 1
                        return True
                except Exception:
                        failed += 1
                        return False

        def _track_size_skip(label, size_bytes):
                nonlocal skipped
                logging.info('excluding "%s" (size %d bytes, outside size filter)', label, size_bytes)
                skipped += 1

        for input_path in arguments['<input>']:
                if os.path.isdir(input_path):
                        # Recursively scan directory
                        for dirpath, dirnames, filenames in os.walk(input_path):
                                for filename in filenames:
                                        full_path = os.path.join(dirpath, filename)
                                        rel_path = os.path.relpath(full_path, os.path.dirname(input_path))
                                        out_path = files.safe_output_path(output_dir, rel_path)
                                        try:
                                                src_size = os.path.getsize(full_path)
                                        except OSError:
                                                src_size = None
                                        if src_size is not None and _filtered_by_size(src_size):
                                                _track_size_skip(full_path, src_size)
                                                continue
                                        if verify_mode:
                                                _track_verify(files.verify_file(full_path, password=password, private_key=private_key))
                                        else:
                                                src_stat = None
                                                if archive_mode:
                                                        try:
                                                                src_stat = os.stat(full_path)
                                                        except OSError:
                                                                src_stat = None
                                                pre_existed = os.path.exists(out_path)
                                                ok = _track_decrypt(files.decrypt_file, full_path, out_path, password=password, private_key=private_key)
                                                if ok and src_stat is not None and not pre_existed and os.path.exists(out_path):
                                                        files.apply_metadata_from_stat(src_stat, out_path)

                elif zipfile.is_zipfile(input_path):
                        # Handle zip file: decrypt contents without temp files
                        with zipfile.ZipFile(input_path, 'r') as zf:
                                for name in zf.namelist():
                                        if name.endswith('/'):
                                                continue  # skip directory entries
                                        out_path = files.safe_output_path(output_dir, name)
                                        try:
                                                src_size = zf.getinfo(name).file_size
                                        except KeyError:
                                                src_size = None
                                        if src_size is not None and _filtered_by_size(src_size):
                                                _track_size_skip('%s:%s' % (input_path, name), src_size)
                                                continue
                                        if verify_mode:
                                                logging.info('verifying zip entry "%s" from "%s"', name, input_path)
                                                with zf.open(name) as entry_stream:
                                                        result = files.verify_stream(entry_stream, password=password, private_key=private_key)
                                                        if result:
                                                                logging.info('OK: zip entry "%s"', name)
                                                        else:
                                                                logging.error('FAILED: zip entry "%s"', name)
                                                        _track_verify(result)
                                        else:
                                                pre_existed = os.path.exists(out_path)
                                                with zf.open(name) as entry_stream:
                                                        ok = _track_decrypt(files.decrypt_stream_to_file, entry_stream, out_path, password=password, private_key=private_key)
                                                if ok and archive_mode and not pre_existed and os.path.exists(out_path):
                                                        files.apply_metadata_from_zipinfo(zf.getinfo(name), out_path)

                else:
                        # Single file
                        out_path = files.safe_output_path(output_dir, os.path.basename(input_path))
                        try:
                                src_size = os.path.getsize(input_path)
                        except OSError:
                                src_size = None
                        if src_size is not None and _filtered_by_size(src_size):
                                _track_size_skip(input_path, src_size)
                                continue
                        if verify_mode:
                                _track_verify(files.verify_file(input_path, password=password, private_key=private_key))
                        else:
                                src_stat = None
                                if archive_mode:
                                        try:
                                                src_stat = os.stat(input_path)
                                        except OSError:
                                                src_stat = None
                                pre_existed = os.path.exists(out_path)
                                ok = _track_decrypt(files.decrypt_file, input_path, out_path, password=password, private_key=private_key)
                                if ok and src_stat is not None and not pre_existed and os.path.exists(out_path):
                                        files.apply_metadata_from_stat(src_stat, out_path)

        # Print summary
        total = succeeded + failed
        action = 'Verified' if verify_mode else 'Decrypted'
        if failed == 0:
                message = '%s %d file(s): all succeeded.' % (action, total)
        else:
                message = '%s %d file(s): %d succeeded, %d failed.' % (action, total, succeeded, failed)
        if skipped:
                message += ' (%d excluded by --skip-larger-than/--skip-smaller-than.)' % skipped
        print(message)

        return {'succeeded': succeeded, 'failed': failed, 'skipped': skipped}


if __name__ == '__main__':
        main()
