"""
synology-decrypt:
 an open source (and executable) description of
 Synology's Cloud Sync encryption algorithm

Usage:
  syndecrypt [-p <password-file> | -k <private.pem>] [--verify] [-O <directory>] <input>...
  syndecrypt (-h | --help)

Options:
  -O <directory> --output-directory=<directory>
                           Output directory [default: output]
  -p <password-file> --password-file=<password-file>
                           The file containing the decryption password
  -k <private.pem> --key-file=<private.pem>
                           The file containing the decryption private key
  --verify                 Check decryptability and file structure without
                           actually decrypting
  -h --help                Show this screen.

For more information, see https://github.com/marnix/synology-decrypt
"""
import docopt
import getpass
import os
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

        logging.getLogger().setLevel(logging.INFO)
        logging.basicConfig(format='%(levelname)s: %(message)s')

        succeeded = 0
        failed = 0

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
                except Exception:
                        failed += 1

        for input_path in arguments['<input>']:
                if os.path.isdir(input_path):
                        # Recursively scan directory
                        for dirpath, dirnames, filenames in os.walk(input_path):
                                for filename in filenames:
                                        full_path = os.path.join(dirpath, filename)
                                        rel_path = os.path.relpath(full_path, os.path.dirname(input_path))
                                        out_path = files.safe_output_path(output_dir, rel_path)
                                        if verify_mode:
                                                _track_verify(files.verify_file(full_path, password=password, private_key=private_key))
                                        else:
                                                _track_decrypt(files.decrypt_file, full_path, out_path, password=password, private_key=private_key)

                elif zipfile.is_zipfile(input_path):
                        # Handle zip file: decrypt contents without temp files
                        with zipfile.ZipFile(input_path, 'r') as zf:
                                for name in zf.namelist():
                                        if name.endswith('/'):
                                                continue  # skip directory entries
                                        out_path = files.safe_output_path(output_dir, name)
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
                                                with zf.open(name) as entry_stream:
                                                        _track_decrypt(files.decrypt_stream_to_file, entry_stream, out_path, password=password, private_key=private_key)

                else:
                        # Single file
                        out_path = files.safe_output_path(output_dir, os.path.basename(input_path))
                        if verify_mode:
                                _track_verify(files.verify_file(input_path, password=password, private_key=private_key))
                        else:
                                _track_decrypt(files.decrypt_file, input_path, out_path, password=password, private_key=private_key)

        # Print summary
        total = succeeded + failed
        action = 'Verified' if verify_mode else 'Decrypted'
        if failed == 0:
                print('%s %d file(s): all succeeded.' % (action, total))
        else:
                print('%s %d file(s): %d succeeded, %d failed.' % (action, total, succeeded, failed))

        return {'succeeded': succeeded, 'failed': failed}


if __name__ == '__main__':
        main()
