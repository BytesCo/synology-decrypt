from __future__ import print_function
import io
import os
import sys
import time
import logging

import syndecrypt.core as core

LOGGER=logging.getLogger(__name__)


def decrypt_stream_to_file(instream, output_file_name, password=None, private_key=None):
        """Decrypt an already-open encrypted stream and write to output file."""
        if os.path.exists(output_file_name):
                LOGGER.warning('skipping decryption: chosen output file "%s" already exists',
                        output_file_name
                )
                return
        LOGGER.info('decrypting to "%s"', output_file_name)
        partial_path = output_file_name + '.partial'
        try:
                outdir = os.path.dirname(output_file_name)
                if outdir and not os.path.isdir(outdir):
                        os.makedirs(outdir)
                with open(partial_path, 'wb') as outstream:
                        core.decrypt_stream(instream, outstream, password=password, private_key=private_key)
                os.rename(partial_path, output_file_name)
        except:
                LOGGER.error('decryption failed, exception occurred: %s: %s', sys.exc_info()[0], sys.exc_info()[1])
                if os.path.exists(partial_path):
                        os.remove(partial_path)
                raise


def decrypt_file(input_file_name, output_file_name, password=None, private_key=None):
        if not os.path.exists(input_file_name):
                LOGGER.warning('skipping decryption of "%s": encrypted input file does not exist',
                        input_file_name
                )
                return
        if os.path.exists(output_file_name):
                LOGGER.warning('skipping decryption of "%s": chosen output file "%s" already exists',
                        input_file_name, output_file_name
                )
                return
        LOGGER.info('decrypting "%s" to "%s"', input_file_name, output_file_name)
        partial_path = output_file_name + '.partial'
        try:
                with open(input_file_name, 'rb') as instream:
                        if not os.path.isdir(os.path.dirname(output_file_name)):
                                os.makedirs(os.path.dirname(output_file_name))
                        with open(partial_path, 'wb') as outstream:
                                core.decrypt_stream(instream, outstream, password=password, private_key=private_key)
                os.rename(partial_path, output_file_name)
        except:
                LOGGER.error('decryption failed, exception occurred: %s: %s', sys.exc_info()[0], sys.exc_info()[1])
                if os.path.exists(partial_path):
                        os.remove(partial_path)
                raise


def verify_file(input_file_name, password=None, private_key=None):
        """Verify that a file can be decrypted without writing output."""
        if not os.path.exists(input_file_name):
                LOGGER.warning('skipping verify of "%s": file does not exist', input_file_name)
                return False
        LOGGER.info('verifying "%s"', input_file_name)
        try:
                with open(input_file_name, 'rb') as instream:
                        core.decrypt_stream(instream, io.BytesIO(), password=password, private_key=private_key)
                LOGGER.info('OK: "%s"', input_file_name)
                return True
        except Exception:
                LOGGER.error('FAILED: "%s": %s: %s', input_file_name, sys.exc_info()[0], sys.exc_info()[1])
                return False


def verify_stream(instream, password=None, private_key=None):
        """Verify that a stream can be decrypted without writing output."""
        try:
                core.decrypt_stream(instream, io.BytesIO(), password=password, private_key=private_key)
                return True
        except Exception:
                LOGGER.error('verify failed: %s: %s', sys.exc_info()[0], sys.exc_info()[1])
                return False


def safe_output_path(output_dir, file_path):
        """Compute output path, handling absolute paths by stripping the root."""
        if os.path.isabs(file_path):
                # Strip leading separator(s) so os.path.join works correctly
                file_path = os.path.relpath(file_path, os.sep)
        return os.path.join(output_dir, file_path)


def apply_metadata_from_stat(src_stat, target_path):
        """Apply mode/mtime/atime/uid/gid from a stat result onto target_path.

        Never raises: metadata failures must not turn a successful decryption into a
        counted failure. ctime is intentionally not copied — it is not settable on
        Linux (the kernel updates it implicitly on any inode change). The caller is
        responsible for snapshotting the source stat *before* opening the source for
        read, so the original atime is captured rather than the post-read atime.
        """
        try:
                os.utime(target_path, ns=(src_stat.st_atime_ns, src_stat.st_mtime_ns))
        except OSError as e:
                LOGGER.warning('cannot set times on "%s": %s', target_path, e)
        try:
                os.chmod(target_path, src_stat.st_mode & 0o7777)
        except OSError as e:
                LOGGER.warning('cannot chmod "%s": %s', target_path, e)
        try:
                os.chown(target_path, src_stat.st_uid, src_stat.st_gid)
        except PermissionError:
                LOGGER.debug('skipping chown of "%s": not permitted', target_path)
        except OSError as e:
                LOGGER.warning('chown of "%s" failed: %s', target_path, e)


def apply_metadata_from_zipinfo(zinfo, target_path):
        """Copy mode (if Unix) and mtime (from zip date_time) onto target_path.

        Never raises. Standard ZipInfo does not carry uid/gid or atime, so only mode
        and mtime are applied.
        """
        if zinfo.create_system == 3:
                mode = (zinfo.external_attr >> 16) & 0o7777
                if mode:
                        try:
                                os.chmod(target_path, mode)
                        except OSError as e:
                                LOGGER.warning('cannot chmod "%s": %s', target_path, e)
        try:
                ts = time.mktime(zinfo.date_time + (0, 0, -1))
                os.utime(target_path, (ts, ts))
        except (OSError, ValueError, OverflowError) as e:
                LOGGER.warning('cannot set mtime on "%s": %s', target_path, e)
