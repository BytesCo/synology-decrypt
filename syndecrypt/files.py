from __future__ import print_function
import io
import os
import sys
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
        try:
                outdir = os.path.dirname(output_file_name)
                if outdir and not os.path.isdir(outdir):
                        os.makedirs(outdir)
                with open(output_file_name, 'wb') as outstream:
                        core.decrypt_stream(instream, outstream, password=password, private_key=private_key)
        except:
                LOGGER.error('decryption failed, exception occurred: %s: %s', sys.exc_info()[0], sys.exc_info()[1])
                if os.path.exists(output_file_name):
                        os.remove(output_file_name)
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
        try:
                with open(input_file_name, 'rb') as instream:
                        if not os.path.isdir(os.path.dirname(output_file_name)):
                                os.makedirs(os.path.dirname(output_file_name))
                        with open(output_file_name, 'wb') as outstream:
                                core.decrypt_stream(instream, outstream, password=password, private_key=private_key)
        except:
                LOGGER.error('decryption failed, exception occurred: %s: %s', sys.exc_info()[0], sys.exc_info()[1])
                if os.path.exists(output_file_name):
                        os.remove(output_file_name)
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
