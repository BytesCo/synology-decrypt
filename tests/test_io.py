"""Tests for directory scanning, zip handling, verify mode, output path handling, and defaults."""
from __future__ import print_function

import hashlib
import io
import os
import shutil
import time
import zipfile

import pytest

import syndecrypt.core as core
import syndecrypt.files as files
import syndecrypt.util as util

PASSWORD = util._binary_contents_of('tests/testfiles-secrets/password.txt')
PRIVATE_KEY = util._binary_contents_of('tests/testfiles-secrets/private.pem')
PASSWORD_STR = PASSWORD.decode('utf-8')  # for getpass simulation

CSENC_V1 = 'tests/testfiles-v1/csenc/single-line.txt'
CSENC_V3 = 'tests/testfiles-v3/csenc/ssingle-line.txt'
PLAIN_CONTENT = b'Just a single line, no newline character at the end...'

# Corrupt csenc data: valid magic header but invalid TLV body
_MAGIC = b'__CLOUDSYNC_ENC__'
_MAGIC_HASH = hashlib.md5(_MAGIC).hexdigest().encode('ascii')
CORRUPT_CSENC = _MAGIC + _MAGIC_HASH + b'\x99' * 100


def _abs_test_path(rel_path):
    """Return absolute path for a test-relative path (works after chdir)."""
    return os.path.abspath(os.path.join(os.path.dirname(__file__), '..', rel_path))


# ---------------------------------------------------------------------------
# 1. Directory input: recursive scanning
# ---------------------------------------------------------------------------

class TestDirectoryInput:

    def test_decrypt_directory_recursively(self, tmp_path):
        """Recursively decrypt all files from a directory into output dir."""
        input_dir = tmp_path / 'encrypted'
        sub_dir = input_dir / 'subdir'
        sub_dir.mkdir(parents=True)

        shutil.copy(CSENC_V1, str(input_dir / 'file1.txt'))
        shutil.copy(CSENC_V3, str(sub_dir / 'file2.txt'))

        output_dir = tmp_path / 'decrypted'
        output_dir.mkdir()

        input_dir_str = str(input_dir)
        for dirpath, dirnames, filenames in os.walk(input_dir_str):
            for filename in filenames:
                full_path = os.path.join(dirpath, filename)
                rel_path = os.path.relpath(full_path, os.path.dirname(input_dir_str))
                out_path = files.safe_output_path(str(output_dir), rel_path)
                files.decrypt_file(full_path, out_path, password=PASSWORD)

        assert (output_dir / 'encrypted' / 'file1.txt').read_bytes() == PLAIN_CONTENT
        assert (output_dir / 'encrypted' / 'subdir' / 'file2.txt').read_bytes() == PLAIN_CONTENT

    def test_decrypt_directory_preserves_structure(self, tmp_path):
        """Directory structure should be preserved in output."""
        input_dir = tmp_path / 'input'
        deep = input_dir / 'a' / 'b' / 'c'
        deep.mkdir(parents=True)
        shutil.copy(CSENC_V1, str(deep / 'deep.txt'))

        output_dir = tmp_path / 'output'
        output_dir.mkdir()

        full_path = str(deep / 'deep.txt')
        rel_path = os.path.relpath(full_path, os.path.dirname(str(input_dir)))
        out_path = files.safe_output_path(str(output_dir), rel_path)
        files.decrypt_file(full_path, out_path, password=PASSWORD)

        result = output_dir / 'input' / 'a' / 'b' / 'c' / 'deep.txt'
        assert result.exists()
        assert result.read_bytes() == PLAIN_CONTENT

    def test_empty_directory_produces_no_output(self, tmp_path):
        """An empty directory should produce no output files."""
        input_dir = tmp_path / 'empty'
        input_dir.mkdir()

        files_found = []
        for dirpath, dirnames, filenames in os.walk(str(input_dir)):
            for filename in filenames:
                files_found.append(filename)

        assert files_found == []


# ---------------------------------------------------------------------------
# 2. Zip input: decrypt files inside zip without temp files
# ---------------------------------------------------------------------------

class TestZipInput:

    def _make_zip(self, zip_path, entries):
        """Create a zip with given {name: filepath} entries."""
        with zipfile.ZipFile(str(zip_path), 'w') as zf:
            for arcname, source_path in entries.items():
                zf.write(source_path, arcname)

    def _make_zip_from_bytes(self, zip_path, entries):
        """Create a zip with given {name: bytes} entries."""
        with zipfile.ZipFile(str(zip_path), 'w') as zf:
            for arcname, data in entries.items():
                zf.writestr(arcname, data)

    def test_decrypt_zip_contents(self, tmp_path):
        """Decrypt files from inside a zip archive."""
        zip_path = tmp_path / 'archive.zip'
        self._make_zip(zip_path, {
            'file1.txt': CSENC_V1,
            'subdir/file2.txt': CSENC_V3,
        })

        output_dir = tmp_path / 'output'
        output_dir.mkdir()

        with zipfile.ZipFile(str(zip_path), 'r') as zf:
            for name in zf.namelist():
                if name.endswith('/'):
                    continue
                out_path = files.safe_output_path(str(output_dir), name)
                with zf.open(name) as entry_stream:
                    files.decrypt_stream_to_file(
                        entry_stream, out_path, password=PASSWORD
                    )

        assert (output_dir / 'file1.txt').read_bytes() == PLAIN_CONTENT
        assert (output_dir / 'subdir' / 'file2.txt').read_bytes() == PLAIN_CONTENT

    def test_zip_no_temp_files_on_success(self, tmp_path):
        """No temp files should be left after successful zip decryption."""
        zip_path = tmp_path / 'archive.zip'
        self._make_zip(zip_path, {'file.txt': CSENC_V1})

        output_dir = tmp_path / 'output'
        output_dir.mkdir()

        with zipfile.ZipFile(str(zip_path), 'r') as zf:
            for name in zf.namelist():
                out_path = files.safe_output_path(str(output_dir), name)
                with zf.open(name) as entry_stream:
                    files.decrypt_stream_to_file(
                        entry_stream, out_path, password=PASSWORD
                    )

        all_files = []
        for dirpath, dirnames, filenames in os.walk(str(tmp_path)):
            for fn in filenames:
                all_files.append(os.path.join(dirpath, fn))

        output_files = [f for f in all_files if 'output' in f]
        assert len(output_files) == 1
        assert output_files[0].endswith('file.txt')

    def test_zip_no_temp_files_on_failure(self, tmp_path):
        """No temp/partial files should remain after failed zip decryption."""
        zip_path = tmp_path / 'bad.zip'
        self._make_zip_from_bytes(zip_path, {'bad.txt': CORRUPT_CSENC})

        output_dir = tmp_path / 'output'
        output_dir.mkdir()

        with zipfile.ZipFile(str(zip_path), 'r') as zf:
            for name in zf.namelist():
                out_path = files.safe_output_path(str(output_dir), name)
                with zf.open(name) as entry_stream:
                    try:
                        files.decrypt_stream_to_file(
                            entry_stream, out_path, password=PASSWORD
                        )
                    except Exception:
                        pass  # expected

        assert not os.path.exists(str(output_dir / 'bad.txt'))

    def test_decrypt_zip_with_nested_dirs(self, tmp_path):
        """Zip with nested directory structure should be preserved."""
        zip_path = tmp_path / 'nested.zip'
        self._make_zip(zip_path, {
            'a/b/c/deep.txt': CSENC_V1,
        })

        output_dir = tmp_path / 'output'
        output_dir.mkdir()

        with zipfile.ZipFile(str(zip_path), 'r') as zf:
            for name in zf.namelist():
                if name.endswith('/'):
                    continue
                out_path = files.safe_output_path(str(output_dir), name)
                with zf.open(name) as entry_stream:
                    files.decrypt_stream_to_file(
                        entry_stream, out_path, password=PASSWORD
                    )

        assert (output_dir / 'a' / 'b' / 'c' / 'deep.txt').read_bytes() == PLAIN_CONTENT


# ---------------------------------------------------------------------------
# 3. --verify option: check decryptability without decrypting
# ---------------------------------------------------------------------------

class TestVerify:

    def test_verify_valid_file_with_password(self):
        """verify_file should return True for a valid encrypted file."""
        assert files.verify_file(CSENC_V1, password=PASSWORD) is True

    def test_verify_valid_file_with_private_key(self):
        """verify_file should return True with private key."""
        assert files.verify_file(CSENC_V3, private_key=PRIVATE_KEY) is True

    def test_verify_fails_without_credentials(self):
        """verify_file should return False when no key is provided."""
        assert files.verify_file(CSENC_V1) is False

    def test_verify_fails_for_nonexistent_file(self):
        """verify_file should return False for a missing file."""
        assert files.verify_file('/nonexistent/path/file.txt') is False

    def test_verify_does_not_create_output(self, tmp_path):
        """verify_file should never create any output files."""
        files.verify_file(CSENC_V1, password=PASSWORD)
        assert list(tmp_path.iterdir()) == []

    def test_verify_stream_valid(self):
        """verify_stream should return True for a valid stream."""
        with open(CSENC_V1, 'rb') as f:
            assert files.verify_stream(f, password=PASSWORD) is True

    def test_verify_stream_invalid(self):
        """verify_stream should return False for corrupt csenc data."""
        bad_stream = io.BytesIO(CORRUPT_CSENC)
        assert files.verify_stream(bad_stream, password=PASSWORD) is False

    def test_verify_zip_entries(self, tmp_path):
        """Verify should work on zip entries without extracting."""
        zip_path = tmp_path / 'archive.zip'
        with zipfile.ZipFile(str(zip_path), 'w') as zf:
            zf.write(CSENC_V1, 'entry.txt')

        with zipfile.ZipFile(str(zip_path), 'r') as zf:
            with zf.open('entry.txt') as entry_stream:
                assert files.verify_stream(entry_stream, password=PASSWORD) is True

        output_files = [f for f in tmp_path.iterdir() if f.name != 'archive.zip']
        assert output_files == []


# ---------------------------------------------------------------------------
# 4. Console password prompt (getpass)
# ---------------------------------------------------------------------------

class TestPasswordPrompt:

    def test_main_prompts_for_password_on_single_file(self, tmp_path, monkeypatch):
        """main() should call getpass when no -p/-k is given for a file."""
        from syndecrypt.__main__ import main
        import getpass as getpass_mod

        prompted = []
        def fake_getpass(prompt='Password: '):
            prompted.append(prompt)
            return PASSWORD_STR

        monkeypatch.setattr(getpass_mod, 'getpass', fake_getpass)

        output_dir = str(tmp_path / 'out')
        abs_input = _abs_test_path(CSENC_V1)

        main(argv=['-O', output_dir, abs_input])

        assert len(prompted) == 1
        assert 'Decryption password' in prompted[0]
        # Verify the file was actually decrypted
        out_file = os.path.join(output_dir, os.path.basename(abs_input))
        assert os.path.exists(out_file)
        with open(out_file, 'rb') as f:
            assert f.read() == PLAIN_CONTENT

    def test_main_prompts_for_password_on_zip(self, tmp_path, monkeypatch):
        """main() should call getpass when no -p/-k is given for a zip."""
        from syndecrypt.__main__ import main
        import getpass as getpass_mod

        prompted = []
        def fake_getpass(prompt='Password: '):
            prompted.append(prompt)
            return PASSWORD_STR

        monkeypatch.setattr(getpass_mod, 'getpass', fake_getpass)

        # Create zip with encrypted file
        zip_path = str(tmp_path / 'archive.zip')
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.write(CSENC_V1, 'encrypted.txt')

        output_dir = str(tmp_path / 'out')

        main(argv=['-O', output_dir, zip_path])

        assert len(prompted) == 1
        assert 'Decryption password' in prompted[0]
        out_file = os.path.join(output_dir, 'encrypted.txt')
        assert os.path.exists(out_file)
        with open(out_file, 'rb') as f:
            assert f.read() == PLAIN_CONTENT

    def test_main_prompts_for_password_on_directory(self, tmp_path, monkeypatch):
        """main() should call getpass when no -p/-k is given for a directory."""
        from syndecrypt.__main__ import main
        import getpass as getpass_mod

        prompted = []
        def fake_getpass(prompt='Password: '):
            prompted.append(prompt)
            return PASSWORD_STR

        monkeypatch.setattr(getpass_mod, 'getpass', fake_getpass)

        # Create directory with an encrypted file
        input_dir = tmp_path / 'enc_dir'
        input_dir.mkdir()
        shutil.copy(CSENC_V1, str(input_dir / 'file.txt'))

        output_dir = str(tmp_path / 'out')

        main(argv=['-O', output_dir, str(input_dir)])

        assert len(prompted) == 1
        assert 'Decryption password' in prompted[0]
        out_file = os.path.join(output_dir, 'enc_dir', 'file.txt')
        assert os.path.exists(out_file)
        with open(out_file, 'rb') as f:
            assert f.read() == PLAIN_CONTENT

    def test_main_prompts_for_password_on_verify(self, tmp_path, monkeypatch):
        """main() should call getpass for --verify when no -p/-k is given."""
        from syndecrypt.__main__ import main
        import getpass as getpass_mod

        prompted = []
        def fake_getpass(prompt='Password: '):
            prompted.append(prompt)
            return PASSWORD_STR

        monkeypatch.setattr(getpass_mod, 'getpass', fake_getpass)

        abs_input = _abs_test_path(CSENC_V1)

        main(argv=['--verify', abs_input])

        assert len(prompted) == 1
        assert 'Decryption password' in prompted[0]

    def test_main_no_prompt_when_password_file_given(self, tmp_path, monkeypatch):
        """main() should NOT prompt when -p is provided."""
        from syndecrypt.__main__ import main
        import getpass as getpass_mod

        prompted = []
        def fake_getpass(prompt='Password: '):
            prompted.append(prompt)
            return 'should_not_be_called'

        monkeypatch.setattr(getpass_mod, 'getpass', fake_getpass)

        output_dir = str(tmp_path / 'out')
        abs_input = _abs_test_path(CSENC_V1)
        pwd_file = _abs_test_path('tests/testfiles-secrets/password.txt')

        main(argv=['-p', pwd_file, '-O', output_dir, abs_input])

        assert len(prompted) == 0

    def test_main_no_prompt_when_key_file_given(self, tmp_path, monkeypatch):
        """main() should NOT prompt when -k is provided."""
        from syndecrypt.__main__ import main
        import getpass as getpass_mod

        prompted = []
        def fake_getpass(prompt='Password: '):
            prompted.append(prompt)
            return 'should_not_be_called'

        monkeypatch.setattr(getpass_mod, 'getpass', fake_getpass)

        output_dir = str(tmp_path / 'out')
        abs_input = _abs_test_path(CSENC_V1)
        key_file = _abs_test_path('tests/testfiles-secrets/private.pem')

        main(argv=['-k', key_file, '-O', output_dir, abs_input])

        assert len(prompted) == 0


# ---------------------------------------------------------------------------
# 5. Absolute path handling
# ---------------------------------------------------------------------------

class TestAbsolutePathHandling:

    def test_safe_output_path_with_absolute_input(self):
        """Absolute input paths should not override the output directory."""
        result = files.safe_output_path('/out', '/home/user/file.txt')
        assert result == os.path.join('/out', 'home/user/file.txt')

    def test_safe_output_path_with_relative_input(self):
        """Relative paths should be joined normally."""
        result = files.safe_output_path('/out', 'subdir/file.txt')
        assert result == '/out/subdir/file.txt'

    def test_safe_output_path_preserves_structure(self):
        """Nested relative paths should be preserved."""
        result = files.safe_output_path('/output', 'a/b/c/file.txt')
        assert result == '/output/a/b/c/file.txt'

    def test_safe_output_path_strips_leading_separator(self):
        """Multiple leading separators should be stripped."""
        result = files.safe_output_path('/out', '///deep/path/file.txt')
        assert 'deep/path/file.txt' in result
        assert result.startswith('/out')

    def test_decrypt_file_with_absolute_input_path(self, tmp_path):
        """Decrypting a file with absolute path should place output correctly."""
        output_dir = tmp_path / 'output'
        output_dir.mkdir()

        abs_input = os.path.abspath(CSENC_V1)
        out_path = files.safe_output_path(str(output_dir), os.path.basename(abs_input))

        files.decrypt_file(abs_input, out_path, password=PASSWORD)
        assert os.path.exists(out_path)
        with open(out_path, 'rb') as f:
            assert f.read() == PLAIN_CONTENT


# ---------------------------------------------------------------------------
# 6. Default output directory
# ---------------------------------------------------------------------------

class TestDefaultOutputDirectory:

    def test_docopt_default_output_is_output(self):
        """The default output directory should be 'output'."""
        import docopt
        doc = """
Usage:
  syndecrypt [-O <directory>] <input>...

Options:
  -O <directory> --output-directory=<directory>  Output directory [default: output]
"""
        args = docopt.docopt(doc, argv=['somefile.txt'])
        assert args['--output-directory'] == 'output'

    def test_decrypt_to_default_output_dir(self, tmp_path, monkeypatch):
        """Files should be decrypted to 'output' folder in cwd by default."""
        monkeypatch.chdir(tmp_path)
        output_dir = os.path.join(str(tmp_path), 'output')
        os.makedirs(output_dir)

        abs_input = _abs_test_path(CSENC_V1)
        out_path = files.safe_output_path(output_dir, 'file.txt')
        files.decrypt_file(abs_input, out_path, password=PASSWORD)

        result = os.path.join(output_dir, 'file.txt')
        assert os.path.exists(result)
        with open(result, 'rb') as f:
            assert f.read() == PLAIN_CONTENT

    def test_main_uses_default_output_dir(self, tmp_path, monkeypatch):
        """main() without -O should use 'output' as the output directory."""
        from syndecrypt.__main__ import main
        import getpass as getpass_mod

        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(getpass_mod, 'getpass', lambda p: PASSWORD_STR)

        abs_input = _abs_test_path(CSENC_V1)
        main(argv=[abs_input])

        expected = tmp_path / 'output' / os.path.basename(abs_input)
        assert expected.exists()
        assert expected.read_bytes() == PLAIN_CONTENT


# ---------------------------------------------------------------------------
# Integration: decrypt_stream_to_file
# ---------------------------------------------------------------------------

class TestDecryptStreamToFile:

    def test_decrypt_stream_to_file_basic(self, tmp_path):
        """decrypt_stream_to_file should write decrypted content."""
        out_path = str(tmp_path / 'result.txt')
        with open(CSENC_V1, 'rb') as instream:
            files.decrypt_stream_to_file(instream, out_path, password=PASSWORD)
        with open(out_path, 'rb') as f:
            assert f.read() == PLAIN_CONTENT

    def test_decrypt_stream_to_file_creates_dirs(self, tmp_path):
        """Parent directories should be created automatically."""
        out_path = str(tmp_path / 'a' / 'b' / 'c' / 'result.txt')
        with open(CSENC_V1, 'rb') as instream:
            files.decrypt_stream_to_file(instream, out_path, password=PASSWORD)
        with open(out_path, 'rb') as f:
            assert f.read() == PLAIN_CONTENT

    def test_decrypt_stream_to_file_skips_existing(self, tmp_path):
        """Should skip if output file already exists."""
        out_path = str(tmp_path / 'existing.txt')
        with open(out_path, 'wb') as f:
            f.write(b'pre-existing content')

        with open(CSENC_V1, 'rb') as instream:
            files.decrypt_stream_to_file(instream, out_path, password=PASSWORD)

        with open(out_path, 'rb') as f:
            assert f.read() == b'pre-existing content'

    def test_decrypt_stream_to_file_cleans_up_on_failure(self, tmp_path):
        """Output file should be removed on decryption failure."""
        out_path = str(tmp_path / 'failed.txt')
        bad_stream = io.BytesIO(CORRUPT_CSENC)
        with pytest.raises(Exception):
            files.decrypt_stream_to_file(bad_stream, out_path, password=PASSWORD)
        assert not os.path.exists(out_path)


# ---------------------------------------------------------------------------
# Summary output: success/failed counts
# ---------------------------------------------------------------------------

class TestSummaryOutput:

    def test_summary_all_succeeded_single_file(self, tmp_path, capsys):
        """Summary should show all succeeded for a single file."""
        from syndecrypt.__main__ import main

        output_dir = str(tmp_path / 'out')
        abs_input = _abs_test_path(CSENC_V1)
        pwd_file = _abs_test_path('tests/testfiles-secrets/password.txt')

        result = main(argv=['-p', pwd_file, '-O', output_dir, abs_input])

        captured = capsys.readouterr()
        assert 'Decrypted 1 file(s): all succeeded.' in captured.out
        assert result == {'succeeded': 1, 'failed': 0, 'skipped': 0}

    def test_summary_all_succeeded_directory(self, tmp_path, capsys):
        """Summary should count all files in a directory."""
        from syndecrypt.__main__ import main

        input_dir = tmp_path / 'enc'
        sub_dir = input_dir / 'sub'
        sub_dir.mkdir(parents=True)
        shutil.copy(CSENC_V1, str(input_dir / 'a.txt'))
        shutil.copy(CSENC_V3, str(sub_dir / 'b.txt'))

        output_dir = str(tmp_path / 'out')
        pwd_file = _abs_test_path('tests/testfiles-secrets/password.txt')

        result = main(argv=['-p', pwd_file, '-O', output_dir, str(input_dir)])

        captured = capsys.readouterr()
        assert 'Decrypted 2 file(s): all succeeded.' in captured.out
        assert result == {'succeeded': 2, 'failed': 0, 'skipped': 0}

    def test_summary_all_succeeded_zip(self, tmp_path, capsys):
        """Summary should count all entries in a zip."""
        from syndecrypt.__main__ import main

        zip_path = str(tmp_path / 'archive.zip')
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.write(CSENC_V1, 'f1.txt')
            zf.write(CSENC_V3, 'f2.txt')

        output_dir = str(tmp_path / 'out')
        pwd_file = _abs_test_path('tests/testfiles-secrets/password.txt')

        result = main(argv=['-p', pwd_file, '-O', output_dir, zip_path])

        captured = capsys.readouterr()
        assert 'Decrypted 2 file(s): all succeeded.' in captured.out
        assert result == {'succeeded': 2, 'failed': 0, 'skipped': 0}

    def test_summary_with_failures_zip(self, tmp_path, capsys):
        """Summary should show failed count when some files fail."""
        from syndecrypt.__main__ import main

        zip_path = str(tmp_path / 'mixed.zip')
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.write(CSENC_V1, 'good.txt')
            zf.writestr('bad.txt', CORRUPT_CSENC)

        output_dir = str(tmp_path / 'out')
        pwd_file = _abs_test_path('tests/testfiles-secrets/password.txt')

        result = main(argv=['-p', pwd_file, '-O', output_dir, zip_path])

        captured = capsys.readouterr()
        assert 'Decrypted 2 file(s): 1 succeeded, 1 failed.' in captured.out
        assert result == {'succeeded': 1, 'failed': 1, 'skipped': 0}

    def test_summary_with_failures_directory(self, tmp_path, capsys):
        """Summary should show failed count for bad files in a directory."""
        from syndecrypt.__main__ import main

        input_dir = tmp_path / 'enc'
        input_dir.mkdir()
        shutil.copy(CSENC_V1, str(input_dir / 'good.txt'))
        (input_dir / 'bad.txt').write_bytes(CORRUPT_CSENC)

        output_dir = str(tmp_path / 'out')
        pwd_file = _abs_test_path('tests/testfiles-secrets/password.txt')

        result = main(argv=['-p', pwd_file, '-O', output_dir, str(input_dir)])

        captured = capsys.readouterr()
        assert '1 succeeded, 1 failed.' in captured.out
        assert result['succeeded'] == 1
        assert result['failed'] == 1

    def test_summary_verify_mode(self, tmp_path, capsys):
        """Summary should say 'Verified' in verify mode."""
        from syndecrypt.__main__ import main

        abs_input = _abs_test_path(CSENC_V1)
        pwd_file = _abs_test_path('tests/testfiles-secrets/password.txt')

        result = main(argv=['-p', pwd_file, '--verify', abs_input])

        captured = capsys.readouterr()
        assert 'Verified 1 file(s): all succeeded.' in captured.out
        assert result == {'succeeded': 1, 'failed': 0, 'skipped': 0}

    def test_summary_verify_mode_with_failure(self, tmp_path, capsys):
        """Summary should count failures in verify mode."""
        from syndecrypt.__main__ import main

        # Create a corrupt file on disk
        bad_file = tmp_path / 'corrupt.bin'
        bad_file.write_bytes(CORRUPT_CSENC)

        abs_good = _abs_test_path(CSENC_V1)
        pwd_file = _abs_test_path('tests/testfiles-secrets/password.txt')

        result = main(argv=['-p', pwd_file, '--verify', abs_good, str(bad_file)])

        captured = capsys.readouterr()
        assert 'Verified 2 file(s): 1 succeeded, 1 failed.' in captured.out
        assert result == {'succeeded': 1, 'failed': 1, 'skipped': 0}

    def test_summary_verify_zip(self, tmp_path, capsys):
        """Summary should count zip entries in verify mode."""
        from syndecrypt.__main__ import main

        zip_path = str(tmp_path / 'archive.zip')
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.write(CSENC_V1, 'good.txt')
            zf.writestr('bad.txt', CORRUPT_CSENC)

        pwd_file = _abs_test_path('tests/testfiles-secrets/password.txt')

        result = main(argv=['-p', pwd_file, '--verify', zip_path])

        captured = capsys.readouterr()
        assert 'Verified 2 file(s): 1 succeeded, 1 failed.' in captured.out
        assert result == {'succeeded': 1, 'failed': 1, 'skipped': 0}


# ---------------------------------------------------------------------------
# 7. --archive / -a: rsync-style metadata preservation
# ---------------------------------------------------------------------------

class TestArchivePreservation:

    # Fixed reference time well in the past so it cannot collide with "now".
    REF_MTIME_NS = 1_262_400_000_000_000_000  # 2010-01-02 12:00:00 UTC in ns
    REF_ATIME_NS = 1_262_400_500_000_000_000  # 0.5s later

    def _stage_source(self, tmp_path, mode=0o640):
        """Copy a v1 csenc fixture into tmp_path with known mode/mtime/atime."""
        src = tmp_path / 'src.csenc'
        shutil.copy(CSENC_V1, str(src))
        os.chmod(str(src), mode)
        os.utime(str(src), ns=(self.REF_ATIME_NS, self.REF_MTIME_NS))
        return src

    def test_archive_preserves_mtime_for_file_input(self, tmp_path):
        src = self._stage_source(tmp_path)
        src_stat = os.stat(str(src))
        out_path = str(tmp_path / 'out' / 'src.csenc')
        files.decrypt_file(str(src), out_path, password=PASSWORD)
        files.apply_metadata_from_stat(src_stat, out_path)
        assert os.stat(out_path).st_mtime_ns == self.REF_MTIME_NS

    def test_archive_preserves_atime_for_file_input(self, tmp_path):
        src = self._stage_source(tmp_path)
        src_stat = os.stat(str(src))
        out_path = str(tmp_path / 'out' / 'src.csenc')
        files.decrypt_file(str(src), out_path, password=PASSWORD)
        files.apply_metadata_from_stat(src_stat, out_path)
        assert os.stat(out_path).st_atime_ns == self.REF_ATIME_NS

    def test_archive_preserves_mode_for_file_input(self, tmp_path):
        src = self._stage_source(tmp_path, mode=0o640)
        src_stat = os.stat(str(src))
        out_path = str(tmp_path / 'out' / 'src.csenc')
        files.decrypt_file(str(src), out_path, password=PASSWORD)
        files.apply_metadata_from_stat(src_stat, out_path)
        assert (os.stat(out_path).st_mode & 0o7777) == 0o640

    def test_archive_preserves_uid_gid_when_same_user(self, tmp_path):
        """When running as the same user, uid/gid are trivially preserved."""
        src = self._stage_source(tmp_path)
        src_stat = os.stat(str(src))
        out_path = str(tmp_path / 'out' / 'src.csenc')
        files.decrypt_file(str(src), out_path, password=PASSWORD)
        files.apply_metadata_from_stat(src_stat, out_path)
        out_st = os.stat(out_path)
        assert out_st.st_uid == src_stat.st_uid
        assert out_st.st_gid == src_stat.st_gid

    def test_archive_chown_failure_is_non_fatal(self, tmp_path, monkeypatch):
        """A PermissionError from chown must not raise; other metadata still applied."""
        src = self._stage_source(tmp_path)
        src_stat = os.stat(str(src))
        out_path = str(tmp_path / 'out' / 'src.csenc')
        files.decrypt_file(str(src), out_path, password=PASSWORD)

        def fake_chown(path, uid, gid):
            raise PermissionError('simulated lack of CAP_CHOWN')
        monkeypatch.setattr(os, 'chown', fake_chown)

        # Must not raise.
        files.apply_metadata_from_stat(src_stat, out_path)

        # mtime should still have been applied.
        assert os.stat(out_path).st_mtime_ns == self.REF_MTIME_NS
        assert os.path.exists(out_path)

    def test_archive_preserves_metadata_directory_input(self, tmp_path):
        """Full main() integration: --archive preserves mtime across a tree."""
        from syndecrypt.__main__ import main

        input_dir = tmp_path / 'enc'
        sub_dir = input_dir / 'sub'
        sub_dir.mkdir(parents=True)
        a = input_dir / 'a.txt'
        b = sub_dir / 'b.txt'
        shutil.copy(CSENC_V1, str(a))
        shutil.copy(CSENC_V3, str(b))
        os.utime(str(a), ns=(self.REF_ATIME_NS, self.REF_MTIME_NS))
        os.utime(str(b), ns=(self.REF_ATIME_NS, self.REF_MTIME_NS))
        os.chmod(str(a), 0o604)

        output_dir = tmp_path / 'out'
        pwd_file = _abs_test_path('tests/testfiles-secrets/password.txt')

        result = main(argv=['-a', '-p', pwd_file, '-O', str(output_dir), str(input_dir)])

        assert result == {'succeeded': 2, 'failed': 0, 'skipped': 0}
        out_a = output_dir / 'enc' / 'a.txt'
        out_b = output_dir / 'enc' / 'sub' / 'b.txt'
        assert out_a.exists() and out_b.exists()
        assert os.stat(out_a).st_mtime_ns == self.REF_MTIME_NS
        assert os.stat(out_b).st_mtime_ns == self.REF_MTIME_NS
        assert (os.stat(out_a).st_mode & 0o7777) == 0o604

    def test_archive_preserves_mtime_for_zip_input(self, tmp_path):
        """Zip entry mtime (2-second precision) is applied via main()."""
        from syndecrypt.__main__ import main

        zip_path = tmp_path / 'archive.zip'
        zinfo = zipfile.ZipInfo(filename='entry.txt', date_time=(2010, 1, 2, 12, 0, 0))
        with zipfile.ZipFile(str(zip_path), 'w') as zf:
            with open(CSENC_V1, 'rb') as f:
                zf.writestr(zinfo, f.read())

        output_dir = tmp_path / 'out'
        pwd_file = _abs_test_path('tests/testfiles-secrets/password.txt')

        result = main(argv=['-a', '-p', pwd_file, '-O', str(output_dir), str(zip_path)])
        assert result == {'succeeded': 1, 'failed': 0, 'skipped': 0}

        out_path = output_dir / 'entry.txt'
        assert out_path.exists()
        expected_ts = time.mktime((2010, 1, 2, 12, 0, 0, 0, 0, -1))
        # Zip stores 2-second granularity; allow that.
        assert abs(os.stat(out_path).st_mtime - expected_ts) <= 2

    def test_archive_preserves_mode_for_zip_input(self, tmp_path):
        """Unix mode bits from external_attr should be applied for zip input."""
        zinfo = zipfile.ZipInfo(filename='entry.txt', date_time=(2015, 6, 15, 9, 30, 0))
        zinfo.create_system = 3  # Unix
        zinfo.external_attr = (0o604 & 0o7777) << 16

        zip_path = tmp_path / 'archive.zip'
        with zipfile.ZipFile(str(zip_path), 'w') as zf:
            with open(CSENC_V1, 'rb') as f:
                zf.writestr(zinfo, f.read())

        out_path = str(tmp_path / 'out.txt')
        with zipfile.ZipFile(str(zip_path), 'r') as zf:
            with zf.open('entry.txt') as entry_stream:
                files.decrypt_stream_to_file(entry_stream, out_path, password=PASSWORD)
            files.apply_metadata_from_zipinfo(zf.getinfo('entry.txt'), out_path)

        assert (os.stat(out_path).st_mode & 0o7777) == 0o604

    def test_no_archive_does_not_copy_metadata(self, tmp_path):
        """Without --archive, source mtime should NOT be transferred to output."""
        from syndecrypt.__main__ import main

        src_dir = tmp_path / 'enc'
        src_dir.mkdir()
        src = src_dir / 'a.txt'
        shutil.copy(CSENC_V1, str(src))
        os.utime(str(src), ns=(self.REF_ATIME_NS, self.REF_MTIME_NS))

        output_dir = tmp_path / 'out'
        pwd_file = _abs_test_path('tests/testfiles-secrets/password.txt')

        # Note: no -a flag.
        main(argv=['-p', pwd_file, '-O', str(output_dir), str(src_dir)])

        out_path = output_dir / 'enc' / 'a.txt'
        assert out_path.exists()
        # Output mtime should be "now-ish" (within 1 day of now), nowhere near 2010.
        out_mtime = os.stat(out_path).st_mtime
        assert out_mtime > time.time() - 86400

    def test_archive_with_verify_is_noop(self, tmp_path, capsys):
        """--archive combined with --verify must produce no output files."""
        from syndecrypt.__main__ import main

        abs_input = _abs_test_path(CSENC_V1)
        pwd_file = _abs_test_path('tests/testfiles-secrets/password.txt')

        result = main(argv=['-a', '-p', pwd_file, '--verify', abs_input])
        assert result == {'succeeded': 1, 'failed': 0, 'skipped': 0}
        captured = capsys.readouterr()
        assert 'Verified 1 file(s): all succeeded.' in captured.out

    def test_archive_skips_when_output_pre_exists(self, tmp_path):
        """A pre-existing output file must not have its metadata overwritten."""
        from syndecrypt.__main__ import main

        src_dir = tmp_path / 'enc'
        src_dir.mkdir()
        src = src_dir / 'a.txt'
        shutil.copy(CSENC_V1, str(src))
        os.utime(str(src), ns=(self.REF_ATIME_NS, self.REF_MTIME_NS))

        output_dir = tmp_path / 'out'
        pre_existing = output_dir / 'enc' / 'a.txt'
        pre_existing.parent.mkdir(parents=True)
        pre_existing.write_bytes(b'do not touch')
        # Stamp a completely different, recognizable mtime on the pre-existing file.
        sentinel_mtime_ns = 1_500_000_000_000_000_000
        os.utime(str(pre_existing), ns=(sentinel_mtime_ns, sentinel_mtime_ns))

        pwd_file = _abs_test_path('tests/testfiles-secrets/password.txt')

        main(argv=['-a', '-p', pwd_file, '-O', str(output_dir), str(src_dir)])

        # File untouched: same content AND same mtime.
        assert pre_existing.read_bytes() == b'do not touch'
        assert os.stat(pre_existing).st_mtime_ns == sentinel_mtime_ns


# ---------------------------------------------------------------------------
# 8. --skip-larger-than / --skip-smaller-than: size-based exclusion
# ---------------------------------------------------------------------------

class TestSizeFiltersParseSize:

    def test_parse_size_plain_bytes(self):
        assert util.parse_size('0') == 0
        assert util.parse_size('1024') == 1024
        assert util.parse_size('1000000') == 1_000_000

    def test_parse_size_suffix_K(self):
        assert util.parse_size('1K') == 1024
        assert util.parse_size('1k') == 1024
        assert util.parse_size('500K') == 500 * 1024

    def test_parse_size_suffix_M_G_T(self):
        assert util.parse_size('1M') == 1024 ** 2
        assert util.parse_size('1G') == 1024 ** 3
        assert util.parse_size('1T') == 1024 ** 4

    def test_parse_size_float(self):
        assert util.parse_size('1.5K') == int(1.5 * 1024)
        assert util.parse_size('0.5M') == 1024 * 512

    def test_parse_size_strips_whitespace(self):
        assert util.parse_size('  1K  ') == 1024

    def test_parse_size_invalid_empty(self):
        with pytest.raises(ValueError):
            util.parse_size('')
        with pytest.raises(ValueError):
            util.parse_size(None)

    def test_parse_size_invalid_text(self):
        with pytest.raises(ValueError):
            util.parse_size('banana')
        with pytest.raises(ValueError):
            util.parse_size('5x')

    def test_parse_size_invalid_negative(self):
        with pytest.raises(ValueError):
            util.parse_size('-1K')


class TestSizeFilters:
    """End-to-end size-filter behavior via main().

    The small CSENC_V1 fixture is 158 bytes on disk. The large 'big.bin'
    fixtures here are zero-padded garbage; they pass the size filter but fail
    to decrypt (counted as 'failed' when not filtered, 'skipped' when filtered).
    Tests that need a definitely-decryptable file use CSENC_V1.
    """

    @staticmethod
    def _stage_dir(tmp_path, contents):
        """Stage files into tmp_path/'enc'/. contents = {name: bytes-or-source-path}."""
        d = tmp_path / 'enc'
        d.mkdir(parents=True)
        for name, source in contents.items():
            target = d / name
            target.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(source, (bytes, bytearray)):
                target.write_bytes(source)
            else:
                shutil.copy(source, str(target))
        return d

    def _csenc_size(self):
        return os.path.getsize(CSENC_V1)

    def test_larger_than_skips_oversize_file(self, tmp_path):
        from syndecrypt.__main__ import main

        src_dir = self._stage_dir(tmp_path, {
            'small.csenc': CSENC_V1,
            'big.bin': b'\x00' * 10_000,
        })
        output_dir = tmp_path / 'out'
        pwd_file = _abs_test_path('tests/testfiles-secrets/password.txt')

        result = main(argv=[
            '--skip-larger-than=1K', '-p', pwd_file,
            '-O', str(output_dir), str(src_dir),
        ])

        assert result == {'succeeded': 1, 'failed': 0, 'skipped': 1}
        assert (output_dir / 'enc' / 'small.csenc').exists()
        assert not (output_dir / 'enc' / 'big.bin').exists()

    def test_smaller_than_skips_undersize_file(self, tmp_path):
        from syndecrypt.__main__ import main

        src_dir = self._stage_dir(tmp_path, {
            'small.csenc': CSENC_V1,
            'big.bin': b'\x00' * 10_000,
        })
        output_dir = tmp_path / 'out'
        pwd_file = _abs_test_path('tests/testfiles-secrets/password.txt')

        # Threshold = 1K. small.csenc is < 1K, big.bin is > 1K.
        # small.csenc is skipped; big.bin is processed but fails decryption.
        result = main(argv=[
            '--skip-smaller-than=1K', '-p', pwd_file,
            '-O', str(output_dir), str(src_dir),
        ])

        assert result['skipped'] == 1
        assert result['failed'] == 1
        assert result['succeeded'] == 0
        assert not (output_dir / 'enc' / 'small.csenc').exists()

    def test_both_filters_combined(self, tmp_path):
        """Range [200, 5000] keeps only the file inside that window."""
        from syndecrypt.__main__ import main

        tiny = b'\x00' * 100
        mid = b'\x00' * 1000
        big = b'\x00' * 10_000

        src_dir = self._stage_dir(tmp_path, {
            'tiny.bin': tiny,
            'mid.bin': mid,
            'big.bin': big,
        })
        output_dir = tmp_path / 'out'
        pwd_file = _abs_test_path('tests/testfiles-secrets/password.txt')

        result = main(argv=[
            '--skip-larger-than=5000', '--skip-smaller-than=200',
            '-p', pwd_file, '-O', str(output_dir), str(src_dir),
        ])

        # Two skipped (tiny, big). One attempted (mid) — fails decryption.
        assert result['skipped'] == 2
        assert result['succeeded'] + result['failed'] == 1

    def test_boundary_is_kept_strict_comparison(self, tmp_path):
        """A file whose size exactly equals the threshold is NOT skipped."""
        from syndecrypt.__main__ import main

        csenc_bytes = open(CSENC_V1, 'rb').read()
        size_exact = len(csenc_bytes)

        src_dir = self._stage_dir(tmp_path, {'on_boundary.csenc': csenc_bytes})
        output_dir = tmp_path / 'out'
        pwd_file = _abs_test_path('tests/testfiles-secrets/password.txt')

        result = main(argv=[
            '--skip-larger-than=' + str(size_exact),
            '--skip-smaller-than=' + str(size_exact),
            '-p', pwd_file, '-O', str(output_dir), str(src_dir),
        ])

        # Strict comparison: size == threshold is processed, not skipped.
        assert result == {'succeeded': 1, 'failed': 0, 'skipped': 0}

    def test_no_filter_processes_all(self, tmp_path):
        """Without any size flags, behavior is unchanged."""
        from syndecrypt.__main__ import main

        src_dir = self._stage_dir(tmp_path, {'a.csenc': CSENC_V1})
        output_dir = tmp_path / 'out'
        pwd_file = _abs_test_path('tests/testfiles-secrets/password.txt')

        result = main(argv=['-p', pwd_file, '-O', str(output_dir), str(src_dir)])
        assert result == {'succeeded': 1, 'failed': 0, 'skipped': 0}

    def test_filters_apply_in_zip_input(self, tmp_path):
        from syndecrypt.__main__ import main

        zip_path = tmp_path / 'archive.zip'
        with zipfile.ZipFile(str(zip_path), 'w') as zf:
            zf.write(CSENC_V1, 'small.csenc')
            zf.writestr('big.bin', b'\x00' * 10_000)

        output_dir = tmp_path / 'out'
        pwd_file = _abs_test_path('tests/testfiles-secrets/password.txt')

        result = main(argv=[
            '--skip-larger-than=1K', '-p', pwd_file,
            '-O', str(output_dir), str(zip_path),
        ])

        assert result == {'succeeded': 1, 'failed': 0, 'skipped': 1}
        assert (output_dir / 'small.csenc').exists()
        assert not (output_dir / 'big.bin').exists()

    def test_filters_apply_in_verify_mode(self, tmp_path, capsys):
        """--verify still honors size filters — oversize files are skipped."""
        from syndecrypt.__main__ import main

        src_dir = self._stage_dir(tmp_path, {
            'small.csenc': CSENC_V1,
            'big.bin': b'\x00' * 10_000,
        })
        pwd_file = _abs_test_path('tests/testfiles-secrets/password.txt')

        result = main(argv=[
            '--verify', '--skip-larger-than=1K', '-p', pwd_file, str(src_dir),
        ])
        captured = capsys.readouterr()

        assert result['succeeded'] == 1
        assert result['failed'] == 0
        assert result['skipped'] == 1
        assert 'Verified' in captured.out
        assert 'excluded by --skip-larger-than' in captured.out

    def test_summary_includes_skipped_count(self, tmp_path, capsys):
        from syndecrypt.__main__ import main

        src_dir = self._stage_dir(tmp_path, {
            'small.csenc': CSENC_V1,
            'big.bin': b'\x00' * 10_000,
        })
        output_dir = tmp_path / 'out'
        pwd_file = _abs_test_path('tests/testfiles-secrets/password.txt')

        main(argv=[
            '--skip-larger-than=1K', '-p', pwd_file,
            '-O', str(output_dir), str(src_dir),
        ])
        captured = capsys.readouterr()
        assert '1 excluded by --skip-larger-than/--skip-smaller-than' in captured.out

    def test_invalid_size_arg_exits_with_message(self, tmp_path):
        """A malformed SIZE should cause a clean sys.exit, not a mid-run crash."""
        from syndecrypt.__main__ import main

        abs_input = _abs_test_path(CSENC_V1)
        pwd_file = _abs_test_path('tests/testfiles-secrets/password.txt')

        with pytest.raises(SystemExit) as exc_info:
            main(argv=['--skip-larger-than=banana', '-p', pwd_file,
                       '-O', str(tmp_path / 'out'), abs_input])
        msg = str(exc_info.value)
        assert '--skip-larger-than' in msg
        assert 'banana' in msg

    def test_single_file_input_honors_size_filter(self, tmp_path):
        """Size filter also works for a single-file input path."""
        from syndecrypt.__main__ import main

        oversize = tmp_path / 'big.bin'
        oversize.write_bytes(b'\x00' * 10_000)
        output_dir = tmp_path / 'out'
        pwd_file = _abs_test_path('tests/testfiles-secrets/password.txt')

        result = main(argv=[
            '--skip-larger-than=1K', '-p', pwd_file,
            '-O', str(output_dir), str(oversize),
        ])
        assert result == {'succeeded': 0, 'failed': 0, 'skipped': 1}
        assert not (output_dir / 'big.bin').exists()
