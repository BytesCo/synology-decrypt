import logging

LOGGER=logging.getLogger(__name__)

def _binary_contents_of(file_name):
        with open(file_name, 'rb') as f: return f.read()


_SIZE_SUFFIXES = {'K': 1024, 'M': 1024**2, 'G': 1024**3, 'T': 1024**4}

def parse_size(s):
        """Parse a size string like '1G', '500K', '1.5M', or '1024' (raw bytes)
        into an integer byte count. Suffixes K/M/G/T are binary (powers of 1024)
        and case-insensitive. Raises ValueError on malformed or negative input.
        """
        if s is None or s == '':
                raise ValueError('size must be non-empty')
        s = s.strip()
        suffix = s[-1].upper()
        if suffix in _SIZE_SUFFIXES:
                n = float(s[:-1]) * _SIZE_SUFFIXES[suffix]
        else:
                n = float(s)
        if n < 0:
                raise ValueError('size must be non-negative')
        return int(n)


# From http://code.activestate.com/recipes/410692/
# "Readable switch construction without lambdas or dictionaries"

# This class provides the functionality we want. You only need to look at
# this if you want to know how this works. It only needs to be defined
# once, no need to muck around with its internals.
class switch(object):
    def __init__(self, value):
        self.value = value
        self.fall = False

    def __iter__(self):
        """Return the match method once, then stop"""
        yield self.match
        # The original recipe #410692 also had
        #   raise StopIteration
        # but that is not working anymore in Python 3.7,
        # (see e.g., https://code.activestate.com/lists/python-ideas/52936/)
        # and doesn't seem to be necessary.

    def match(self, *args):
        """Indicate whether or not to enter a case suite"""
        if self.fall or not args:
            return True
        elif self.value in args: # changed for v1.5, see below
            self.fall = True
            return True
        else:
            return False


from subprocess import Popen, PIPE
import threading

class FilterSubprocess:
        """
        A wrapper around Popen(stdin=PIPE,stdout=PIPE) where stdout
        is sent to the provided callback handler.
        """

        def __init__(self, command_line, stdout_handler):
                self.stdout_handler = stdout_handler
                self.proc = Popen(args=command_line, stdin=PIPE, stdout=PIPE)
                self.handler_exception = None
                self.stdout_handler_thread = threading.Thread(target=self.stdout_handler_loop)
                self.stdout_handler_thread.start()

        def __enter__(self):
                return self

        def __exit__(self, exc_type, exc_value, traceback):
                self.close()

        def stdout_handler_loop(self):
                while True:
                        c = self.proc.stdout.read(1024)
                        if len(c) == 0: break
                        if self.handler_exception is not None:
                                # Already failed; keep draining so the subprocess can exit
                                # rather than blocking on a full stdout pipe buffer.
                                continue
                        try:
                                self.stdout_handler(c)
                        except Exception as e:
                                self.handler_exception = e

        def write(self, b):
                self.proc.stdin.write(b)

        def close(self):
                self.proc.stdin.close()
                self.stdout_handler_thread.join()
                if self.handler_exception is not None:
                        raise self.handler_exception


class Lz4Decompressor(FilterSubprocess):
        def __init__(self, decompressed_chunk_handler):
                FilterSubprocess.__init__(self, ['lz4', '-d'], stdout_handler=decompressed_chunk_handler)
