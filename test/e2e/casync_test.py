import filecmp
import subprocess
import tempfile
import hashlib
import http.server

from pathlib import Path
from typing import IO
from threading import Thread

from csn_test import Target, run_csn

def write_reproducible_random(f: IO[bytes], size: int, seed: bytes):
    assert size % 32 == 0

    for i in range(0, size, 32):
        chunk = hashlib.sha256(seed + i.to_bytes(length = 8, byteorder = 'little')).digest()
        f.write(chunk)

    f.flush()

def test_casync_interop():
    """
    Generate a caibx file using the regular casync tool, run a synchronization
    using csn and check that the results match.
    """

    source_image = tempfile.NamedTemporaryFile()
    write_reproducible_random(source_image, 1024*1024, b'dummy image')

    casync_dir = tempfile.TemporaryDirectory()
    subprocess.run(['casync', 'make', '--digest=sha256', 'img.caibx', source_image.name],
                   cwd=casync_dir.name,
                   stdout=subprocess.DEVNULL
    ).check_returncode()

    class Server(http.server.HTTPServer):
        def finish_request(self, request, client_address):
            chunk_dir = Path(casync_dir.name) / 'default.castr'
            self.RequestHandlerClass(request, client_address, self,
                                     directory=str(chunk_dir))

    httpd = Server(("", 8080), http.server.SimpleHTTPRequestHandler)
    server_thread = Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()

    t = Target(1024*1024)
    try:
        run_csn(Path(casync_dir.name) / 'img.caibx', t, http_store=True)
    finally:
        httpd.shutdown()

    assert filecmp.cmp(t.path(), source_image.name)
