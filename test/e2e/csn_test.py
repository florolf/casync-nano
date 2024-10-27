import pytest
import hashlib
import pyzstd
import re
import subprocess
import tempfile
import logging

from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from pathlib import Path
from typing import ClassVar, Iterable, List, Self, Dict, Union, Optional
from collections import defaultdict

from Crypto.Cipher import ChaCha20

class Chunk:
    def __init__(self, data: bytes):
        self.data = data
        self.digest = hashlib.sha256(data).digest()

    @property
    def hexdigest(self) -> str:
        return self.digest.hex()

    @classmethod
    def make(cls, size: int, start_byte: bytes = b"\x00") -> Self:
        """
        Create a bytestring that when chunked with the default parameters ends
        up as exactly one chunk.

        This works because the 48-byte sequence (i.e. one buzhash window) "XX
        00 00 00 ..." never produces a break and "00 00 00 ... 05 8b" always
        does.
        """

        assert 16*1024 <= size <= 256*1024
        assert len(start_byte) == 1

        # Special case: This is a max-sized chunk so we'll always get a
        # break-point here. We could of course just use the break pattern as
        # for all other sizes, but let's exercise this code path as well.
        if size == 256*1024:
            return cls(start_byte + b"\x00" * (size-1))

        break_pattern = b"\x00" * 46 + b"\x05\x8b"

        return cls(start_byte +
                   b"\x00" * (size-1-48) +
                   break_pattern)

class ChunkRequestHandler(BaseHTTPRequestHandler):
    request_count: ClassVar[defaultdict[str, int]] = defaultdict(int)
    misses: ClassVar[Dict[str, int]] = defaultdict(int)

    data: ClassVar[Dict[str, Chunk]] = {}
    encryption_key: ClassVar[Optional[bytes]] = None

    CHUNK_PATH_PATTERN = re.compile(r"/([0-9a-f]{4})/(\1[0-9a-f]{60})\.(.*)")

    def do_GET(self):
        m = self.CHUNK_PATH_PATTERN.fullmatch(self.path)
        if not m:
            self.send_error(404)
            return

        expected_ext = "cacnk"
        if self.__class__.encryption_key is not None:
            expected_ext = "cacnk.enc"

        _, cid, ext = m.groups()
        if cid not in self.__class__.data or ext != expected_ext:
            self.__class__.misses[cid] +=1

            self.send_error(404)
            return

        self.__class__.request_count[cid] += 1

        self.send_response(200)
        self.end_headers()

        chunk = self.__class__.data[cid]

        data = pyzstd.compress(chunk.data)
        if self.__class__.encryption_key is not None:
            cipher = ChaCha20.new(
                key=self.__class__.encryption_key,
                nonce=chunk.digest[0:24]
            )

            data = cipher.encrypt(data)

        self.wfile.write(data)

    @classmethod
    def reset(cls):
        cls.misses.clear()
        cls.request_count.clear()
        cls.data = {}
        cls.encryption_key = None

    @classmethod
    def set_data(cls, chunks: Iterable[Chunk]):
        cls.data = {
            chunk.hexdigest: chunk for chunk in chunks
        }

    @classmethod
    def set_encryption(cls, key: bytes):
        cls.encryption_key = key

class Target:
    def __init__(self, size: int):
        self.f = tempfile.NamedTemporaryFile(mode='wb+', suffix='.img')
        self.f.truncate(size)
        self.size = size

    def write(self, data: bytes, pos: int = 0):
        assert pos + len(data) <= self.size

        self.f.seek(pos)
        self.f.write(data)
        self.f.flush()

    def path(self) -> Path:
        return Path(self.f.name)

    def write_chunks(self, chunks: List[Chunk]):
        self.f.seek(0)
        for chunk in chunks:
            self.f.write(chunk.data)

        self.f.flush()

    def check_chunks(self, chunks: List[Chunk]) -> bool:
        self.f.seek(0)
        offset = 0

        for chunk in chunks:
            l = len(chunk.data)

            td = self.f.read(l)
            if td != chunk.data:
                logging.error('chunk mismatch at offset %d', offset)
                return False

            offset += l

        return True

def make_caibx(chunks: List[Chunk]) -> tempfile.NamedTemporaryFile:
    f = tempfile.NamedTemporaryFile(mode='wb+', suffix='.caibx')

    words: List[Union[int, bytes]] = []

    # index header
    words.extend([
        0x30, # length
        0x96824d9c7b129ff9, # magic
        0x9000000000000000, # flags
        16*1024, 64*1024, 256*1024 # min/avg/max chunk size
    ])

    # table
    words.extend([
        0xffffffffffffffff, # indefinite length
        0xe75b9e112f17417d, # magic
    ])

    offset = 0
    for chunk in chunks:
        offset += len(chunk.data)
        words.append(offset)
        words.append(chunk.digest)

    # footer
    words.extend([
        0, 0,
        0x30, # table offset
        16 + (len(chunks)+1) * 40,
        0x4b4f050e5549ecd1 # end marker
    ])

    for word in words:
        if type(word) is int:
            f.write(word.to_bytes(length=8, byteorder='little'))
        elif type(word) is bytes:
            f.write(word)

    f.flush()

    return f

@pytest.fixture(scope='module')
def chunk_server():
    httpd = HTTPServer(("", 8080), ChunkRequestHandler)

    server_thread = Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()

    yield httpd

    httpd.shutdown()

def run_csn(caibx: Path, target: Target,
            local_store: Optional[Target] = None, local_index: Optional[Path] = None,
            http_store: bool = False, http_store_attr: Optional[Dict[str, str]] = None,
            should_fail: bool = False):

    cmd = ['csn', str(caibx), str(target.path())]
    if local_store:
        if local_index:
            cmd.append('%s:%s' % (str(local_store.path()), str(local_index)))
        else:
            cmd.append(str(local_store.path()))

    if http_store:
        url = 'http://127.0.0.1:8080'
        if http_store_attr:
            url += '#'
            for k, v in sorted(http_store_attr.items()):
                url += '%s=%s' % (k, v)

        cmd.append(url)

    result = subprocess.run(cmd)
    if should_fail:
        assert result.returncode != 0
    else:
        assert result.returncode == 0

def test_regular(chunk_server):
    """
    Baseline test just using a single HTTP source
    """

    del chunk_server

    chunks = [
        Chunk.make(32*1024, start_byte = b'\x01'),
        Chunk.make(32*1024+1, start_byte = b'\x02'),
        Chunk.make(256*1024),
        Chunk.make(32*1024, start_byte = b'\x03'),
    ]

    ChunkRequestHandler.reset()
    ChunkRequestHandler.set_data(chunks)

    caibx = make_caibx(chunks)

    t = Target(1024*1024)
    run_csn(Path(caibx.name), t, http_store=True)
    assert t.check_chunks(chunks)

def test_regular_encrypted(chunk_server):
    """
    test_regular, but with chunk encryption
    """

    del chunk_server

    chunks = [
        Chunk.make(32*1024, start_byte = b'\x01'),
        Chunk.make(32*1024+1, start_byte = b'\x02'),
        Chunk.make(256*1024),
        Chunk.make(32*1024, start_byte = b'\x03'),
    ]

    key = bytearray()
    key.extend(range(0, 32))
    key = bytes(key)

    ChunkRequestHandler.reset()
    ChunkRequestHandler.set_data(chunks)
    ChunkRequestHandler.set_encryption(key)

    caibx = make_caibx(chunks)

    t = Target(1024*1024)
    run_csn(Path(caibx.name), t, http_store=True, http_store_attr={
        'encrypt': 'key:' + key.hex()
    })
    assert t.check_chunks(chunks)

def test_resumption(chunk_server):
    """
    Make sure that resuming a synchronization process does not redundantly
    fetch data
    """

    del chunk_server

    chunks = [
        Chunk.make(32*1024, start_byte = b'\x01'),
        Chunk.make(32*1024, start_byte = b'\x02'),
        Chunk.make(32*1024, start_byte = b'\x03'),
    ]

    ChunkRequestHandler.reset()
    ChunkRequestHandler.set_data(chunks[2:])

    caibx = make_caibx(chunks)

    t = Target(1024*1024)

    # Simulate a partial update where the first two chunks have already been
    # written.
    t.write_chunks(chunks[0:2])

    run_csn(Path(caibx.name), t, http_store=True)
    assert t.check_chunks(chunks)

def test_no_repeated_fetch(chunk_server):
    """
    Chunks that are repeated consecutively should not incur HTTP fetches
    """

    del chunk_server

    duplicate = Chunk.make(32*1024, start_byte = b'\x03')
    chunks = [
        Chunk.make(32*1024, start_byte = b'\x01'),
        Chunk.make(32*1024, start_byte = b'\x02'),
        duplicate,
        duplicate
    ]

    ChunkRequestHandler.reset()
    ChunkRequestHandler.set_data(chunks)

    caibx = make_caibx(chunks)

    t = Target(1024*1024)
    run_csn(Path(caibx.name), t, http_store=True)
    assert t.check_chunks(chunks)

    assert ChunkRequestHandler.request_count[duplicate.hexdigest] == 1

def test_target_as_source(chunk_server):
    """
    When using the target as a source too, even non-consecutive chunk
    repetitions should not incur HTTP fetches
    """

    del chunk_server

    duplicate = Chunk.make(32*1024, start_byte = b'\x03')
    chunks = [
        Chunk.make(32*1024, start_byte = b'\x01'),
        duplicate,
        Chunk.make(32*1024, start_byte = b'\x02'),
        duplicate
    ]

    ChunkRequestHandler.reset()
    ChunkRequestHandler.set_data(chunks)

    caibx = make_caibx(chunks)

    t = Target(1024*1024)
    run_csn(Path(caibx.name), t, http_store=True, local_store=t)
    assert t.check_chunks(chunks)

    assert ChunkRequestHandler.request_count[duplicate.hexdigest] == 1

def test_chunk_corruption(chunk_server):
    """
    Make sure casync-nano catches server-side chunk corruption
    """

    del chunk_server

    chunks = [
        Chunk.make(32*1024, start_byte = b'\x01'),
        Chunk.make(32*1024, start_byte = b'\x02'),
        Chunk.make(32*1024, start_byte = b'\x03'),
    ]

    ChunkRequestHandler.reset()
    ChunkRequestHandler.set_data(chunks)

    caibx = make_caibx(chunks)

    # Corrupt the chunk data so that the server provides data that is
    # compressed correctly and of the correct length, but doesn't match its
    # checksum.
    chunks[0].data = b'\xaa' * 32 * 1024

    t = Target(1024*1024)
    run_csn(Path(caibx.name), t, http_store=True, should_fail=True)

def test_ab_regular(chunk_server):
    """
    Test that the common A/B update path only fetches changed chunks
    """

    del chunk_server

    chunks_a = [
        Chunk.make(256*1024, start_byte = b'\x01'),
        Chunk.make(32*1024, start_byte = b'\x02'),

        Chunk.make(32*1024, start_byte = b'\x03'),
    ]

    chunks_b = [
        Chunk.make(256*1024, start_byte = b'\x01'),
        Chunk.make(32*1024, start_byte = b'\x02'),

        Chunk.make(32*1024, start_byte = b'\x04'),
    ]

    ChunkRequestHandler.reset()
    ChunkRequestHandler.set_data(chunks_b[-1:])

    local = Target(1024*1024)
    local.write_chunks(chunks_a)

    caibx = make_caibx(chunks_b)

    t = Target(1024*1024)
    run_csn(Path(caibx.name), t, local_store=local, http_store=True)
    assert t.check_chunks(chunks_b)

def test_ab_sideload(chunk_server):
    """
    Same as test_ab_regular but with sideloading the index
    """

    del chunk_server

    chunks_a = [
        Chunk.make(256*1024, start_byte = b'\x01'),
        Chunk.make(32*1024, start_byte = b'\x02'),

        Chunk.make(32*1024, start_byte = b'\x03'),
    ]

    chunks_b = [
        Chunk.make(256*1024, start_byte = b'\x01'),
        Chunk.make(32*1024, start_byte = b'\x02'),

        Chunk.make(32*1024, start_byte = b'\x04'),
    ]

    ChunkRequestHandler.reset()
    ChunkRequestHandler.set_data(chunks_b[-1:])

    local = Target(1024*1024)
    local.write_chunks(chunks_a)

    caibx_a = make_caibx(chunks_a)
    caibx_b = make_caibx(chunks_b)

    t = Target(1024*1024)
    run_csn(Path(caibx_b.name), t, local_store=local,
            local_index=Path(caibx_a.name), http_store=True)
    assert t.check_chunks(chunks_b)

def test_ab_sideload_bitrot(chunk_server):
    """
    Same as test_ab_sideload but simulate bitrot in the local chunk store
    """

    del chunk_server

    chunks_a = [
        Chunk.make(32*1024, start_byte = b'\x01'),
        Chunk.make(32*1024, start_byte = b'\x02'),

        Chunk.make(32*1024, start_byte = b'\x03'),
    ]

    chunks_b = [
        Chunk.make(32*1024, start_byte = b'\x01'),
        Chunk.make(32*1024, start_byte = b'\x02'),

        Chunk.make(32*1024, start_byte = b'\x04'),
    ]

    ChunkRequestHandler.reset()
    ChunkRequestHandler.set_data([chunks_b[0], chunks_b[2]])

    local = Target(1024*1024)
    local.write_chunks(chunks_a)

    # corrupt the first chunk
    local.write(b'\xde\xad\xbe\xef', 100)

    caibx_a = make_caibx(chunks_a)
    caibx_b = make_caibx(chunks_b)

    t = Target(1024*1024)
    run_csn(Path(caibx_b.name), t, local_store=local,
            local_index=Path(caibx_a.name), http_store=True)
    assert t.check_chunks(chunks_b)
