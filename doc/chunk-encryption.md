# Chunk encryption design document

This document describes the design and implementation of chunk encryption in
casync-nano. In this document, "casync" refers to the general family of casync
tools (like casync, desync and casync-nano). "casync-nano" refers to
casync-nano specifically.

## Rationale

casync-nano is primarily intended for distributing system images. System images
can contain secrets or other proprietary information, thus protecting them from
an attacker is important.

casync-based systems lend themselves to an architecture where the small index
file is distributed over a channel that is expensive (in terms of capacity),
but trustworthy (e.g. a mutually authenticated connection to some kind of
update server which supplies the device with a specific index file based on its
identity) and the large but immutable chunks are stored on a less-trusted (both
in terms of integrity and confidentiality) and possibly third-party system such
as a CDN.

In the following, we thus focus on the protection of the chunk data.

The integrity of individual chunks is already ensured relative to the integrity
of the index file since the checksum of each chunk is verified against the
index file after downloading it. Therefore, the integrity of the entire system
image is guaranteed if the integrity of the index file is ensured by some kind
of external mechanism that is out of scope for casync.

The "confidentiality" aspect however is not addressed by any casync
implementation at this time - chunks are stored unencrypted.

Even without access to the casync index file that specifies the selection/order
of chunks that comprise a given image, just being able to retrieve the bare
chunks can yield valuable information to an attacker since the minimum chunk
size is usually large (16 KiB) compared to the length of a secret, for example.
Furthermore, reasonable guesses as to which chunks were consecutive in the
source image can usually be made.

Access to the chunks themselves can of course be limited using the usual HTTP
authentication mechanisms at the chunk store. The hash-based addressing of a
chunk store also makes it more difficult to guess the URL of a chunk (if one
does not have access to the index file and directory listings are turned off,
of course). Nonetheless, this is brittle. Modern OTA mechanisms usually apply
end-to-end encryption to the images themselves to avoid having to trust the
storage or transmission layers.

Content-defined chunking allows the implementation of delta updates by
leveraging similarities between different revisions of the same system image.
This approach only works when the similarities are visible to the chunking
process, which precludes potentially desirable transformations of the source
image such as compressing it or encrypting it.

While casync resolves the compression issue by simply compressing the chunks
after they have been carved from the source image, there is no equivalent
mechanism for encrypting them. The rest of this document explores how to fill
this gap.

## Design considerations

The proposed scheme will encrypt chunks individually to preserve as much of the
original casync architecture as possible. Since the chunks in the chunk store
will normally be shared between different system image versions, running the
chunk generation process for different source images should not produce chunk
files that share the same ID but aren't usable for another images that also
nominally include the same chunk. In other words, each chunk must be encrypted
(and decryptable) independently from all the others.

Using authenticated encryption is considered the norm nowadays. Luckily, while
the devices casync-nano runs on are generally resource-constrained, modern,
fast AEAD constructions are [available][rfc8439] that don't require specific
hardware for speed or side-channel resistance. However, authentication
necessarily adds a (very minor) data overhead for the authentication tag and
complicates streaming processing of the data, since it either must be buffered
in full, verified and then decrypted before it can be processed further, or
subdivided into smaller chunks that are processed individually (see the
[age][age-spec] design for an implementation of this). Decrypting and passing
on the data *before* verifying the authentication tag violates the
[Cryptographic Doom Principle][moxie-crypto-doom] and is generally considered a
bad idea.

[rfc8439]: https://www.rfc-editor.org/rfc/rfc8439.html
[age-spec]: https://age-encryption.org/v1
[moxie-crypto-doom]: https://moxie.org/2011/12/13/the-cryptographic-doom-principle.html

In the following, we will, however, do just that, since it simplifies the
implementation a lot for the aforementioned reasons. There are mitigating
factors that limit the downside enough to make this a viable option, though:

 - The security model of casync-nano always has been that the index file is the
   source of truth of how the restored system image is supposed to look like.
   If the user performs out-of-band verification of the index file (via a
   cryptographic signature, for example), casync-nano guarantees that the
   resulting image corresponds to the index file. As described above, it does
   this by not trusting the chunk store in the first place and verifying that
   the hash of each downloaded chunk corresponds to the chunk ID before writing
   it to disk. In effect, this authenticates the data after all.

 - Thus, the only step that processes untrusted data is the zstd decompression
   that happens before this hashing step (since zstd compression is not
   necessarily reproducible, which would change the chunk ID and since it would
   require a superfluous compression step for determining the ID of locally
   sourced chunks on the target device even if it were).

   While a data compression library certainly is a potential exploit target,
   libzstd is already processing huge amounts of untrusted data on the web
   these days. It stands to reason that the remaining risk for vulnerabilities
   is small compared to the trouble of significantly complicating the
   encryption scheme (which carries its own implementation risks).

   Most notably however, all of this is already the case in the status quo
   design and adding a non-AEAD encryption step does not make it worse, it
   only neglects the opportunity to add a mitigation for it.

Taking all this into account, we are going to use XChaCha20 (the extension of
the XSalsa20 extended nonce construction to ChaCha20, see the expired I-D
[`draft-irtf-cfrg-xchacha-03`][xchacha20] or libsodium for a description) to
encrypt each chunk. The key is a global fixed parameter and the nonce is
derived from the chunk ID. We cannot use the chunk ID verbatim since SHA256
hashes are 256 bit long, but XChaCha20 nonces are only 192 bits long. Thus, the
192 bit prefix of the chunk ID is used as the nonce. This does not meaningfully
affect the security properties since XChaCha20 is meant to be used with random
nonces and practically, SHA256 hashes are random bit strings, so their prefixes
are random bit strings too.

[xchacha20]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-xchacha/03/

Each key/nonce combination can encrypt up to 256 GiB (64 bytes per block with a
32 bit counter) of data, which is plenty for a single chunk.

## Encryption scheme

A XChaCha20 instance is initialized using the encryption key set by the user
and by using the first 24 bytes of the chunk ID as the nonce. The block counter
starts at 0.

A compressed chunk is encrypted by performing a byte-wise XOR with the
generated keystream. Decryption is performed analogously.

An encrypted chunk uses the file extension `.cacnk.enc`, so a full path looks
like this: `/8a39/8a39d2abd3999ab73c34db2476849cddf303ce389b35826850f9a700589b4a90.cacnk.enc`.

## Security considerations

As discussed above, this is not an authenticated construction. XChaCha20 is a
stream cipher so the encrypted blocks are trivially malleable. However,
integrity of the restored system image is indirectly assured through the
cryptographic hashes present in the index files.

Confidentiality of the contents individual chunks is protected and while this
is a necessary precondition for protecting the confidentiality of the *entire*
system image, it is not sufficient to achieve it: The chunk file name leaks the
hash of its unencrypted contents, which can give an attacker information about
the contents for certain well-known data. An attacker can also prove the
presence of data larger than a single chunk in the image by experimentally
chunking it and checking if a chunk with that hash exists in the chunk store or
the index file.

These issues can be somewhat mitigated for example by also tying the chunk ID
to a key (for example using a construction such as HMAC or a hash function with
a keyed mode such as BLAKE2). However:

 - Changing the way chunk IDs are computed presents a significant break from
   the existing casync ecosystem as it requires changes to the caibx file
   format.

 - The information leak introduced here is limited. The likelihood that an
   attacker is able to derive more precise information than what was described
   above is relatively slim and this is sufficient to make extracting secrets
   or reverse-engineering the system much harder.

 - Obfuscation of the chunk IDs as described above can be implemented
   independently of chunk encryption.

Thus, we postpone this topic for a future extension.

Furthermore, even after encryption, an attacker can still learn the compressed
size and (if they have the index file) the sequence of chunks, which also
reveals some information about the plain text.

## Test vectors

See the test vectors in [`draft-irtf-cfrg-xchacha-03`][xchacha20] for the
XChaCha20 implementation.

For a concrete example of the casync-nano usage, consider the following chunk:

```
00000000  28 b5 2f fd 00 58 54 00  00 10 00 00 01 00 fb ff
00000010  39 c0 02 02 00 10 00 01  00 00
```

This is the compressed version of the 256 KiB all-zero chunk. It has the ID
`8a39d2abd3999ab73c34db2476849cddf303ce389b35826850f9a700589b4a90`. Thus, the
nonce is:

```
00000000  8a 39 d2 ab d3 99 9a b7  3c 34 db 24 76 84 9c dd
00000010  f3 03 ce 38 9b 35 82 68
```

Encrypting this chunk with the key `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
yields:

```
00000000  e8 da 60 0a 95 61 93 c3  4f d4 9a 77 bf 48 da 84
00000010  8f 5f ff c1 78 66 61 cb  7a e4
```

Since this chunk is shorter than a single ChaCha20 block, it is more
instructive to look at the corresponding keystream. The first 128 bytes (of
which 26 are used in the example above) of the keystream are:

```
00000000  c0 6f 4f f7 95 39 c7 c3  4f c4 9a 77 be 48 21 7b
00000010  b6 9f fd c3 78 76 61 ca  7a e4 88 12 c9 e0 28 3e
00000020  f3 9d 9b 3d 51 f4 f7 fd  cf a9 9e ea d7 a3 80 12
00000030  9a cb 33 1f 5b 6d 39 e8  4b 09 0b 57 39 01 08 29
00000040  81 7c 56 33 01 5b 44 41  e2 29 80 93 24 cd ea 57
00000050  39 df f8 a5 5d cc d7 33  a2 e7 41 36 b9 26 be 36
00000060  f0 4a f4 22 58 77 9e 01  c1 20 5d 8b 00 a5 cb 9b
00000070  20 2d f3 13 eb c4 73 f7  a5 fc 28 ef c3 c6 b6 91
```
