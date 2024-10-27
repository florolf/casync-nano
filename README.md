# casync-nano

casync-nano is a feature-reduced replacement for casync aimed at
embedded targets. It only supports `extract` operations, the `.caibx`
file format and limits hashing to SHA256 hashes, but in turn tries to be
light on dependencies and system resources in operation.

It implements enough of the regular casync CLI to work as a drop-in
replacement in the casync mode of [RAUC](https://rauc.io/).

See the [man page](doc/csn.1.scd) for more details.

## Scope

casync-nano is meant to be used as part of an image-based differential
update mechanism for embedded devices. As such, it leaves out features
such as filesystem images (`.caidx`) and image generation/management. On
the other hand, it has some features that the original casync
implementation lacks:

  * Caching of index files corresponding to a local chunk store ("seed"
    in casync terminology). This is useful to avoid slow reindexing of
    a partition in an A/B update scheme where the active partition is
    read-only and thus corresponds to the index file that created it
    during the previous update by definition. (Chunks read from such a
    store are still validated to address unintentional changes and
    bit rot)
  * Support for the kernel crypto API to accelerate hashing operations
    using hardware mechanisms that are present on many modern SoCs.
  * Support for encrypting chunks so that they can be stored on untrusted
    third-party HTTP infrastructure. (Still considered experimental, but
    usable/in use already and unlikely to change. See
    [here](doc/chunk-encryption.md) for more details).
  * Vastly reduced memory usage

## State

casync-nano is stable and is actively being used in the field.

Currently, casync-nano only supports reading from and writing to block devices
(such as eMMC storage).

## Dependencies
  * libcurl
  * openssl
  * zstd
