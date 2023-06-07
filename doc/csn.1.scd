CSN(1)

# NAME

csn - casync-nano

# SYNOPSIS

*csn* _INDEX_ _TARGET_ _STORE_...++
*casync* [--store _HTTP_URL_...] [--seed _PATH_] [--seed-output _YESNO_] *extract* _INDEX_ _TARGET_

# DESCRIPTION

casync-nano is a feature-reduced replacement for casync intended as a building
block for implementing image-based differential updates on embedded systems. To
that end, the only operation it supports is the extraction of .caibx files that
utilize SHA256 hashes. On the other hand, it has some features that help in its
intended application compared to the original casync tool:

- Side-loading of index files corresponding to a local source of chunks.
  This is useful to avoid slow reindexing of a partition in an A/B update
  scheme (see OPERATION and EXAMPLES below).
- Support for the kernel crypto API to accelerate hashing operations using
  hardware mechanisms that are present on many modern SoCs.
- Vastly reduced memory usage.

casync-nano is a multi-call binary and provides a compatibility layer that
implements a subset of the _casync_(1) *extract* command to the extent necessary
to support tools such as RAUC when called as casync and presents its own
interface when called as *csn*.

# OPTIONS

_INDEX_
	Specifies the .caibx file that describes the image to be extracted.

_TARGET_
	Specifies where the extracted image will be written to. This will normally
	be a block device. casync-nano currently does not support writing to MTD
	devices.

	As a safety mechanism, casync-nano will refuse to create _TARGET_ when it
	does not exist. To extract an image to a regular file, create an empty file
	first.

_STORE_
	A generic source of chunks. This can either be a HTTP(S) URL pointing
	towards a casync-style chunk store or a path to a local file or block device
	that will be broken apart into chunks. (See OPERATION below for more details
	on how the synchronization process works).

	A local store specification may optionally be followed by a colon and the
	path to a .caibx file representing the contents of that local store. If
	supplied, this index will be used instead of running the chunking algorithm
	on the local store, which is computationally expensive. Such a side-loaded
	index will be verified such that if it is incorrect for whatever reason
	(e.g. if the local store has bit-rotted or the .caibx simply doesn't match
	the contents), it will be discarded and the synchronization process
	continues as if it hadn't been specified at all.

	Normally, when a chunk appears multiple times in _INDEX_, casync-nano will
	query its stores for it multiple times. Thus, if it is not contained in a
	local store, it will be downloaded over the network multiple times. While
	this sounds problematic, it empirically does not really happen in practice
	in the cases which casync-nano is intended for (since such a redundant
	chunk will usually already have been redundant in the previous version of
	the image and will thus be present in a local store). Still, if you are
	concerned about this possibility, you can also supply _TARGET_ as an
	additional _STORE_. This triggers some special logic that will prevent this
	problem by reusing chunks that have been written to _TARGET_ already. Note
	however that because of the data structures involved, this currently
	carries a moderate performance penalty.

	During synchronization, the specified stores are queried in the order given
	on the command line. Thus, local stores should appear first.

The casync compatibility layer accepts getopt-style arguments that map to the
concepts above: Both --store and --seed are equivalent to specifying a _STORE_.
The --seed-output option is ignored to avoid incurring a warning when used with
RAUC.

When the _CSN_KCAPI_DRIVER_ environment variable is set, that particular
algorithm specifier/driver of the Linux kernel crypto API is used for
calculating SHA256 checksums (via the _AF_ALG_ mechanism). Note that this might
actually be slower than using the default user space software implementation
depending on your hardware. Please run a benchmark before using this in your
application.

# OPERATION

casync and casync-nano use Content-Defined Chunking (CDC) to split large files
such as disk images into smaller chunks in way that (statistically) produces the
same chunks even when content moves within the file. This affords a way to
transfer different versions of the same file efficiently by only transferring a
list of the chunks in the new version and their order to the target. If the
target has an older version of the same file available locally, it stands to
reason that a large percentage of the chunks will have remained the same. Thus,
only the missing ones need to be downloaded, saving a significant amount of
bandwidth.

The advantage of this approach compared to other binary delta systems is that it
is generic and very simple to reason about, does not require generation of
deltas between each pair of possible versions and allows archiving of old
versions with little marginal storage cost. The downside is that the effective
deltas (i.e. the amount of bytes a client has to download) will likely be larger
than the ones produced by more specialized binary delta systems.

casync-nano implements the exact same chunking algorithm as casync. The only
parameters of that algorithm are the minimum, target average and maximum chunk
sizes (in practice, these are always set to the default values of 16, 64 and 256
KiB, respectively). Given the same set of parameters, all implementations of
this algorithm will always produce the exact same set of chunks for a given
input file.

Chunks are identified by their SHA256 checksum, which provides protection
against corruption and also cryptographically binds the output of a
synchronization process to the input index that produced it. For each chunk that
it retrieves, casync-nano verifies that the contents actually hash to the chunk
id. This means that authenticating the .caibx file (for example through some
kind of signature) implicitly authenticates the output image. This check is also
performed for local stores to prevent bit-rot.

When starting up, casync-nano runs the chunking algorithm using the parameters
specified in the .caibx file on all local stores that were supplied on the
command line. Since this process is computationally expensive, it also allows
the user to supply the (supposed) result of this process externally by passing
an auxiliary .caibx file for each store (casync-nano calls this "side-loading").

The idea here is that the most common application of casync-nano will be an OTA
update system that uses an A/B partition scheme where one partition is the one
the system will currently be executing from and the other one is the one that
will contain the new system image at the end of the synchronization process.
Crucially, the current system partition usually is read-only for resilience
reasons and is thus unmodified from when it was originally created. This means
that since the _current_ system image usually also is the result of a previous
OTA update, we could have saved the .caibx file that produced it on mutable
storage somewhere and supply it for the current synchronization run, avoiding
recomputing the chunk boundaries.

HTTP chunk stores are expected to follow the casync store structure, that is:
- Individual chunks correspond to individual files
- Each file is compressed using the zstd algorithm and named "_HASH_.cacnk"
  where _HASH_ is the lower-case hexadecimal representation of the SHA256 hash
  of the _uncompressed_ chunk.
- Each file is placed in a directory below the root that corresponds to the
  first four characters of its file name.

E.g. the path corresponding to an 256 KiB long all-zero-byte chunk would be
/8a39/8a39d2abd3999ab73c34db2476849cddf303ce389b35826850f9a700589b4a90.cacnk.

casync-nano aims to be resilient in face of the various issues that can occur on
systems that have unstable or intermittent connectivity:
- HTTP chunk downloads are retried a number of times using exponential backoff
  if they or the network fail transiently.
- If a given HTTP store has incurred a number of transient failures that
  couldn't be recovered from, it is disabled to avoid hammering it excessively.
- casync-nano checks the content that is already present on the target and skips
  any prefix that has already been synchronized, which allows resuming a
  synchronization process that has been interrupted, ensuring forward progress.

In general, casync-nano does not cache individual chunks in memory or elsewhere
to avoid unpredictable memory usage. Chunks are always retrieved from the
specified stores on demand. The only exception is that the previously retrieved
chunk is reused if it repeats in the .caibx file. This happens during long runs
of null bytes, for example. Benchmarking has shown that this is generally
sufficient for the intended applications of casync-nano.

# EXAMPLES

Extract image.caibx to /dev/mmcblk0p3, downloading all chunks from example.com:

	csn image.caibx /dev/mmcblk0p3 https://example.com

Same as before, but avoid downloading chunks multiple times by using the
partially-written-to target as a cache:

	csn image.caibx /dev/mmcblk0p3 /dev/mmcblk0p3 https://example.com

Extract image.caibx to /dev/mmcblk0p3, using both example.com and
/dev/mmcblk0p2 as sources for chunks, preferring to use /dev/mmcblk0p2 if
possible. Furthermore, assume old.caibx was used to create /dev/mmcblk0p2
previously:

	csn image.caibx /dev/mmcblk0p3 /dev/mmcblk0p2:old.caibx https://example.com

The latter is the most common application for casync-nano.

Since casync-nano does not provide a mechanism to generate .caibx files or the
corresponding chunk stores, the original casync tool has to be used for that
purpose:

	casync make --digest=sha256 image.caibx image.img

# LIMITATIONS

Indices are internally implemented using sorted arrays and binary search. This
is fine for static indices, but when using the target as a store (which is
continuously updated during synchronization), it causes a certain amount of
overhead. However, since this is more of a niche use case, as of now, it does
not really justify adding a more complex/expensive data structure for the other
cases as well.

# BUG REPORTS

Please report bugs in casync-nano or errors in this manual page via GitHub
(https://github.com/florolf/casync-nano/issues) or email (_fl@n621.de_).

The casync compatibility layer only targets RAUC right now. Any incompatibility
is considered a bug. If you encounter any problems or use another update
orchestration system that requires broader casync emulation, please report a
bug.

# SEE ALSO
_casync_(1)++
_RAUC_ (https://rauc.io/)
