CSN-TOOL(1)

# NAME

csn-tool - casync-nano helper tool

# SYNOPSIS

*csn-tool* crypt _KEYSPEC_ _INPUT_PATH_ [_OUTPUT_PATH_]

# DESCRIPTION

csn-tool is a helper tool that contains functionality that is useful for
managing casync-nano based infrastructure, but is not needed on the target
device itself.

# COMMANDS

*csn-tool* crypt _KEYSPEC_ [_INPUT_PATH_] [_OUTPUT_PATH_]

Performs encryption and decryption of chunks. Since the chunk encryption
algorithm in casync-nano is self-inverse, both operations are executed using
the same command. To avoid repetition, only the term "encryption" is used in
this section.

_KEYSPEC_ describes how the encryption key is obtained. In each case, the 32
byte key is represented in hexadecimal. Possible values for _KEYSPEC_ are:

- _key:HEXSTRING_ - supplies the key literally through the command line. The
  usual caveats about this making it visible to other processes on the system
  apply.
- _env:NAME_ - read the key from the environment variable _NAME_
- _file:PATH_ - read the key from the file at _PATH_

The file name at _INPUT_PATH_ must follow the casync naming convention (namely,
its 32 byte chunk ID in hexadecimal followed by .cacnk or .cacnk.enc).

If both _INPUT_PATH_ and _OUTPUT_PATH_ are supplied, the input file is
encrypted and the output is stored at the supplied output path. If
_OUTPUT_PATH_ is *-*, the output will be written to standard out.

If only _INPUT_PATH_ is supplied, _OUTPUT_PATH_ is determined based on the
input path. Namely, if the input file is a .cacnk file, the output file is the
corresponding .cacnk.enc file in the same directory and vice versa.

If neither _INPUT_PATH_ nor _OUTPUT_PATH_ are supplied, csn-tool reads a list
of files from standard input and encrypts each one in turn, automatically
deriving the output path for each one. This is useful when encrypting an entire
chunk store, for example:

	find ./default.castr/ -name \*.cacnk | csn-tool crypt file:./key

In each case, if the output file already exists, it is not modified.

# BUG REPORTS

Please report bugs in casync-nano or errors in this manual page via GitHub
(https://github.com/florolf/casync-nano/issues) or email (_fl@n621.de_).

# SEE ALSO
_csn_(1)++
