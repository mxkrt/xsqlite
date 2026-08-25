''' _varint.py - deals with SQLite varint values

Copyright (c) 2014-2026 Netherlands Forensic Institute - MIT License
Copyright (c) 2025-2026 mxkrt@lsjam.nl - MIT License
'''


def varint(bytes_, offset, maxwidth=9):
    ''' Read a single varint form the given bytes_ at given offset

    The maxwidth argument is added to prevent reading very large varints, which
    is only realistic for the rowid of tables with many rows or for columns that
    contain very large TEXT or BLOB values. A value of 5 seems a reasonable max
    when parsing recordheader serialtypes.

    However, when maxwidth is not 9, the decoding of varints dictates that
    the upperbit of the last byte must be 0. Otherwise the varint decoder
    would proceed and try to read another byte. So in this case we raise a
    ValueError

    Returnvalue is the varint value and it's width in bytes
    '''

    # read and decode the varint
    value = 0
    for idx in range(0, maxwidth):
        # read a byte
        val = bytes_[offset+idx]
        upperbit = val >> 7
        if idx == 8:
            # all bits of the 9th byte are included
            value = value << 8
            value += val
        else:
            # only the lower 7 bits of the byte are included
            value = value << 7
            value += val & 0x7f
        if upperbit == 0:
            # stop when the upperbit is zero
            break
        elif idx == (maxwidth - 1) and idx != 8:
            # The upperbit dictates that we should read another
            # byte, but this would exceed the given maxwidth.
            # Thus, this would lead to an incorrectly parsed varint
            raise ValueError("given maxwidth prevents proper parsing of varint")
        if idx > 8:
            break

    # return varint and width
    return value, idx+1


def varints(bytes_, offset, bytecount, limit=None, maxwidth=9):
    ''' Interprets bytecount bytes at given offset as varints.

    Returns a list of varint values. When limit is set, decoding varints
    is aborted after 'limit' varints have been found. Raises an exception if
    the last varint that has been read exceeds the bytecount boundary.  The maxwidth
    argument is passed onto the varint function to limit the width of each individual
    varint to this maximum, which is usefull when parsing recordheader serialtypes
    '''

    if bytecount <= 0:
        return []

    pos = offset
    endpos = offset + bytecount

    # check if amount of bytes is available
    if endpos > len(bytes_):
        raise ValueError('not enough bytes available')


    results = []
    while True:
        if len(results) == limit:
            # stop if we have read enough varints
            break

        if pos == endpos:
            # stop if we have read the desired amount of bytes
            break

        if pos > endpos:
            # the last varint has moved us beyond desired amount of bytes
            raise ValueError("last varint required reading extra bytes")

        # read the varint and append to the list
        value, width = varint(bytes_, pos, maxwidth)
        results.append((value, width))
        pos += width

    return results


def tovarint(number):
    ''' Creates a bytes object with the given number as varint. '''

    if number >= 2**64:
        raise ValueError('max varint is 2**64-1')

    val = 0
    count = 0
    upper = 0

    if number >= 2**56:
        # need all 9 bytes, lower is full
        val = number & 0xff
        number >>= 8
        count = 1
        upper = 0x80
    elif number == 0:
        val = 0
        count = 1

    while count < 9 and number > 0:
        val += (number & 0x7f | upper) << count * 8
        number >>= 7
        count += 1
        upper = 0x80

    return int.to_bytes(val, count, 'big', signed=False)


def _varint_cache(bytes_):
    ''' prepare a varint cache for the given bytes array

    Parsing individual varints at each offset is expensive, so instead we make
    a cache by converting the given bitstream to a sequence of varints,
    starting at the given offset

    Note that this will likely include many false-positives and garbage
    varints, for example when we are parsing an area that does not contain
    actual varints. If, for example, more than 9 bytes all have their upper bit
    set to 1, we end up with a sequence of many large 9 byte varints that have
    no actual meaning in the database format.

    Returns a sequence of varints, and two dictionaries mapping offset to index.
    '''

    if not isinstance(bytes_, bytes):
        raise _exceptions.InvalidArgumentException("requires a bytes array as argument")

    # The first varint might be 'hidden' in this initial scan, for example when
    # the previous byte P (that should not have been part of the varint
    # sequence) has it's upper bit set. In this case, the next byte Q will be
    # interpreted as part of the varint that starts one byte earlier, instead
    # of a single 1-byte varint:

    #  P      Q      R      S      T      U      V      W      X      Y      Z
    # +------+------+------+------+------+------+------+------+------+------+------+
    # | 0x81 | 0x01 | 0x08 | 0x81 | 0x04 | 0x06 | 0x81 | 0x86 | 0x4f | 0x04 | 0x82 |
    # +------+------+------+------+------+------+------+------+------+------+------+

    # So if we start scanning at P, we read varint value 129, whereas if we
    # start scanning at Q, we read value 1. A priori, we can not know where the
    # sequence of varints starts, so the interpretation of the first varint
    # depends on the start offset.

    # To analyse this problem further, the following shows the interpretation
    # of varints when we start scanning at each offset P through Z:

    # P: 129 - 8 - 132 - 6 - 17231 - 4 - error
    # Q:   1 - 8 - 132 - 6 - 17231 - 4 - error
    # R:       8 - 132 - 6 - 17231 - 4 - error
    # S:           132 - 6 - 17231 - 4 - error
    # T:             4 - 6 - 17231 - 4 - error
    # U:                 6 - 17231 - 4 - error
    # V:                     17231 - 4 - error
    # W:                       847 - 4 - error
    # X:                        79 - 4 - error
    # Y:                             4 - error
    # Z:                                 error

    # As we can see, depending on where we start scanning, we may get different
    # values for the first varint in our sequence. Since a byte array can
    # contain multiple varint sequences, and because there is no way of knowing
    # where each sequence starts, we can not a priori determine which offsets
    # should and which should not be in the cache. For example, in the byte
    # array above we can have 2 small varint sequences (offset Q through U and
    # offset W through Y), but if we start scanning at offset P, both offsets
    # are not in the cache:

    # Cache 1:

    # P: 129
    # Q: not in cache
    # R: 8
    # S: 132
    # T: not in cache
    # U: 6
    # V: 17231
    # W: not in cache
    # X: not in cache
    # Y: 4
    # Z: error

    # The actual cache should be:

    # Cache 2:

    # P: not in cache
    # Q: 1
    # R: 8
    # S: 132
    # T: not in cache
    # U: 6
    # V: not in cache
    # W: 847
    # X: not in cache
    # Y: 4
    # Z: error

    # We can solve this problem in two ways:

    # 1) whenever we have parsed a multi-byte varint, parse the individual
    # varints that are 'consumed' by the multi-byte varint and add these to the
    # cache as well. This way, we have an interpreted varint for each offset,
    # which in our example results in:

    #     P: 129
    #     Q: 1
    #     R: 8
    #     S: 132
    #     T: 4
    #     U: 6
    #     V: 17231
    #     W: 847
    #     X: 79
    #     Y: 4
    #     Z: error

    # 2) leave holes in the cache, and only when requesting a varint from the
    # cache for an offset that is not in the cache (since it is consumed by a
    # larger varint starting one or more bytes earlier), re-parse the bytes at
    # that given offset from the original bitstream.  In our example above,
    # starting at offset P this would result in a cache as shown under Cache 1.

    # The downside of 1 is that we have to re-parse some bytes multiple times,
    # which can be expensive when parsing an area that does not contain any
    # actual varints. This is especially true when many of these bytes have a
    # value > 127 (upper bit set). Moreover, the problem with approach 1 is
    # that we no longer have the correct sequence of varints directly after
    # multi-byte varints. For example, if we start at V, we expect the next
    # varint to be 4, however, we have now corrupted this sequence by adding
    # the varint- values for the sub-bytes of the varint starting at V. Thus,
    # we can not use this approach.

    # The downside of 2 is that we can not fetch all varints from cache and we
    # have to re-parse the bytes at request time.

    # Since option 1 corrupts our sequence, and since we are likely to carve
    # through many area's that do not contain any varints, we opt for solution
    # 2. This way we can still cache most of the varints safely, as long as we
    # re-parse whenever we are trying to start at an offset that is inside one
    # of the >1-byte varints in our cache.

    # Note that whenever an offset is in the cache and we request a sequence of
    # n varints from the cache, we get the same results from the cache as when
    # we would parse the bytes at the given offset as a sequence of n varints
    # directly. Thus, each cache hit will yield the correct sequence of varints

    # length of data
    length = len(bytes_)

    # parsing everything as varints will fail if the last bytes have their
    # upper bit set (see offset Z in example above), so first determine how
    # much we can cache this way by checking the offset of the last byte with
    # it's lower bit unset
    cacheable_length = length
    for i in range(length-1, -1, -1):
        if bytes_[i] & 0x80 != 0:
            cacheable_length -=1
        else:
            break

    # cache the varints in this bytes array
    vcache = varints(bytes_, 0, cacheable_length)

    # since varints can be multiple bytes, the index in the vcache does not
    # reflect the actual offset within the bytes_ array. Also, we need to be
    # able to search for varint_sequences by offset. For this we add a second
    # structure to the cache, mapping varint offset to it's index in the
    # sequence.
    v_offset=0
    vcache_offsets = {}
    for idx, varint in enumerate(vcache):
        vcache_offsets[v_offset] = idx
        v_offset += varint[1]

    return vcache, vcache_offsets


def _parse_as_varints(bytes_, offset, varint_count):
    ''' parse the bytes at given offset as a sequence of varint_count varints

    Returns the sequence of varints or raises an Exception when data could not be parsed as such
    '''

    if not isinstance(bytes_, bytes):
        raise _exceptions.InvalidArgumentException("requires a bytes array as argument")

    # Theoretically, a single varint can be 9 bytes wide. This means that if we
    # need varint_count varints, the theoretical maximum size of the area to
    # scan for varints is varint_count * 9.  However, this can only be true for
    # TEXT and BLOB fields, all others have a 1 byte varint describing the
    # serial type. The maximum size of a TEXT or BLOB is determined by the
    # compile-time option SQLITE_MAX_LENGTH, which defaults to 1000000000 bytes
    # (~ 950 MB). A BLOB of this length is represented as follows:

    # (N-13)/2 = 1000000000
    # N - 13 = 2000000000
    # N = 2000000013

    # A TEXT of this length is represented as follows:

    # (N-12)/2 = 1000000000
    # N - 12 = 2000000000
    # N = 2000000012

    # Thus, for this default maximum the width of a serial type in the record
    # header is at most 5 bytes
    # >>> tovarint(2000000013).len / 8
    # 5.0

    # So, in order to find varint_count varints in a row, without any prior
    # knowledge about the type of records we are dealing with, we need a
    # minimum of varint_count bytes, and a maximum of varint_count * 5 bytes,
    # assuming all fields hold TEXT or BLOB of maximum size.

    # to summarize, we must find the smallest sequence of bytes that lead to
    # varint_count varints at given offset. Start with smallest bytecount, and
    # gradually increase bytecount until a sequence of the desired amount of
    # varints is returned.

    for width in range(varint_count, varint_count * 5):
        try:
            res = varints(bytes_, offset, width, limit=varint_count, maxwidth=5)
            # check if we have the expected amount of varints, if not try again with one more byte
            if len(res) == varint_count:
                # as soon as we found a valid sequence, return it
                return res
            else:
                continue
        except:
            pass

    # if we get here, no valid varints sequence was found
    return None


def _get_varints(bytes_, offset, varint_count, vcache, vcache_offsets):
    ''' return varint sequence from given bytes_ array at given offset

    We first check if the given offset has a cached entry in the vcache and
    return the varint sequence from the cache if possible. Otherwise, the bytes
    at given offset are parsed as varints.

    Note that the caller is responsible for making sure the vcache and
    vcache_offsets correspond to the bytes_ array, otherwise this will just
    return garbage. '''

    if not isinstance(bytes_, bytes):
        raise _exceptions.InvalidArgumentException("requires a bytes array as argument")

    length = len(bytes_)

    if offset < 0 or offset >= length:
        raise _exceptions.InvalidArgumentException('offset is not withing bytes array')

    # unallocated area may contain some left over cellpointers followed by an
    # area with only 0x00 bytes, followed by the remnants of older records. In
    # this case, there is always a freeblock or cell header prior to the record
    # to reconstruct. When the recordheader consists of only null-bytes, this
    # is either not a valid recordheader or the record will not yield much
    # information, so we can safely skip all area's that are equal or longer
    # than the minimum recordheader size for this table and that contain only
    # null-bytes. Regions of null-bytes will always be parsed as valid varints
    # and so these will be in the cache. In this case the varint sequence will
    # be [(0,1),(0,1),...,(0,1)] and this will be of no use to us.
    all_zero_parsed = [(0,1)]*varint_count
    all_zero_bytes = b'\x00'*varint_count

    if offset in vcache_offsets:
        # HIT: fetch the sequence from the cache
        v_index = vcache_offsets[offset]
        res = vcache[v_index:v_index+varint_count]
        if len(res) != varint_count:
            # there is a varint sequence at this offset, but it is too short
            return None
        if res == all_zero_parsed:
            return None
        return res

    else:
        # MIS: parse varints at given offset
        # first check if we have a sequence of null bytes
        if bytes_[offset:offset+varint_count] == all_zero_bytes:
            # most sequences of null-bytes are in the varint cache,
            # but when the previous byte has its upper bit set,
            # the current byte offset is not in the cache, so we
            # need to check for this here as well.
            return None
        res = _parse_as_varints(bytes_, offset, varint_count)
        if res is not None:
            return res
        else:
            return None


def varint_scanner(bytes_, varint_count):
    ''' yield sequences of varint_count varints, from given region in bytes_ array

    For recovery of records we need to look for recordheaders, which consists
    of two varints for the rowid and the recordsize, followed by a sequence of
    varints holding the serial typecodes for each field in the record.

    This function can be used to scan the given bytes array for locations where
    we can successfully parse the given number of varints, so that we have a
    set of candidate locations that we can compare against serial type
    signatures.

    Scanning is stopped varint_count bytes prior to the end of the array, since
    we are only interested in varint_count sized sequences. The varint cache
    (vcache) is used to prevent having to reparse sequences if we shift only a
    single byte during the scan.

    We know that, depending on where the deleted record exists (freeblock,
    unallocated area), and depending on the width of the rowid varint and the
    width of the record size varint, at most the first 2 bytes of the
    recordheader can be overwritten by the 4-byte freeblock header (which does
    not use varints but uses two 16 bit values for next_freeblock_offset and
    freeblock_size.

    Thus, it can be a good strategy to search for sequences of varints with
    length n-2 if n is the number of columns in the table (or the minimally
    encountered number of columns when a table has been altered using ALTER
    TABLE statement to add more columns during the lifetime of the database.

    Note that the caller is responsible for making sure the vcache and
    vcache_offsets correspond to the bytes_ array, otherwise this will just
    return garbage. '''

    # NOTE: this function used to accept an offset and a size to limit scanning
    #       of the given bytes_ array to a sub-region. However, this turned out to
    #       be problematic since the vcache could contain varint sequences of the
    #       proper length (varint_count) that end outside the defined region. In this
    #       case, the _get_varints function would return a valid sequence from the
    #       cache whereas it spills over the defined region. So, we now create the
    #       varint_cache within this function to make sure it is based on the same
    #       bytes_ array and does not contain varint_sequences that spill over the
    #       bytes_ array. Also, caching the entire database file does not turn out
    #       to be faster. This note is here mainly to prevent myself from attempting
    #       to "optimize" this later again.

    if not isinstance(bytes_, bytes):
        raise _exceptions.InvalidArgumentException("requires a bytes array as argument")

    # check arguments
    if varint_count < 0:
        raise _exceptions.InvalidArgumentException('varint_count is negative')

    length = len(bytes_)

    # Not an error, but simply a stop condition
    if length < varint_count:
        return

    # if we have only null bytes, no need to scan for varints, stop condition
    if set(bytes_) == {0}:
        return

    # create a varint_cache for this bytes_ array
    vcache, vcache_offsets = _varint_cache(bytes_)

    # the region in which we search for varints is the entire length, but since
    # we want a sequence of varint_count varints, we can stop varint_count bytes
    # prior to that offset, assuming that each varint consumes 1 byte.
    end_pos = length - varint_count

    # scan over offsets in the bytes_ array, and look for sequences of varint_count varints
    for o in range(0, end_pos):
        res = _get_varints(bytes_, o, varint_count, vcache, vcache_offsets)
        if res is None:
            # _get_varints returns None if the sequence has too few varints or contains
            # only null bytes
            continue

        # if we get here, we have a valid sequence, yield offset, varints and serialtypes
        yield o, res
