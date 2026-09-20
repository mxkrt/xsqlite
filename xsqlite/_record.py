''' _record.py - code related to parsing record structures

Copyright (c) 2014-2026 Netherlands Forensic Institute - MIT License
Copyright (c) 2025-2026 mxkrt@lsjam.nl - MIT License

The implementation of the structures and the logic is based on the description
of the database format as given on: https://www.sqlite.org/fileformat.html
'''

from struct import unpack_from as _unpack_from
from collections import namedtuple as _nt
from ._varint import varint, varints

# namedtuple representing a recordheader
_recordheader = _nt('recordheader', 'headersize serialtypes')

# namedtuple representing a recordformat structure
_recordformat = _nt('recordformat', 'header body')

# SQLite uses these 5 storage classes
_null = _nt('null', 'size value')
_integer = _nt('integer', 'size value')
_real = _nt('real', 'size value')
_text = _nt('text', 'size value')
_blob = _nt('blob', 'size value')

# intbe24 and intbe48 need to be converted separately (and similarly)
_int24 = lambda b: int.from_bytes(b, 'big', signed=True)
_int48 = lambda b: int.from_bytes(b, 'big', signed=True)

# namedtuple represeting a serialtype
# - size: the size of the serialtype in the recordbody
# - storageclass: NULL, Integer, Real, Text or Blob
# - parser: format string for struct.unpack
# - function: post processing function to apply after struct.unpack
_serialtype = _nt('serialtype', 'size storageclass parser function')

# The fixed-width types and the corresponding parser instruction
_fixedtypes = {0: _serialtype(0, _null, None, None),
               1: _serialtype(1, _integer, 'b', None),    # signed int8
               2: _serialtype(2, _integer, 'h', None),    # signed int16
               3: _serialtype(3, _integer, '3s', _int24), # signed int24
               4: _serialtype(4, _integer, 'i', None),    # signed int32
               5: _serialtype(6, _integer, '6s', _int48), # signed int48
               6: _serialtype(8, _integer, 'q', None),    # signed int64
               7: _serialtype(8, _real, 'd', None),       # float64
               8: _serialtype(0, _integer, None, None),
               9: _serialtype(0, _integer, None, None)}


def serialtype(stype):
    ''' Return serialtype namedtuple based on numeric serial type

    Arguments:
    - stype    : numeric serial type

    Returns:
    - serialtype : namedtuple with serialtype properties
    '''

    if stype in [10, 11]:
        raise ValueError('reserved serialtype 10 or 11 encountered')
    elif type(stype) != int:
        raise ValueError('serialtype should be integer')
    elif stype < 0:
        raise ValueError('negative serialtype encountered')
    elif stype >= 12 and stype % 2 == 0:
        # BLOB of length (N-12) / 2
        size = int((stype - 12) / 2)
        return _serialtype(size, _blob, f'{size}s', None)
    elif stype >= 13 and stype % 2 == 1:
        # STRING of length (N-13) / 2
        size = int((stype - 13) / 2)
        return _serialtype(size, _text, f'{size}s', None)
    else:
        return _fixedtypes[stype]


def recordheader(data, offset):
    ''' Parse given bytes as recordheader

    Arguments:
    - data     : bytes containing the recordheader structure
    - offset   : offset of the recordheader structure

    Returns:
    - recordheader : sequence of serialtype numbers
    '''

    # parse and unpack headersize varint (value, varint_width)
    hsize, skip = varint(data, offset)

    # default max number of columns is 2000 and each column may take
    # up to 5 bytes in record header (varint of 5 bytes is enough for
    # max size of individual columns)
    if hsize > 2000 * 5:
        raise ValueError('columns exceed default maximum.')

    # read varints in remaining header
    types_offset = offset+skip
    types_bytecount = hsize-skip

    serialtypes = varints(data, types_offset, types_bytecount)
    # this function returns tuples, consisting of (varint_value, varint_width) pairs
    serialtypes = tuple(i[0] for i in serialtypes)

    if len(serialtypes) <= 0:
        raise ValueError('empty list of serialtypes.')

    return _recordheader(hsize, serialtypes)


def recordbody(data, offset, recheader):
    ''' Parses the recordbody at given offset based on given recordheader.

    Arguments:
    - data      : the data in which the recordbody exists
    - offset    : the offset of the recordbody in given data
    - recheader : the parsed recordheader with parser instructions

    Returns:
    - body: tuple of storage class objects for the various objects. 

    Note: Some serial types are not stored in the body, but are determined by the 
    header. These have size 0. The following serial types are defined:

        - null: used for NULL column values
        - integer: used for INTEGER column values
        - real: used for REAL column values
        - text: used for TEXT column values
        - blob: used for BLOB column values

    Note that TEXT columns are not yet decoded, since it depends on the
    database text encoding, which this function is unaware of. Also, we want to
    use this function for recovery of partial records, which might not properly
    decode. So the bytes are returned as-is.
    '''

    # make list of sizes, storageclases and a parser command from serialtypes
    stypes = tuple(serialtype(t) for t in recheader.serialtypes)
    sizes = tuple(s[0] for s in stypes)
    sclasses = tuple(s[1] for s in stypes)

    # build the parse instruction (big-endian)
    fmt = '>' + ''.join(tuple(s.parser for s in stypes if s.parser is not None))
    # int24 and int48 need post-processing
    pfuncs = tuple(s.function for s in stypes if s.parser is not None)
    # parse the bytes
    parsed = list(_unpack_from(fmt, data, offset))
    # apply function to selected fields
    for idx, func in enumerate(pfuncs):
        if func is None:
            continue
        else:
            parsed[idx] = func(parsed[idx])
    # add the non-space-consuming column values in the appropriate slots
    columns = []
    for i in range(len(recheader.serialtypes)):
        tc = recheader.serialtypes[i]
        sclass = sclasses[i]
        size = sizes[i]
        if tc == 0:
            val = None
        elif tc == 8:
            val = 0
        elif tc == 9:
            val = 1
        else:
            val = parsed.pop(0)
        columns.append(sclass(size, val))
    return tuple(columns)


def recordformat(data, offset):
    ''' Parse given bytes as recordformat (header + body)

    Arguments:
    - data     : bytes containing the recordformat structure
    - offset   : offset of the recordformat structure

    Returns:
    - recordformat : namedtuple with the parsed recordheader + body
    '''

    recheader = recordheader(data, offset)
    bodyoffset = recheader.headersize + offset
    body = recordbody(data, bodyoffset, recheader)
    return _recordformat(recheader, body)
