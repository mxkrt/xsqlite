''' _structures - basic structures in the SQLite3 file format

Copyright (c) 2014-2026 Netherlands Forensic Institute - MIT License
Copyright (c) 2025-2026 mxkrt@lsjam.nl - MIT License

The implementation of the structures and the logic is based on the description
of the database format as given on: https://www.sqlite.org/fileformat.html
'''

from struct import unpack_from as _unpack_from
from collections import namedtuple as _nt

from ._varint import varint, varints


##############
# pageheader #
##############

# pageheader fields:
# - pagetype: the type of b-tree page
# - first_freeblock_offset: relative offset of the first freeblock.
# - cellcount: number of cells on this page.
# - cell_content_offset: relative offset of cell content area.
# - fragmented_freebyte_count: total number of fragmented free bytes.
# - rightmost_pointer: the right-most pointer for interior pages.
# - size: the size of the btree_pageheader
_pageheader = _nt('btree_pageheader',
                  'pagetype first_freeblock_offset cellcount '
                  'cell_content_offset fragmented_freebyte_count '
                  'rightmost_pointer size')

# There are four b-tree pagetypes defined:
# - table_interior : A table b-tree interior page
# - table_leaf     : A table b-tree leaf page
# - index_interior : An index b-tree interior page
# - index_leaf     : An index b-tree leaf page
_pagetype = {2: 'index_interior',
             5: 'table_interior',
             10: 'index_leaf',
             13: 'table_leaf'}


def pageheader(data, offset, usablepagesize):
    ''' Parse given bytes as btree pageheader

    Arguments:
    - data           : bytes containing the btree pageheader
    - offset         : offset of the btree pageheader structure
    - usablepagesize : usable page size as calculated from database header

    Returns:
    - pageheader     : named tuple with parsed btree pageheader
    '''

    # parse first 8 bytes
    hsize = 8
    fmt = '>BHHHB'
    parsed = _unpack_from(fmt, data, offset)
    pgtype, first_freeblock, cellcount, cellarea, freebytes = parsed

    # in some fields (including this one), value 0 means 65536
    if cellarea == 0:
        cellarea = 65536

    # replace parsed values with interpreted values
    if pgtype in _pagetype:
        pgtype = _pagetype[pgtype]
    else:
        raise ValueError('invalid b-tree page type {:d}'.format(pgtype))

    # interior pages have a rightmost pointer
    rmp = None
    if pgtype in ['index_interior', 'table_interior']:
        rmp = _unpack_from('>I', data, offset+hsize)[0]
        hsize += 4

    if first_freeblock > usablepagesize:
        raise ValueError('first freeblock offset outside usable page area.')
    if cellarea > usablepagesize:
        raise ValueError('cell content area offset outside usable page area.')
    if freebytes > (usablepagesize - cellarea):
        raise ValueError('free byte count exceeds cell content area size.')

    return _pageheader(pgtype, first_freeblock, cellcount,
                       cellarea, freebytes, rmp, hsize)


##############
# btree page #
##############

# btree page fields:
# - pagetype: one of the four pagetypes defined in pagetype function
# - header_offset: relative offset of header (mostly 0, except for page 1)
# - header: the btree_pageheader for the current page
# - cellpointer_offset : relative offset of the cellpointer area within the page
# - cellpointer_area: the parsed cellpointer_area for the current page
# - cells: a list of parsed cells
# - rowidmap: {rowid:cellnumber} for table_leaf pages, None otherwise
# - freeblocks: a list of freeblocks for this page
# - unallocated_offset: relative offset of the unallocated space
# - reserved_offset: relative offset of the reserved area (usablepagesize)
# - size: the page size (passed in as variable)
# - unallocated: the data stored in the unallocated area for this page
# - reserved: the data stored in the reserved area for this page or None
_btreepage = _nt('btree_page', 'pagetype header_offset header '
                               'cellpointer_offset cellpointer_area '
                               'cells rowidmap freeblocks '
                               'unallocated_offset reserved_offset size '
                               'unallocated reserved')


def btree_page(data, offset, pagesize, usablepagesize, isheaderpage=False):
    ''' Parse given bytes as bree page

    Arguments:
    - data           : bytes containing the page
    - offset         : offset of the page structure
    - pagesize       : pagesize as stored in database header
    - usablepagesize : offset of the reserved area in the page
    - isheaderpage   : if True, assume database header in first 100 bytes

    Returns:
    - btreepage      : named tuple with the parsed btree page
    '''

    # parse the pageheader
    hoffset = offset
    if isheaderpage is True:
        hoffset += 100
    pgheader = pageheader(data, hoffset, usablepagesize)

    # parse the cell pointer area (directly after the pageheader)
    cpa = cellpointer_area(data, hoffset + pgheader.size, pgheader.cellcount)

    # parse the cells
    cells = [cell(data, offset, cp, pgheader.pagetype,
                  usablepagesize) for cp in cpa.cellpointers]

    # add rowid to cell number map for this page if it is table leaf
    rowidmap = None
    if pgheader.pagetype == 'table_leaf':
        rowidmap = {cells[i].rowid: i for i in range(len(cells))}

    # relative offset of unallocated space 
    # (from end of last cellpointer to cell content area)
    cpa_offset = hoffset + pgheader.size - offset
    cpa_size = pgheader.cellcount * 2
    # size of unallocated area
    usize = pgheader.cell_content_offset - (cpa_offset + cpa_size)
    # relative offset of unallocated area
    uoffset = cpa_offset + cpa_size
    # NOTE: uoffset is relative, so need to add offset
    unalloc = data[uoffset+offset:uoffset+usize+offset]

    # collect the freeblocks on this page
    fblocks = []
    fboffset = pgheader.first_freeblock_offset
    while fboffset != 0:
        fblock = freeblock(data, offset, fboffset)
        fboffset = fblock.next_freeblock
        fblocks.append(fblock)

    # reserved area runs from end of cell content area to end of page
    res = None
    res_offset = None
    if pagesize > usablepagesize:
        res_offset = offset+usablepagesize
        res = data[res_offset:offset+pagesize]
        # make the offsets relative to page offset before returning
        res_offset = res_offset - offset

    return _btreepage(pgheader.pagetype, hoffset-offset, pgheader, cpa_offset, 
                      cpa, cells, rowidmap, fblocks, uoffset, res_offset, pagesize,
                      unalloc, res)


####################
# cellpointer area #
####################

# cellpointer area fields:
# - cellpointers: a list of cell pointers
# - size: size of the cell pointer area
_cellpointerarea = _nt('cellpointer_area',
                       'cellpointers size')


def cellpointer_area(data, offset, cellcount):
    ''' Parse given bytes as cellpointer area

    Arguments:
    - data      : bytes containing the database header
    - offset    : offset of the dbheader structure
    - cellcount : the total number of cells to parse

    Returns:
    - cellpointer_area: namedtuple representing the cellpointer area
    '''

    fmt = '>' + 'H'*cellcount
    cpointers = _unpack_from(fmt, data, offset)
    # cellpointer value 0 means 65536
    cpointers = [65536 if p == 0 else p for p in cpointers]
    # cell pointer is two bytes wide
    cpa_size = cellcount * 2
    return _cellpointerarea(cpointers, cpa_size)


########
# cell #
########


def cell(data, page_offset, cell_offset, pagetype, usablepagesize):
    ''' Parse given bytes as cell, depending of pagetype

    Arguments:
    - data           : bytes containing the page that holds the cell
    - page_offset    : offset of the page holding the cell structure
    - cell_offset    : relative offset of the cell within the page
    - pagetype       : string indicating the type of page (and thus cell type)
    - usablepagesize : offset of reserved area within page

    Returns:
    - cell           : parsed cell, depending on pagetype
    '''

    # cell structure varies for different page types
    if pagetype == 'table_leaf':
        return _tableleaf_cell(data, page_offset, cell_offset, usablepagesize)
    elif pagetype == 'index_leaf':
        return _indexleaf_cell(data, page_offset, cell_offset, usablepagesize)
    elif pagetype == 'index_interior':
        return _indexinterior_cell(data, page_offset, cell_offset, usablepagesize)
    elif pagetype == 'table_interior':
        # NOTE: table_interior cells only store page numbers and varint integer 
        #       key, so no overflow computation is needed, hence the absence of
        #       the usablepagesize argument here
        return _tableinterior_cell(data, page_offset, cell_offset)
    else:
        raise ValueError('unknown pagetype when trying to parse cells')


def _inline_payload_size(celltype, payloadsize, usablepagesize):
    ''' Calculates the inline size for the given payloadsize. 

    Arguments:
    - celltype       : the type of cell
    - payloadsize    : the size of the full payload
    - usablepagesize : offset of reserved area within page

    Returns:
    - inlinesize     : total size of payload that can be stored inline
    '''

    if celltype not in ['table', 'index']:
        raise ValueError("celltype should be 'table' or 'index'")

    # Table B-Tree Leaf Cell:
    # If the payload size P is less than or equal to U-35 then the entire
    # payload is stored on the b-tree leaf page. Let M be ((U-12)*32/255)-23.
    # If P is greater than U-35 then the number of byte stored on the b-tree
    # leaf page is the smaller of M+((P-M)%(U-4)) and U-35. Note that number of
    # bytes stored on the leaf page is never less than M.
    #
    # Index B-Tree Leaf Or Interior Cell:
    # Let X be ((U-12)*64/255)-23). If the payload size P is less than or equal
    # to X then the entire payload is stored on the b-tree page. Let M be
    # ((U-12)*32/255)-23. If P is greater than X then the number of byte stored
    # on the b-tree page is the smaller of M+((P-M)%(U-4)) and X. Note that
    # number of bytes stored on the index page is never less than M.

    P = payloadsize
    U = usablepagesize

    # code rounds down (used to have math.ceil here) by casting to u16.
    # c-test: (unsigned short int) 3.9652 --> result = 3
    # --> this is same as int() in Python
    M = int(((U - 12) * 32 / 255) - 23)   # (minLocal and minLeaf)

    if celltype == 'table':
        X = U - 35                           # (maxLeaf)
    elif celltype == 'index':
        # see note on rounding above
        X = int(((U - 12) * 64 / 255) - 23)  # (maxLocal)

    if P <= X:
        return P
    else:
        istore = M + ((P - M) % (U - 4))
        if istore <= X:
            return istore
        else:
            # NOTE: in btree.c size is set to minLocal in this case,
            # which is essentially M, whereas the documentation on
            # the fileformat says X here. Used M instead, docs seem wrong!
            return M


# Table B-Tree Leaf Cell fields:
# - payloadsize: total payload size, including overflow (if any)
# - rowid: rowid of record stored in the cell
# - first_overflow_page: page number of first overflow page
# - cell_offset: relative offset of the cell within the page (passed as arg)
# - inline_payload_offset: relative offset of the inline payload within the page
# - cell_size: total size of the cell (payload_size + headersize)
# - inline_payload: the data stored as inline payload
_table_leaf_cell = _nt('table_leaf_cell',
                       'payloadsize rowid first_overflow_page '
                       'cell_offset inline_payload_offset cell_size '
                       'inline_payload')


def _tableleaf_cell(data, page_offset, cell_offset, usablepagesize):
    ''' Parse bytes at page_offset+cell_offset as Table B-Tree Leaf Cell

    Arguments:
    - data           : bytes containing the cell
    - page_offset    : offset of the page holding the cell structure
    - cell_offset    : relative offset of the cell within the page
    - usablepagesize : offset of reserved area within page

    Returns:
    - cell           : parsed cell
    '''

    offset = page_offset + cell_offset

    # table B-Tree leaf cell starts with payloadsize and rowid
    payloadsize, payloadsize_width = varint(data, offset)
    rowid, rowid_width = varint(data, offset + payloadsize_width)

    # determine dimensions and location of inline payload
    ipsize = _inline_payload_size('table', payloadsize, usablepagesize)
    payloadstart = payloadsize_width + rowid_width
    # create slice for inline payload
    ipstart = payloadstart + offset
    ipend = ipstart + ipsize
    payload = data[ipstart:ipend]
    # make ipstart relative before returning
    ipstart = ipstart - page_offset

    # determine size of the cell structure thus far
    cellsize = payloadsize_width + rowid_width + ipsize

    # if the payload overflows, we need to read first overflow page pointer
    fop = None
    if payloadsize > ipsize:
        # read 4 byte integer for first overflow page (fop)
        fop = _unpack_from('>I', data, offset + cellsize)[0]
        cellsize += 4

    return _table_leaf_cell(payloadsize, rowid, fop, cell_offset, ipstart,
                            cellsize, payload)


# Table B-Tree Interior Cell fields:
# - left_child_pointer: left child pointer (pagenumber)
# - key: integer key
# - cell_offset: relative offset of the cell within the page
# - cell_size: size of the cell
_table_interior_cell = _nt('table_interior_cell',
                           'left_child_pointer key cell_offset cell_size')


def _tableinterior_cell(data, page_offset, cell_offset):
    ''' Parse bytes at page_offset+cell_offset as Table B-Tree Interior Cell

    Arguments:
    - data      : bytes containing the cell
    - page_offset    : offset of the page holding the cell structure
    - cell_offset    : relative offset of the cell within the page

    Returns:
    - cell      : parsed table interior cell
    '''

    offset = page_offset + cell_offset

    # read left child pointer
    lcp = _unpack_from('>I', data, offset)[0]
    # read the varint key
    key, key_width = varint(data, offset + 4)
    cellsize = 4 + key_width
    return _table_interior_cell(lcp, key, cell_offset, cellsize)


# Index B-Tree Leaf Cell fields:
# - payloadsize: total payload size, including overflow (if any)
# - first_overflow_page: page number of first overflow page
# - cell_offset: relative offset of the cell within the page
# - inline_payload_offset: relative offset of the inline payload within the page
# - cell_size: total size of the cell (payload_size + headersize)
# - inline_payload: the data stored as inline payload
_index_leaf_cell = _nt('index_leaf_cell',
                       'payloadsize first_overflow_page '
                       'cell_offset inline_payload_offset cell_size '
                       'inline_payload')


def _indexleaf_cell(data, page_offset, cell_offset, usablepagesize):
    ''' Parse bytes at page_offset+cell_offset as Index B-Tree Leaf Cell 

    Arguments:
    - data           : bytes containing the cell
    - page_offset    : offset of the page holding the cell structure
    - cell_offset    : relative offset of the cell within the page
    - usablepagesize : offset of reserved area within page

    Returns:
    - cell           : parsed cell
    '''

    offset = page_offset + cell_offset

    # index B-Tree leaf cell starts with payloadsize
    payloadsize, payloadsize_width = varint(data, offset)

    # determine dimensions and location of inline payload
    ipsize = _inline_payload_size('index', payloadsize, usablepagesize)
    payloadstart = payloadsize_width

    # create slice for inline payload
    ipstart = payloadstart + offset
    ipend = ipstart + ipsize
    payload = data[ipstart:ipend]
    # make ipstart relative before returning
    ipstart = ipstart - page_offset

    # determine size of the cell structure so far
    cellsize = payloadsize_width + ipsize

    # if the payload overflows, we need to read first overflow page pointer
    fop = None
    if payloadsize > ipsize:
        # read 4 byte integer for first overflow page (fop)
        fop = _unpack_from('>I', data, offset + cellsize)[0]
        cellsize += 4

    return _index_leaf_cell(payloadsize, fop, cell_offset, ipstart,
                            cellsize, payload)


# Index B-Tree Interior Cell fields:
# - left_child_pointer: left child pointer (pagenumber)
# - payloadsize: total payload size, including overflow (if any)
# - first_overflow_page: page number of first overflow page
# - cell_offset: relative offset of the cell within the page
# - inline_payload_offset: relative offset of the inline payload within the page
# - cell_size: total size of the cell (payload_size + headersize)
# - inline_payload: the data stored as inline payload
_index_interior_cell = _nt('index_interior_cell',
                           'left_child_pointer payloadsize '
                           'first_overflow_page cell_offset '
                           'inline_payload_offset cell_size '
                           'inline_payload')


def _indexinterior_cell(data, page_offset, cell_offset, usablepagesize):
    ''' Parse bytes at page_offset+cell_offset as Index B-Tree Interior Cell 

    Arguments:
    - data           : bytes containing the cell
    - page_offset    : offset of the page holding the cell structure
    - cell_offset    : relative offset of the cell within the page
    - usablepagesize : offset of reserved area within page

    Returns:
    - cell           : parsed cell
    '''

    offset = page_offset + cell_offset

    # read left child pointer
    lcp = _unpack_from('>I', data, offset)[0]

    # index B-Tree interior cell has key payloadsize at offset 4
    payloadsize, payloadsize_width = varint(data, offset + 4)

    # determine dimensions and location of inline payload
    ipsize = _inline_payload_size('index', payloadsize, usablepagesize)
    payloadstart = payloadsize_width + 4

    # create slice for inline payload
    ipstart = payloadstart + offset
    ipend = ipstart + ipsize
    payload = data[ipstart:ipend]
    # make ipstart relative before returning
    ipstart = ipstart - page_offset

    # determine size of the cell thus far
    cellsize = payloadsize_width + ipsize + 4

    # if the payload overflows, we need to read first overflow page pointer
    fop = None
    if payloadsize > ipsize:
        # read 4 byte integer for first overflow page (fop)
        fop = _unpack_from('>I', data, offset + cellsize)[0]
        cellsize += 4

    return _index_interior_cell(lcp, payloadsize, fop, cell_offset, ipstart,
                                cellsize, payload)



#################
# record format #
#################

# recordformat fields:
# - header: the parsed record header
# - body: the parsed record body
_recordformat = _nt('recordformat', 'header body')

# NOTE: offset is not stored intentionally in the parsed header and body, since
# we may also pass in slices of data which makes the offset relative to the
# slice, making the offset useless without keeping track of the slice of data
# passed into the function. The caller is responsible for tracking the offset
# of the data


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


#################
# record header #
#################

# recordheader fields:
# - headersize : the size of the header in bytes
# - serialtypes : a sequence of serialtypes as stored in the header
_recordheader = _nt('recordheader', 'headersize serialtypes')


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
    serialtypes = [i[0] for i in serialtypes]

    if len(serialtypes) <= 0:
        raise ValueError('empty list of serialtypes.')

    return _recordheader(hsize, serialtypes)


##############
# serialtype #
##############

# serialtype fields:
# - size : the size of the serialtype in the recordbody
# - storageclass: NULL, Integer, Real, Text or Blob
# - parser: format string for struct.unpack
# - function: post processing function to apply after struct.unpack
_serialtype = _nt('serialtype', 'size storageclass parser function')

# SQLite uses these 5 storage classes
_null = _nt('null', 'size value')
_integer = _nt('integer', 'size value')
_real = _nt('real', 'size value')
_text = _nt('text', 'size value')
_blob = _nt('blob', 'size value')

# intbe24 and intbe48 need to be converted separately (and similarly)
_int24 = lambda b: int.from_bytes(b, 'big', signed=True)
_int48 = lambda b: int.from_bytes(b, 'big', signed=True)

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


###############
# record body #
###############


def recordbody(data, offset, recheader):
    ''' Parses the recordbody at given offset based on given recordheader.

    Arguments:
    - data      : the data in which the recordbody exists
    - offset    : the offset of the recordbody in given data
    - recheader : the parsed recordheader with parser instructions

    Returns:
    - body: list of storage class objects for the various objects. 

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
    stypes = [serialtype(t) for t in recheader.serialtypes]
    sizes = [s[0] for s in stypes]
    sclasses = [s[1] for s in stypes]

    # build the parse instruction (big-endian)
    fmt = '>' + ''.join([s.parser for s in stypes if s.parser is not None])
    # int24 and int48 need post-processing
    pfuncs = [s.function for s in stypes if s.parser is not None]
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
    return columns


#############
# freeblock #
#############

# fields:
# - next_freeblock : relative offset of next freeblock within page
# - offset         : relative offset of this freeblock within page
# - size           : size of the current freeblock
# - data_offset    : offset of data in page freeblock (offset+4)
# - data           : bytes stored in the freeblock (excluding header)
_freeblock = _nt('freeblock', 'offset next_freeblock size data_offset data')


def freeblock(data, page_offset, freeblock_offset):
    ''' Parse data at page_offset+freeblock_offset as freeblock

    Arguments:
    - data             : bytes containing the cell
    - page_offset      : offset of the page holding the cell structure
    - freeblock_offset : relative offset of the cell within the page

    Returns:
    - freeblock        : parsed freeblock
    '''

    # read next freeblock pointer and freeblocksize
    next_fb, size = _unpack_from('>HH', data, freeblock_offset + page_offset)
    # define a block for the data area
    start = freeblock_offset+page_offset+4
    end = start+size-4
    fbdata = data[start:end]
    return _freeblock(freeblock_offset, next_fb, size, freeblock_offset+4, fbdata)


################
# overflowpage #
################



################
# generic page #
################

# a basic page that treats all data as unallocated

# generic page fields:
# - pagetype: 'unknown'
# - unallocated_offset: relative offset of the unallocate space (0)
# - unallocated: the data stored in the unallocated area for this page
# - unallocated_size : size of the unallocated space
# - size: the page size (passed in as variable)
_genericpage = _nt('genericpage', 'pagetype unallocated_offset unallocated '
                                  'unallocated_size size')


def genericpage(data, offset, pagesize):
    ''' Parses data at given offset as generic (unallocated) page.

    Arguments:

    - data           : bytes containing the page
    - offset         : offset of the page within the data
    - pagesize       : the size of a database page

    Returns:
    - genericpage     : 'parsed' generic page
    '''
    return _genericpage('unknown', 0, data[offset:offset+pagesize], 
                        pagesize, pagesize)



