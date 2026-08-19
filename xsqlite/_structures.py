''' _structures - basic structures in the SQLite3 file format

Copyright (c) 2014-2026 Netherlands Forensic Institute - MIT License
Copyright (c) 2025-2026 mxkrt@lsjam.nl - MIT License

The implementation of the structures and the logic is based on the description
of the database format as given on: https://www.sqlite.org/fileformat.html
'''

from struct import unpack_from as _unpack_from
from collections import namedtuple as _nt


###################
# database header #
###################

# dbheader fields:
# - headerstring: The header string 'SQLite format 3[0x00]'
# - pagesize: The database page size in bytes. Size 1 means 65536
# - writeversion: file format write version. 1 for legacy; 2 for WAL.
# - readversion: file format read version. 1 for legacy; 2 for WAL.
# - reservedspace: Bytes of unused "reserved" space at the end of
#   each page. Usually 0.
# - maxpayloadfraction: maximum embedded payload fraction.
# - minpayloadfraction: minimum embedded payload fraction.
# - leafpayloadfraction: Leaf payload fraction.
# - filechangecounter: File change counter. Note: the change counter
#   might not be incremented on each transaction in WAL mode.
# - dbsize: Size of the database file in pages, a.k.a. the "in-header
#   database size".
# - firstfreelisttrunkpage: Page number of the first freelist trunk page.
# - totalfreelistpages: Total number of freelist pages.
# - schemacookie: The schema cookie.
# - schemaformat: The schema format number.
# - defaultpagecachesize: Default page cache size.
# - largestrootbtreepage: The page number of the largest root b-tree page
#   when in auto- or incremental vacuum mode, zero otherwise.
# - textencoding: The database text encoding.
# - userversion: The "user version" as read and set by the user_version
#   pragma. Not used by SQLite internally.
# - vacuummode: True (non-zero) for incremental-vacuum mode.  False
#   (zero) otherwise.
# - "Application ID" set by PRAGMA application_id.
# - reserved: 20 bytes reserved for expansion. Must be zero.
# - validfor: The version-valid-for number
# - version: SQLITE_VERSION_NUMBER field
# - usablepagesize: calculated usable page size
# - externalsize: calculated size of database in pages based on available data
#   (may be wrong if only part of th data was passed into function).
# - inheadersizevalid: indicates if in-header database size is valid
#   The 'in header database size' is only valid if it is nonzero
#   and if the filechange counter matches the validfor number.
# - size: the size of the database header (100)
_dbheader = _nt('database_header', 'headerstring pagesize writeversion '
                'readversion reservedspace maxpayloadfraction '
                'minpayloadfraction leafpayloadfraction filechangecounter '
                'dbsize firstfreelisttrunkpage totalfreelistpages '
                'schemacookie schemaformat defaultpagecachesize '
                'largestrootbtreepage textencoding userversion '
                'vacuummode applicationID reserved validfor version '
                'usablepagesize externalsize inheadersizevalid size')


# map encoding numbers to human-readable encoding string
# Note: while only the encodings 1 through 3 are allowed per the
# documentation on the sqlite3 website. We have found several
# databases with encoding 0. After some searching through the
# sqlite3 amalgamation source we found the following:
#
# 109621       if( encoding==0 ) encoding = SQLITE_UTF8;
#
# Thus, an encoding of 0 is also allowed and indicates UTF8
_encoding = {0: 'utf-8',
             1: 'utf-8',
             2: 'utf-16le',
             3: 'utf-16be'}


def dbheader(data, offset=0):
    ''' Parse given bytes as database header

    Arguments:
    - data     : bytes containing the database header
    - offset   : offset of the dbheader structure

    Returns:
    - dbheader : namedtuple with the parsed database header
    '''

    # database header is 100 bytes
    hsize = 100

    # parse bytes according to Database Header Format
    fmt = '>16sH' + 'B'*6 + 'I'*12 + '20sII'
    parsed = _unpack_from(fmt, data, offset)
    headerstring = parsed[0].decode('utf-8')
    pagesize = parsed[1]
    if pagesize == 1:
        pagesize = 65536
    writeversion = parsed[2]
    readversion = parsed[3]
    reservedspace = parsed[4]
    maxpayloadfraction = parsed[5]
    minpayloadfraction = parsed[6]
    leafpayloadfraction = parsed[7]
    filechangecounter = parsed[8]
    dbsize = parsed[9]
    firstfreelisttrunkpage = parsed[10]
    totalfreelistpages = parsed[11]
    schemacookie = parsed[12]
    schemaformat = parsed[13]
    defaultpagecachesize = parsed[14]
    largestrootbtreepage = parsed[15]
    textencoding = _encoding[parsed[16]]
    userversion = parsed[17]
    vacuummode = bool(parsed[18])
    applicationID = parsed[19]
    reserved = int.from_bytes(parsed[20], byteorder='big', signed=False)
    validfor = parsed[21]
    version = parsed[22]

    # calculated and derived fields
    usablepagesize = pagesize - reservedspace
    externalsize = int(len(data) / pagesize)
    inheadersizevalid = True
    if dbsize == 0 or filechangecounter != validfor:
        inheadersizevalid = False

    # validation
    if headerstring != 'SQLite format 3\x00':
        raise ValueError('header string should be SQLite format 3\x00')
    if pagesize not in [1] + [512 * i for i in range(1, 65)]:
        raise ValueError('pagesize must be a power of two between 512 '
                         'and 32768 inclusive or the value 1 to represent '
                         'page size of 65536')
    if writeversion not in [1, 2]:
        raise ValueError('write version should be 1 or 2')
    if readversion not in [1, 2]:
        raise ValueError('read version should be 1 or 2')
    if maxpayloadfraction != 64:
        raise ValueError('Max embedded payload fraction != 64')
    if minpayloadfraction != 32:
        raise ValueError('Min embedded payload fraction != 32')
    if leafpayloadfraction != 32:
        raise ValueError('Leaf payload fraction must != 32')
    # NOTE: the schema format is only allowed to be 1 through 4,
    # but similar to the encoding field, the actual sqlite3
    # source is a bit more relaxed with it's constraint. In the
    # amalgamation we find:
    #
    # 109651   /*
    # 109652   ** file_format==1    Version 3.0.0.
    # 109653   ** file_format==2    Version 3.1.3.  // ALTER TABLE ADD COLUMN
    # 109654   ** file_format==3    Version 3.1.4.  // ditto but with non-NULL defaults
    # 109655   ** file_format==4    Version 3.3.0.  // DESC indices.  Boolean constants
    # 109656   */
    # 109657   pDb->pSchema->file_format = (u8)meta[BTREE_FILE_FORMAT-1];
    # 109658   if( pDb->pSchema->file_format==0 ){
    # 109659     pDb->pSchema->file_format = 1;
    # 109660   }
    #
    # Thus, we allow schemaformat 0 as well.
    #
    # Also note that the schemaformat is not used in any way in the rest of
    # xsqlite's parsing and interpretation.
    if schemaformat not in [0, 1, 2, 3, 4]:
        raise ValueError('Supported schema formats are 0,1,2,3,4')
    if reserved != 0:
        raise ValueError('Data in reserved area of header should be 0x00.')

    return _dbheader(headerstring, pagesize, writeversion,
                     readversion, reservedspace, maxpayloadfraction,
                     minpayloadfraction, leafpayloadfraction,
                     filechangecounter, dbsize, firstfreelisttrunkpage,
                     totalfreelistpages, schemacookie, schemaformat,
                     defaultpagecachesize, largestrootbtreepage,
                     textencoding, userversion, vacuummode, applicationID,
                     reserved, validfor, version, usablepagesize,
                     externalsize, inheadersizevalid, hsize)


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


##########
# varint #
##########


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


# overflow page fields:
# - pagetype: 'overflow'
# - next_overflow_page: pagenumber of next overflowpage or 0 (eoc)
# - payload_offset: relative offset of the payload in the page (4)
# - reserved_offset: relative offset of the reserved area (usablepagesize)
# - reserved: the data stored in the reserved area for this page or None
# - size: the page size (passed in as variable)
# - payload: bytes with the payload
_overflowpage = _nt('overflowpage', 'pagetype next_overflow_page '
                                    'payload_offset reserved_offset size '
                                    'payload reserved')


def overflowpage(data, offset, pagesize, usablepagesize):
    ''' Parses data at given offset as overflowpage.

    Arguments:
    - data           : bytes containing the overflow page
    - offset         : offset of the page within the data
    - pagesize       : the size of a database page
    - usablepagesize : start of the reserved area withing the page

    Returns:
    - overflowpage  : a parsed overflow page

    Note that the last overflow page in a chain may not completely contain
    payload data. In other words, there may be slack in the chained overflow
    pages. This has to be determined by the caller, because for this
    cell-specific information is needed (the payloadsize).

    (Note that conceptually overflow is part of the cell)
    '''

    # read the next overflowpage pagenumber and restore btstr position
    next_overflow_page = _unpack_from('>I', data, offset)[0]

    # btree.c, line 5175:
    #    const u32 ovflSize = pBt->usableSize - 4;  /* Bytes content per ovfl page */

    # From this we learn that overflow pages also have a reserved area (if used)
    # and that the size of the overflow on a page is limited to usableSize minus 4 for 
    # the small header with the next overflow page

    # payload and reserved area
    start = offset + 4
    psize = usablepagesize - 4
    end = start + psize
    payload = data[start:end]

    # reserved area runs from end of cell content area to end of page
    res = None
    res_offset = None
    if pagesize > usablepagesize:
        res_offset = offset+usablepagesize
        res = data[res_offset:offset+pagesize]
        # make the offsets relative to page offset before returning
        res_offset = res_offset - offset

    return _overflowpage('overflow', next_overflow_page, 4, res_offset, 
                         pagesize, payload, res)


#######################
# freelist trunk page #
#######################

# When a page ends up on the freelist, it either becomes a freelisttrunk page
# or a freelistleafpage. In the first case, parts of the page are overwritten.
# In the second case, the entire page is left as is, and it is merely made
# unreachable from the original position (either since the overflow pointers to
# the page are no longer valid, or because the page is removed from some btree.

# freelist trunk page fields:
# - pagetype: 'freelist_trunk'
# - nextfreelisttrunkpage: pagenumber of next freelist trunk page or 0 (eoc)
# - leafpointercount: total number of leaf pointers on this page
# - freelistleafpointers: pagenumbers of the freelist leaf pages
# - unallocated_offset: relative offset of the unallocated space
# - unallocated: the data stored in the unallocated area for this page
# - unallocated_size : size of the unallocated space
# - reserved_offset: relative offset of the reserved area (usablepagesize)
# - reserved: the data stored in the reserved area for this page or None
# - size: the page size (passed in as variable)
_freelisttrunkpage = _nt('freelisttrunkpage',
                         'pagetype nextfreelisttrunkpage leafpointercount '
                         'freelistleafpointers unallocated_offset unallocated '
                         'unallocated_size reserved_offset reserved size')


def freelisttrunkpage(data, offset, pagesize, usablepagesize):
    ''' Parses data at given offset as freelist trunk page.

    Arguments:

    - data           : bytes containing the overflow page
    - offset         : offset of the page within the data
    - pagesize       : the size of a database page
    - usablepagesize : start of the reserved area withing the page

    Returns:
    - freelisttrunkpage : parsed freelist trunk page
    '''

    # leafpointers are 4 bytes wide
    lpsize = 4

    nextfreelisttrunkpage, leafpointercount = _unpack_from('>II', data, offset)

    # Check if the leafpointers fit in the usable pagesize
    if (8 + leafpointercount * lpsize) > usablepagesize:
        raise ValueError('page cannot hold that many leafpointers')

    fpstart = offset + 8
    fpend = fpstart + leafpointercount * lpsize

    fmt = '>' + 'I' * leafpointercount
    flpointers = _unpack_from(fmt, data, fpstart)

    # unallocated area is between pointers and reserved area
    unallocated = data[fpend:offset+usablepagesize]

    # reserved area runs from end of cell content area to end of page
    res = None
    res_offset = None
    if pagesize > usablepagesize:
        res_offset = offset+usablepagesize
        res = data[res_offset:offset+pagesize]
        # make the offsets relative to page offset before returning
        res_offset = res_offset - offset

    return _freelisttrunkpage('freelist_trunk', nextfreelisttrunkpage, 
                              leafpointercount, flpointers, fpend-offset, unallocated, 
                              usablepagesize-fpend, res_offset, res, pagesize)


######################
# freelist leaf page #
######################

# freelist leaf page fields:
# - pagetype: 'freelist_leaf'
# - unallocated_offset: relative offset of the unallocate space (0)
# - unallocated: the data stored in the unallocated area for this page
# - unallocated_size : size of the unallocated space
# - reserved_offset: relative offset of the reserved area (usablepagesize)
# - reserved: the data stored in the reserved area for this page or None
# - size: the page size (passed in as variable)
_freelistleafpage = _nt('freelistleafpage',
                        'pagetype unallocated_offset unallocated '
                        'unallocated_size reserved_offset reserved size')


def freelistleafpage(data, offset, pagesize, usablepagesize):
    ''' Parses data at given offset as freelist leaf page.

    Arguments:

    - data           : bytes containing the overflow page
    - offset         : offset of the page within the data
    - pagesize       : the size of a database page
    - usablepagesize : start of the reserved area withing the page

    Returns:
    - freelistleafpage : parsed freelist leaf page
    '''

    # define all up to reserved area as unallocated
    unallocated = data[offset:offset+usablepagesize]
    # reserved area runs from end of cell content area to end of page
    res = None
    res_offset = None
    if pagesize > usablepagesize:
        res_offset = offset+usablepagesize
        res = data[res_offset:offset+pagesize]
        # make the offsets relative to page offset before returning
        res_offset = res_offset - offset

    return _freelistleafpage('freelist_leaf', 0, unallocated, 
                             usablepagesize, res_offset, res, pagesize)


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



