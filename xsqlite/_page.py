''' _page.py - functionality related to sqlite3 pages

Copyright (c) 2014-2026 Netherlands Forensic Institute - MIT License
Copyright (c) 2025-2026 mxkrt@lsjam.nl - MIT License
'''

from enum import Enum as _Enum
from collections import namedtuple as _nt
from struct import unpack_from as _unpack_from

from ._varint import varint, varints


class PageSource(_Enum):
    ''' Enum for setting the source of a page (i.e. WAL or main db) '''

    DatabaseFile = 0
    WALFile = 1


class PageType(_Enum):
    ''' the type of page '''

    IndexBtreeInterior = 2
    TableBtreeInterior = 5
    IndexBtreeLeaf = 10
    TableBtreeLeaf = 13
    FreelistTrunk = 20
    FreelistLeaf = 21
    PayloadOverflow = 30
    PointerMap = 40
    LockByte = 50


# namedtuple representing a parsed Table B-Tree Interior Cell
# - left_child_pointer: left child pointer (pagenumber)
# - key: integer key
# - cell_offset: relative offset of the cell within the page
# - cell_size: size of the cell
_table_interior_cell = _nt('table_interior_cell',
                           'left_child_pointer key cell_offset cell_size')


# namedtuple representing a parsed Table B-Tree Leaf Cell
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


# namedtuple representing a parsed Index B-Tree Interior Cell
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


# namedtuple representing a parsed Index B-Tree Leaf Cell
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


# namedtuple representing a parsed Freeblocks
# - offset         : relative offset of this freeblock within page
# - next_freeblock : relative offset of next freeblock within page
# - size           : size of the current freeblock
# - data_offset    : offset of data in page freeblock (offset+4)
# - get_bytes      : bytes stored in the freeblock (incl. header)
_freeblock = _nt('freeblock', 'offset next_freeblock size data_offset get_bytes')


class Page():
    ''' Base class for database pages '''


    def __init__(s):
        ''' initialize Page object '''

        # check if the required fields are set
        if not hasattr(s, "data"):
            raise ValueError("Page: data not initialized")
        if not hasattr(s, "pagenum"):
            raise ValueError("Page: pagenumber not initialized")
        if not hasattr(s, "offset"):
            raise ValueError("Page: offset not initialized")
        if not hasattr(s, "size"):
            raise ValueError("Page: size not initialized")
        if not hasattr(s, "pagesource"):
            raise ValueError("Page: pagesource not initialized")


    def get_bytes(s):
        ''' return byte array with all page data '''

        return s.data[s.offset:s.offset+s.size]


class BtreePage(Page):
    ''' Class representing a Btree Page '''

    def __init__(s, data, offset, pagenum, pagesize, pagesource, usablepagesize):
        ''' initialize a btree page from given data at given offset

        Arguments:
        - data           : data containing the btree page at given offset
        - offset         : offset of the btree page structure
        - pagenum        : the pagenumber (derived from offset or wal frame)
        - pagesize       : the size of the page (derived from database header)
        - pagesource     : PageSource value (DatabaseFile or WalFile)
        - usablepagesize : usable page size as calculated from database header
        '''

        s.data = data
        s.offset = offset
        s.size = pagesize
        s.pagenum = pagenum
        s.pagesource = pagesource
        s.usablepagesize = usablepagesize

        if pagenum == 1:
            s.header_offset = 100
        else:
            s.header_offset = 0

        # parse the page header
        s._parse_pageheader()

        # the cellpointers are directly after the header
        s.cell_pointers_offset = s.header_offset + s.headersize

        # the size of the cell pointer area (a cell pointer is two bytes wide)
        s.cell_pointers_size = s.cell_count * 2

        # TODO: 
        # TODO: next step is to parse the freeblocks
        # collect the freeblocks on this page
        ##fblocks = []
        ##fboffset = pgheader.first_freeblock_offset
        ##while fboffset != 0:
        ##    fblock = freeblock(data, offset, fboffset)
        ##    fboffset = fblock.next_freeblock
        ##    fblocks.append(fblock)


        # initialize superclass
        super().__init__()


    def cells(s):
        ''' API function to return list of cells '''

        if hasattr(s, "_cells"):
            return s._cells

        # parse the cells, depending on pagetype
        if s.pagetype == PageType.TableBtreeInterior:
            s._cells = [s._parse_table_interior_cell(cp) for cp in s.cell_pointers()]
            return s._cells

        elif s.pagetype == PageType.TableBtreeLeaf:
            s._cells = [s._parse_table_leaf_cell(cp) for cp in s.cell_pointers()]
            # add a mapping from rowid to cell_number for convenience
            s._rowidmap = {c.rowid: idx for idx,c in enumerate(s.cells())}
            s.max_rowid = max(s._rowidmap.keys())
            s.min_rowid = min(s._rowidmap.keys())
            return s._cells

        elif s.pagetype == PageType.IndexBtreeInterior:
            s._cells = [s._parse_index_interior_cell(cp) for cp in s.cell_pointers()]
            return s._cells

        elif s.pagetype == PageType.IndexBtreeLeaf:
            s._cells = [s._parse_index_leaf_cell(cp) for cp in s.cell_pointers()]
            return s._cells


    def cell_by_rowid(s, rowid):
        ''' API function to return cell for given rowid '''

        if s.pagetype != PageType.TableBtreeLeaf:
            raise ValueError("only Table Btree Leaf pags have cells with rowids")

        if not hasattr(s, "_rowidmap"):
            # initialize by parsing the cells
            s.cells()

        return s._rowidmap[rowid]


    def _parse_pageheader(s):
        ''' Parse the pageheader of the BtreePage '''

        # offset is relative to page offset
        offset = s.offset + s.header_offset

        # parse first 8 bytes
        hsize = 8
        fmt = '>BHHHB'
        parsed = _unpack_from(fmt, s.data, offset)

        # determine the pagetype
        pgtype = parsed[0]
        if pgtype == 2:
            s.pagetype = PageType.IndexBtreeInterior
        elif pgtype == 5:
            s.pagetype = PageType.TableBtreeInterior
        elif pgtype == 10:
            s.pagetype = PageType.IndexBtreeLeaf
        elif pgtype == 13:
            s.pagetype = PageType.TableBtreeLeaf
        else:
            raise ValueError('invalid b-tree page type {:d}'.format(pgtype))

        # first_freeblock_offset: relative offset of the first freeblock.
        s.first_freeblock_offset = parsed[1]

        # cellcount: number of cells on this page.
        s.cell_count = parsed[2]


        # cell_content_offset: relative offset of cell content area.
        cellarea = parsed[3]
        # in some fields (including this one), value 0 means 65536
        if cellarea == 0:
            s.cell_content_offset = 65536
        else:
            s.cell_content_offset = cellarea

        # fragmented_freebyte_count: total number of fragmented free bytes.
        s.fragmented_freebytes = parsed[4]

        # rightmost_pointer: the right-most pointer for interior pages.
        s.rightmost_pointer = None
        if pgtype in {2,5}:
            rmp_offset = offset + hsize
            s.rightmost_pointer = _unpack_from('>I', s.data, rmp_offset)[0]
            hsize += 4

        # size of the header
        s.headersize = hsize

        if s.first_freeblock_offset > s.usablepagesize:
            raise ValueError('first freeblock offset outside usable page area.')
        if s.cell_content_offset > s.usablepagesize:
            raise ValueError('cell content area offset outside usable page area.')
        if s.fragmented_freebytes > (s.usablepagesize - cellarea):
            raise ValueError('free byte count exceeds cell content area size.')


    def cell_pointers(s):
        ''' Parse the cellpointer area of the BtreePage '''

        if hasattr(s, '_cell_pointers'):
            return s._cell_pointers

        # offset is relative to page offset
        offset = s.offset + s.cell_pointers_offset

        fmt = '>' + 'H' * s.cell_count
        cpointers = _unpack_from(fmt, s.data, offset)
        # cellpointer value 0 means 65536
        s._cell_pointers = [65536 if p == 0 else p for p in cpointers]
        return s._cell_pointers


    def _inline_payload_size(s, payloadsize):
        ''' Calculates the inline size for the given payloadsize.

        Arguments:
        - payloadsize    : the size of the full payload

        Returns:
        - inlinesize     : total size of payload that can be stored inline
        '''

        if s.pagetype == PageType.TableBtreeLeaf:
            celltype = 'table'
        elif s.pagetype == PageType.IndexBtreeLeaf:
            celltype = 'index'
        elif s.pagetype == PageType.IndexBtreeInterior:
            celltype = 'index'
        else:
            raise ValueError("function called for unexpected pagetype")

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
        U = s.usablepagesize

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


    def _parse_table_interior_cell(s, cell_offset):
        ''' Parse bytes at given offset in page as Table B-Tree Interior Cell
        '''

        # offset is relative to page offset
        offset = s.offset + cell_offset

        # read left child pointer
        lcp = _unpack_from('>I', s.data, offset)[0]
        # read the varint key
        key, key_width = varint(s.data, offset + 4)
        cellsize = 4 + key_width
        return _table_interior_cell(lcp, key, cell_offset, cellsize)


    def _parse_table_leaf_cell(s, cell_offset):
        ''' Parse bytes at given offset as Table B-Tree Leaf Cell
        '''

        # offset is relative to page offset
        offset = s.offset + cell_offset

        # table B-Tree leaf cell starts with payloadsize and rowid
        payloadsize, payloadsize_width = varint(s.data, offset)
        rowid, rowid_width = varint(s.data, offset + payloadsize_width)

        # determine dimensions and location of inline payload
        ipsize = s._inline_payload_size(payloadsize)
        payloadstart = payloadsize_width + rowid_width
        # create slice for inline payload
        ipstart = payloadstart + offset
        ipend = ipstart + ipsize
        payload = s.data[ipstart:ipend]
        # make ipstart relative before returning
        ipstart = ipstart - s.offset

        # determine size of the cell structure thus far
        cellsize = payloadsize_width + rowid_width + ipsize

        # if the payload overflows, we need to read first overflow page pointer
        fop = None
        if payloadsize > ipsize:
            # read 4 byte integer for first overflow page (fop)
            fop = _unpack_from('>I', s.data, offset + cellsize)[0]
            cellsize += 4

        return _table_leaf_cell(payloadsize, rowid, fop, cell_offset, ipstart,
                                cellsize, payload)


    def _parse_index_interior_cell(s, cell_offset):
        ''' Parse bytes at given offset as Index B-Tree Interior Cell
        '''

        # offset is relative to page offset
        offset = s.offset + cell_offset

        # read left child pointer
        lcp = _unpack_from('>I', s.data, offset)[0]

        # index B-Tree interior cell has key payloadsize at offset 4
        payloadsize, payloadsize_width = varint(s.data, offset + 4)

        # determine dimensions and location of inline payload
        ipsize = s._inline_payload_size(payloadsize)
        payloadstart = payloadsize_width + 4

        # create slice for inline payload
        ipstart = payloadstart + offset
        ipend = ipstart + ipsize
        payload = s.data[ipstart:ipend]
        # make ipstart relative before returning
        ipstart = ipstart - s.offset

        # determine size of the cell thus far
        cellsize = payloadsize_width + ipsize + 4

        # if the payload overflows, we need to read first overflow page pointer
        fop = None
        if payloadsize > ipsize:
            # read 4 byte integer for first overflow page (fop)
            fop = _unpack_from('>I', s.data, offset + cellsize)[0]
            cellsize += 4

        return _index_interior_cell(lcp, payloadsize, fop, cell_offset, ipstart,
                                    cellsize, payload)


    def _parse_index_leaf_cell(s, cell_offset):
        ''' Parse bytes at given offset as Index B-Tree Leaf Cell
        '''

        # offset is relative to page offset
        offset = s.offset + cell_offset

        # index B-Tree leaf cell starts with payloadsize
        payloadsize, payloadsize_width = varint(s.data, offset)

        # determine dimensions and location of inline payload
        ipsize = s._inline_payload_size(payloadsize)
        payloadstart = payloadsize_width

        # create slice for inline payload
        ipstart = payloadstart + offset
        ipend = ipstart + ipsize
        payload = s.data[ipstart:ipend]
        # make ipstart relative before returning
        ipstart = ipstart - s.offset

        # determine size of the cell structure so far
        cellsize = payloadsize_width + ipsize

        # if the payload overflows, we need to read first overflow page pointer
        fop = None
        if payloadsize > ipsize:
            # read 4 byte integer for first overflow page (fop)
            fop = _unpack_from('>I', s.data, offset + cellsize)[0]
            cellsize += 4

        return _index_leaf_cell(payloadsize, fop, cell_offset, ipstart,
                                cellsize, payload)


    def _parse_freeblock(s, fb_offset):
        ''' Parse data at given offset as freeblock ''' 

        # offset is relative to page offset
        offset = s.offset + fb_offset

        # read next freeblock pointer and freeblocksize
        next_fb, size = _unpack_from('>HH', s.data, offset)
        
        def get_bytes():
            ''' returns the data for this freeblock as bytes, excluding header '''
            return s.data[offset:offset+size]

        return _freeblock(fb_offset, next_fb, size, fb_offset+4, get_bytes)


# btree page fields:
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
