''' database.py - functionality related to sqlite3 database files

Copyright (c) 2014-2026 Netherlands Forensic Institute - MIT License
Copyright (c) 2025-2026 mxkrt@lsjam.nl - MIT License

The implementation of the structures and the logic is based on the description
of the database format as given on: https://www.sqlite.org/fileformat.html

NOTE: indices, views and triggers are not implemented. WITHOUT ROWID tables are
also not implemented. WAL support is implemented, but JOURNAL support is not. '''

from collections import namedtuple as _nt
from collections import OrderedDict as _OD
from functools import partial as _partial
import os.path as _path
from os import stat as _stat
from enum import Enum as _Enum
from struct import unpack as _unpack
import mmap as _mmap

from . import _exceptions
from . import _structures
from . import _sql
from . import _decode
from ._wal import WalFile
from ._sqlitemaster import SQLiteMaster


class Database():
    ''' class representing a SQLite3 database, optionally including wal or journal file '''


    def __init__(s, infile, wal=None, journal=None):
        ''' open the given file as Database object, optionally including wal or journal file

        infile, wal and journal can be filepath (string) or an already opened file-like objects

        If wal or journal are not given, we try to detect if a WAL or journal file exists
        in the same directory as the main database file.
        '''

        if wal is not None and journal is not None:
            raise _exceptions.InvalidArgumentException("only one of wal or journal can be given")

        if isinstance(infile, str):
            # parse the file as constant bitstream
            s.filename = _path.abspath(_path.expanduser(infile))
            dbfile = open(s.filename, 'rb')
            s.data = _mmap.mmap(dbfile.fileno(), 0, access=_mmap.ACCESS_READ)
        elif isinstance(infile, _mmap.mmap):
            # we already have an mmapped file
            s.filename = None
            s.data = infile
        elif hasattr(infile, 'read') and hasattr(infile, 'seek'):
            # read the bytes from the file as constant bitstream
            s.filename = None
            s.data = _mmap.mmap(infile.fileno(), 0, access=_mmap.ACCESS_READ)
        else:
            raise ValueError("expected filename, mmapped file or file-like object")

        if wal is not None:
            s.walfile = WalFile(wal)
        else:
            # check if a WAL file exists in the same directory as the main db file
            if s.filename is not None:
                if _path.exists(s.filename+'-wal'):
                    s.walfile = WalFile(s.filename+'-wal')

        if journal is not None:
            if isinstance(journal, str):
                # open and mmap the file (parsing not yet supported)
                s.journalfilename = _path.abspath(_path.expanduser(journal))
                if _stat(s.journalfilename).st_size != 0:
                    jfile = open(s.journalfilename, 'rb')
                    s.journaldata = _mmap.mmap(jfile.fileno(), 0, access=_mmap.ACCESS_READ)
            elif isinstance(journal, _mmap.mmap):
                # we already have an mmapped file
                s.journaldata = journal
            elif hasattr(journal, 'read') and hasattr(journal, 'seek'):
                s.journaldata = _mmap.mmap(jfile.fileno(), 0, access=_mmap.ACCESS_READ)
            else:
                raise ValueError("expected filename, mmapped file or file-like object")

        else:
            # check if a journal file exists in the same directory as the main db file
            if s.filename is not None:
                dirname = _path.dirname(s.filename)
                basename = _path.basename(s.filename)
                journalpath = _path.join(dirname, basename+'-journal')
                if _path.exists(journalpath):
                    s.journalfilename = journalpath
                    if _stat(s.journalfilename).st_size != 0:
                        jfile = open(s.journalfilename, 'rb')
                        s.journaldata = _mmap.mmap(jfile.fileno(), 0, access=_mmap.ACCESS_READ)

        if hasattr(s, 'walfile') and hasattr(s, 'journaldata'):
            raise ValueError('database appears to have a WAL and a journal file!')

        # parse the header at offset 0
        s.header = _structures.dbheader(s.data, offset=0)

        if hasattr(s, 'walfile'):
            if s.header.pagesize != s.walfile.header.pagesize:
                raise _exceptions.AssumptionBrokenException("wal and main db disagree on pagesize")

        # check if the header indicates wal mode or not
        if s.header.writeversion == 2 and s.header.readversion == 2:
            s.walmode = True
        elif s.header.writeversion != s.header.readversion:
            raise _exceptions.AssumptionBrokenException("writeversion and readversion differ")
        else:
            s.walmode = False

        # check if total freelistpages match header
        total_freelist_pages = len(list(s.freelist_pages()))
        if s.header.totalfreelistpages != total_freelist_pages:
            if hasattr(s, 'walfile'):
                # in this case, it might be the case that the
                # header has not yet been updated since there is
                # still a checkpoint operation to be done.
                pass
            else:
                raise ValueError('total nr of freelistpages incorrect')

        # parse sqlite_master table (stored in btree starting in page 1)
        s.sqlite_master = SQLiteMaster(s.rowidrecords(1), s.header.textencoding)

        # create table objects for each of the defined tables
        s.tables = _OD()
        for tbl_name, sqlite_master_rec in s.sqlite_master.tables.items():
            tbl = Table(sqlite_master_rec, s.header.textencoding)
            s.tables[tbl_name] = tbl

        # add a list of tablenames for convenience
        s.tablenames = [n for n in s.tables.keys()]


    def get_pageoffset(s, pagenumber):
        ''' function that returns the offset of the page with given pagenumber
        '''

        if pagenumber < 1:
            raise _exceptions.InvalidArgumentException('pagenumbers start at 1 in SQLite fileformat')

        # if the page is an active page in the WAL file, return the WAL frame contents offset
        if s.page_is_in_wal(pagenumber):
            walframe = s.walfile.get_page_frame(pagenumber)
            return walframe.contents_offset

        if s.header.inheadersizevalid and pagenumber > s.header.dbsize:
            raise _exceptions.InvalidArgumentException('pagenumber points beyond EOF')

        if not s.header.inheadersizevalid and pagenumber > s.header.externalsize:
            raise _exceptions.InvalidArgumentException('pagenumber points beyond EOF')

        return (pagenumber - 1) * s.header.pagesize


    def get_page_data(s, pagenumber):
        ''' function that returns the page as block object '''

        # first check if we should get the page from the main database or from the WAL
        if hasattr(s, 'walfile'):
            walframe = s.walfile.get_page_frame(pagenumber)
            if walframe is not None:
                return walframe.contents

        start = s.get_pageoffset(pagenumber)
        end = start + s.header.pagesize
        return s.data[start:end]


    def page_is_in_wal(s, pagenumber):
        ''' return True if page is in WAL file, False otherwise '''

        if hasattr(s, 'walfile'):
            walframe = s.walfile.get_page_frame(pagenumber)
            if walframe is not None:
                return True
        return False


    def get_btreepage(s, pagenumber):
        ''' Parse given page as btree page and return a parsed page

        A page object is a simple object combining a pagenumber, pageoffset and a
        parsed page. This function is a wrapper for _structures.btree_page.
        '''

        pg_offset = s.get_pageoffset(pagenumber)
        # TODO: instead of slicing, pass the correct mmapped data (main or wal)
        # and the pg_offset into _structures.btree_page?
        pg_data = s.get_page_data(pagenumber)
        # start with the page with the given pagenumber
        isheaderpage = False
        if pagenumber == 1:
            isheaderpage = True

        # use offset 0 here, since data contains only the single page to be parsed
        page = _structures.btree_page(pg_data, 0, s.header.pagesize, s.header.usablepagesize, isheaderpage)
        from_wal = s.page_is_in_wal(pagenumber)
        return Page(pg_data, page, pagenumber, pg_offset, from_wal)


    def get_page_by_rowid(s, rootpagenumber, rowid):
        ''' Returns the page that should contain the record with the given rowid.

        The term 'should' is chosen deliberately: When a record is removed it is no longer
        accessible on the corresponding page, but when navigating the tree you still end up on the
        same page. Also, when you start the search on a page that is in the wrong subtree, you will
        end up with the wrong page altogether, so you should call this with the root page of the
        table that you are interested in. Finally, if the rowid is larger than the highest stored
        rowid, you will receive the last page in the btree, regardless of whether or not the rowid
        is actually stored there.

        Uses the btreepage function to return a page object, see documentation there for details on
        the returnvalue.  '''

        rootpage = s.get_btreepage(rootpagenumber)

        if rootpage.page.pagetype not in ['table_leaf', 'table_interior']:
            raise _exceptions.InvalidArgumentException('need the pagenumber of a table page')

        if rootpage.page.pagetype == 'table_leaf':
            return rootpage

        if rootpage.page.pagetype == 'table_interior':
            if rowid > rootpage.page.cells[-1].key:
                # go right: rmp points to subtree were keys are > cells[-1].key
                return s.get_page_by_rowid(rootpage.page.header.rightmost_pointer, rowid)
            else:
                # go left :leftpointer points to pages were all keys are <= key
                # from documentation: pointers to the left of a X refer to b-tree
                # pages on which all keys are less than or equal to X.
                for cell in rootpage.page.cells:
                    lp = cell.left_child_pointer
                    if rowid <= cell.key:
                        return s.get_page_by_rowid(lp, rowid)


    def treewalker(s, rootpagenumber):
        ''' Generates a sequence of btree pages for a given btree-page object. The
        generated sequence represents the subtree under the given page. Both
        the interior and the leaf table pages are returned so that this can be used
        for both index and table trees (index pages contain data, especially for
        WITHOUT_ROWID tables). Normally one should call this with the rootpage of a
        table or index, but you can also start at a lower level in the tree.

        Pages from subtrees are yielded in the same order as they are stored in the
        b-tree, so natural ordering by the table's key (mostly rowid) is honoured.
        The interior pages are yielded prior to descending into the subtree defined
        by the corresponding interior page.

        Uses the get_btreepage function to yield a page object, see documentation
        there for details on the returnvalue.
        '''

        # start with the rootpage
        btpage = s.get_btreepage(rootpagenumber)

        yield btpage

        if btpage.page.pagetype in ['table_leaf', 'index_leaf']:
            # leaf pages have no subtree
            pass

        elif btpage.page.pagetype in ['table_interior', 'index_interior']:
            # interior pages have subtrees, descent into them
            for cell in btpage.page.cells:
                subpagenum = cell.left_child_pointer
                for subpage in s.treewalker(subpagenum):
                    yield subpage

            # don't forget the rightmost pointer
            rmp = btpage.page.header.rightmost_pointer
            for subpage in s.treewalker(rmp):
                yield subpage


    def cellwalker(s, rootpagenumber):
        ''' Generates logical cells for a (sub)tree starting at rootpagenumber

        A logical cell is a thin wrapper around the cell as returned by
        _structures.cell(), which includes the pagenumber, cellnumber and a
        function to retrieve the cell payload.
        '''

        tree = s.treewalker(rootpagenumber)

        for pg in tree:
            if pg.page.pagetype == 'table_leaf':
                for idx, c in enumerate(pg.page.cells):
                    pload = Payload(s, c)
                    yield Cell(c, pload, idx, pg.pagenumber, pg.pageoffset, pg.pagesource)


    def get_cell_by_rowid(s, rootpagenumber, rowid):
        ''' Returns the logical cell with the given rowid by searching the b-tree.

        A logical cell is a thin wrapper around the cell as returned by
        _structures.cell(), which includes the pagenumber, cellnumber and a
        function to retrieve the cell payload.

        See comments in page_by_rowid function for details on where to start the
        search. If the record is not in the subtree that you start searching in, or
        if the record has been deleted, None is returned.
        '''
        pg = s.get_page_by_rowid(rootpagenumber, rowid)

        if rowid in pg.page.rowidmap:
            cellnumber = pg.page.rowidmap[rowid]
            cell = pg.page.cells[cellnumber]
            pload = Payload(s, cell)
            return Cell(cell, pload, cellnumber, pg.pagenumber, pg.pageoffset, pg.pagesource)
        return None


    def _freelist_pages(s, freelist_trunkpage_number):
        ''' yields all freelist pages starting at the given trunkpage '''

        # when the next freelist trunkpage number is 0, we are done
        if freelist_trunkpage_number == 0:
            return

        # parse and yield the freelist trunkpage
        pg_data = s.get_page_data(freelist_trunkpage_number)
        pageoffset = s.get_pageoffset(freelist_trunkpage_number)
        rootfltpage = _structures.freelisttrunkpage(pg_data, 0, s.header.pagesize, s.header.usablepagesize)
        from_wal = s.page_is_in_wal(freelist_trunkpage_number)
        yield Page(pg_data, rootfltpage, freelist_trunkpage_number, pageoffset, from_wal)

        # yield all pages pointed to by the leaf pointers in the trunkpage
        for pgnum in rootfltpage.freelistleafpointers:
            pg_data = s.get_page_data(pgnum)
            pg_offset = s.get_pageoffset(pgnum)
            leafpage = _structures.freelistleafpage(pg_data, 0, s.header.pagesize, s.header.usablepagesize)
            from_wal = s.page_is_in_wal(pgnum)
            yield Page(pg_data, leafpage, pgnum, pg_offset, from_wal)

        # continue with the next freelist trunk page
        for pg in s._freelist_pages(rootfltpage.nextfreelisttrunkpage):
            yield pg


    def freelist_pages(s):
        ''' Generates a sequence of all freelist pages within the SQLite file. '''

        for pg in s._freelist_pages(s.header.firstfreelisttrunkpage):
            yield pg


    def superseded_pages(s):
        ''' Generates a sequence of all pages that have been superseded by a WAL page

        The superseded pages originate from the main database file, for
        superseded or outdated pages from the WAL itself use the WalFile API
        functions '''

        if not hasattr(s, 'walfile'):
            # No WAL file, no superseded pages
            return

        # pages from the database file that are superseded by a page from a WAL frame
        for pagenumber in s.walfile._checkpoint_frames.keys():
            # first check if there is an associated page in the database, since
            # the WAL can have additional pages that are not yet in database file.
            # In this case, there is no superseded page for this WAL page in the
            # main database, so we can skip over these
            if s.header.inheadersizevalid and pagenumber > s.header.dbsize:
                continue
            if not s.header.inheadersizevalid and pagenumber > s.header.externalsize:
                continue

            # determine the pageoffset within the main database file
            pageoffset = (pagenumber - 1) * s.header.pagesize

            # get the page_data from the main database file, not via get_page_data API
            data = s.data[pageoffset:pageoffset+s.header.pagesize]
            # unpack as a generic page
            page = _structures.genericpage(data, 0, s.header.pagesize)
            from_wal = False
            yield Page(data, page, pagenumber, pageoffset, from_wal)


    def rowidrecords(s, rootpagenumber):
        ''' Generates rowid-records for the table-btree starting at the given page.

        Rootpagenumber has to be the number of a table-btree page. There is no
        sanity check wether this is actually the rootpage of the tree, it just
        starts handing out records from that point in the tree (intended
        behaviour).
        '''

        # parse the rootpage to check pagetype
        rootpage = s.get_btreepage(rootpagenumber)

        if rootpage.page.pagetype not in ['table_leaf', 'table_interior']:
            raise ValueError('rowidrecords should be called on table b-tree page')

        # walk the tree
        tree = s.treewalker(rootpagenumber)

        # for table B-tree pages, records are only stored in the table leaf pages
        for page in tree:
            if page.page.pagetype == 'table_leaf':
                # yield records on this page in rowid order, not in
                # cell-location order
                rowids_on_page = [r for r in page.page.rowidmap.keys()]
                rowids_on_page.sort()
                for rowid in rowids_on_page:
                    cellnum = page.page.rowidmap[rowid]
                    parsed_cell = page.page.cells[cellnum]
                    # make logical cell out of raw cell
                    pload = Payload(s, parsed_cell)
                    cell = Cell(parsed_cell, pload, cellnum, page.pagenumber, page.pageoffset, page.pagesource)
                    yield RowidRecord(cell)


    def rowidrecord_by_rowid(rootpagenumber, rowid):
        ''' Returns rowidrecord with given rowid by searching b-tree under rootpage

        See comments in page_by_rowid function for details on where to start the
        search. If the record is not in the subtree that you start searching in, or
        if the record has been deleted, None is returned.

        Returns a rowidrecord object, see rowidrecord function for details on
        format

        Arguments:
        rootpagenumber : page to start searching on
        rowid          : the rowid you are looking for
        '''

        cell = s.get_cell_by_rowid(rootpagenumber, rowid)
        if cell is None:
            return None

        return RowidRecord(cell)


    def recordheaders(s, cls):
        ''' Generates sequence of recordheaders from a sequence of logical cells.

        The sequence of logical cells can be generated using the _logical.cells()
        function.

        A logical recordheader is a thin wrapper around the recordheader as returned by
        _structures.recordheader(), which includes the pagenumber and cellnumber in
        which the recordheader exists

        Arguments:
        cls            : a sequence of cells
        '''

        for c in cls:
            data = b''.join(c.payload.blocklist)
            yield RecordHeader(_structures.recordheader(data, 0), c.cellnumber, c.pagenumber)


class Column():
    ''' class that represent a column in a Table '''

    def __init__(s, sql_parsed_columndef):
        ''' initialize a Column object from the given parsed column definition '''

        s.name = sql_parsed_columndef.name
        s.typename = sql_parsed_columndef.coltype
        s.affinity = sql_parsed_columndef.affinity
        s.notnull = sql_parsed_columndef.notnull
        s.unique = sql_parsed_columndef.unique
        s.default = sql_parsed_columndef.default
        s.primary = sql_parsed_columndef.primary
        s.pkey_sort = sql_parsed_columndef.pkey_sort
        s.pkey_autoincrement = sql_parsed_columndef.pkey_autoincrement
        s.constraints = sql_parsed_columndef.constraints


class Table():
    ''' class that represents a the structure of a table an SQLite3 database

    The returned object has two decoder properties. These can be used to decode
    a single raw record. In order to decode a sequence of raw records from the
    table 'tbl' you can do something like::

        tblrecs = (tbl.user_decoder(r) for r in db.rowidrecords(tbl.rootpage))
    '''

    def __init__(s, sqlite_master_record, textencoding):
        ''' initialize the table object from the given SQLiteMasterRecord '''

        s.name = sqlite_master_record.name
        s.rootpage = sqlite_master_record.rootpage

        # reduce column definition to a subset of fields
        s.columns = [Column(c) for c in sqlite_master_record.columns]

        s.ipk_col = sqlite_master_record.ipk_column
        s.withoutrowid = sqlite_master_record.withoutrowid

        # prepare body decoder
        colnames = [c.name for c in s.columns]
        affinities = [c.affinity for c in s.columns]
        s.decoder = _decode.BodyDecoder(textencoding, affinities)

        # prepare record viewer
        s.viewer = _decode.RecordViewer(colnames, s.decoder, s.ipk_col)


class Payload():
    ''' class representing the payload for a single record, including optional overflow '''

    # a namedtuple to represent the overflow
    _overflow = _nt('overflow', 'blocklist slack overflowpages')


    def __init__(s, db, cell):
        ''' create payload object for given cell, including optional overflow

        Note that the cell argument can be a raw cell as returned by the
        _structures.cell() function, but it can also be the cell_wrapper
        defined in the Database class '''

        if isinstance(cell, Cell):
            # we need the raw cell for this function
            cell = cell.parsed_cell

        s.payloadsize = cell.payloadsize

        # construct a list of block objects
        s.blocklist = [cell.inline_payload]
        oflow = s._get_overflow(db, cell)
        s.overflowpages = []
        s.overflowslack = None
        if oflow is not None:
            # extend the list with the overflow blocks
            s.blocklist.extend(oflow.blocklist)
            s.overflowpages = oflow.overflowpages
            s.overflowslack = oflow.slack


    def _get_overflow(s, db, cell):
        ''' returns an overflow object for a cell or None if no overflow exists

        Note that the cell argument can be a raw cell as returned by the
        _structures.cell() function, but it can also be the wrapper defined
        in this class

        Returns an overflow object, which consists of the following fields:
            - blocklist: a list of blocks containing the payload bytes
            - slack: a single block contains slack, or None
            - overflowpages: a list of pagenumbers from which overflow was fetched
        '''
        if isinstance(cell, Cell):
            # we need the raw cell for this function
            cell = cell.parsed_cell

        if cell.payloadsize > len(cell.inline_payload):
            if cell.first_overflow_page is None:
                raise ValueError('cell has overflow, but no first_overflow_page')
            toread = cell.payloadsize - len(cell.inline_payload)
            return s._collect_overflow(db, toread, cell.first_overflow_page)
        return None


    def _collect_overflow(s, db, toread, pagenumber):
        ''' Creates overflow object by parsing overflowpages starting at pagenumber

        The toread parameter is used to check if overflow chain ends at the same
        moment at which enough bytes are read. In addition, it is used to
        separate payload from slack if the payload doesn't end at the last byte
        of the last overflow page. Note that I've not yet seen slack in
        test databases, so maybe payload calculations are such that no payload
        slack exists. This remains to be investigated.

        Returns an overflow object, see overflow function for details
        '''

        pload = []
        overflowpages = []
        slack = None
        nextpage = pagenumber

        while nextpage != 0:
            overflowpages.append(nextpage)
            if toread <= 0:
                raise ValueError('nextpage available but no more bytes to read')

            # get the next overflowpage
            next_pg_data = db.get_page_data(nextpage)

            # start at offset 0, since we have created a sub bitstream
            opage = _structures.overflowpage(next_pg_data, 0, db.header.pagesize, db.header.usablepagesize)
            nextpage = opage.next_overflow_page
            if toread >= len(opage.payload):
                pload.append(opage.payload)
                toread -= len(opage.payload)
            else:
                remainder = opage.payload[0:toread]
                slack = opage.payload[toread:]
                pload.append(remainder)
                toread = 0

        return Payload._overflow(pload, slack, overflowpages)


class PageSource(_Enum):
    ''' use to identify the source of the page (i.e. WAL or main db) '''

    DatabaseFile = 0
    WALFile = 1


class Page():
    ''' wrapper for parsed pages with some extra meta-data '''


    def __init__(s, data, parsed_page, pagenum=None, offset=None, from_wal=False):
        ''' initialize Page object, optionally setting pagenumber and offset to given values '''

        s.pagenumber = pagenum
        s.pageoffset = offset
        s.data = data
        s.page = parsed_page
        if from_wal is True:
            s.pagesource = PageSource.WALFile
        else:
            s.pagesource = PageSource.DatabaseFile


class Cell():
    ''' wrapper for parsed cell with some extra meta-data '''

    def __init__(s, parsed_cell, payload, cellnumber, pagenumber=None, pageoffset=None, pagesource=None):
        ''' initialize Cell object, optionally setting pagenumber '''

        s.pagenumber = pagenumber
        s.pageoffset = pageoffset
        s.pagesource = pagesource
        s.cellnumber = cellnumber
        s.parsed_cell = parsed_cell
        s.payload = payload


class RecordHeader():
    ''' wrapper for parsed recordheader with some extra meta-data '''

    def __init__(s, parsed_recordheader, cellnumber, pagenumber=None):
        ''' initialize RecordHeader, optionally setting pagenumber '''

        s.parsed_recordheader = parsed_recordheader
        s.cellnumber = cellnumber
        s.pagenumber = pagenumber


class RowidRecord():
    ''' wrapper around recordformat with some extra metadata

    A rowid-record is defined here as a detailed version of what is returned by
    the _structures.recordformat() function, including information about the page
    and cell that the record is stored in. This information is only available
    if a logical cell is passed into this function. If a raw cell is given,
    pagenumber and cellnumber will be None.

    A rowid-record has the following fields:

        - pagenumber: pagenumber that contains the cell, or None
        - pagesource: source of the recordpage (main db, WAL)
        - pageoffset: offset of the page that contains the cell, or None
        - cellnumber: cellnumber that contains the record, or None
        - rowid: the rowid of the record
        - header: the recordformat header object
        - body: the recordformat body object
        - inlinesize: size of the inline recordheader and body (inline payload)
        - payloadsize: size of the cell payload, including overflow
        - has_overflow: whether or not the cell has payload overflow

        When the table has a INTEGER PRIMARY KEY, this is what is stored in the
        rowid and the record itself contains a NULL value for that column.
    '''

    def __init__(s, cell):
        ''' initialize RowidRecord from given cell'''

        if isinstance(cell, Cell):
            # we have a logical cell, extract required info
            s.pagenumber = cell.pagenumber
            s.pageoffset = cell.pageoffset
            s.pagesource = cell.pagesource
            s.cellnumber = cell.cellnumber
            s.rowid = cell.parsed_cell.rowid
            s.inlinesize = len(cell.parsed_cell.inline_payload)
            s.payloadsize = cell.parsed_cell.payloadsize
            s.payloadoffset = cell.parsed_cell.inline_payload_offset
            pload = cell.payload
        else:
            s.pagenumber = None
            s.pageoffset = None
            s.pagesource = None
            s.cellnumber = None
            s.rowid = cell.rowid
            s.inlinesize = len(cell.inline_payload)
            s.payloadsize = cell.payloadsize
            s.payloadoffset = cell.inline_payload_offset
            pload = Payload(s, cell)

        if len(pload.overflowpages) == 0:
            s.has_overflow = False
        else:
            s.has_overflow = True

        # combine the individual blocks into a combined blocklist
        payload_data = b''.join(pload.blocklist)
        # check if length matches defined payloadsize (btstr is in bits)
        if len(payload_data) != s.payloadsize:
            raise RuntimeError('combined payload is not the correct size')

        # parse as recordformat struct
        recdata = _structures.recordformat(payload_data, 0)
        s.header = recdata.header
        s.body = recdata.body

        # sanity check on payload size and total size of header + body
        sizes = [_structures.serialtype(t).size for t in recdata.header.serialtypes]
        definedsize = sum(sizes) + recdata.header.headersize
        if definedsize != s.payloadsize:
            raise RuntimeError('mismatch between size in recordheader and payloadsize.')
