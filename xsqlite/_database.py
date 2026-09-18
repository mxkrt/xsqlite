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
from struct import unpack_from as _unpack_from
import mmap as _mmap

from . import _structures
from . import _sql
from . import _decode
from ._wal import WalFile
from ._page import PageSource, PageType, Page, BtreePage
from ._page import FreeListLeafPage, FreeListTrunkPage
from ._sqlitemaster import SQLiteMaster


class Database():
    ''' class representing a SQLite3 database, optionally including wal or journal file '''


    def __init__(s, infile, wal=None, journal=None):
        ''' Load given file as Database object, with optional WAL or journal

        Arguments:
        - infile  : path or file-like object for main database file
        - wal     : optional path or file-like object for WAL file
        - journal : optional path or file-like object for journal file

        Only one of wal or journal may be given. If not given, we try to detect
        the WAL or journal within the same directory as the main database file
        '''

        if wal is not None and journal is not None:
            raise ValueError("Only one of 'wal' or 'journal' can be given")

        # load and mmap the database file
        s._load_db(infile)

        # attempt to load walfile
        s._load_wal(wal)

        if not hasattr(s, 'walfile'):
            # attempt to load journal
            s._load_journal(journal)

        # parse the database header from page 1
        if s.is_page_visible_in_wal(1) is True:
            hdr_frame = s.walfile.get_visible_page_frame(1)
            s.header = s._parse_header(hdr_frame.contents[0:100])
        else:
            s.header = s._parse_header(s.data[0:100])

        # calculated size of database in pages based on available data
        s.externalsize = int(len(s.data) / s.header.pagesize)

        # check if the header indicates wal mode or not
        s.walmode = False
        if s.header.writeversion == 2 and s.header.readversion == 2:
            s.walmode = True
        elif s.header.writeversion != s.header.readversion:
            raise ValueError("writeversion and readversion expected equal")

        if hasattr(s, 'walfile'):
            if s.header.pagesize != s.walfile.header.pagesize:
                raise ValueError("WAL and database header disagree on pagesize")

        return

        # TODO: everything below here should be checked for passing the
        #       correct data if it is a page from WA


        # parse sqlite_master table (stored in btree starting in page 1)
        s.sqlite_master = SQLiteMaster(s.rowidrecords(1), s.header.textencoding)

        # create table objects for each of the defined tables
        s.tables = _OD()
        for tbl_name, sqlite_master_rec in s.sqlite_master.tables.items():
            tbl = Table(sqlite_master_rec, s.header.textencoding)
            s.tables[tbl_name] = tbl

        # add a list of tablenames for convenience
        s.tablenames = [n for n in s.tables.keys()]


    def _load_db(s, infile):
        ''' open and mmap the given database file '''

        if isinstance(infile, str):
            s.filename = _path.realpath(_path.expanduser(infile))
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


    def _load_wal(s, wal):
        ''' load and mmap the given wal file '''

        if wal is not None:
            s.walfile = WalFile(wal, usablepagesize)
            return
        elif s.filename is not None:
            # check if a WAL file exists in the same directory as the main db file
            if _path.exists(s.filename+'-wal'):
                s.walfile = WalFile(s.filename+'-wal')
                return


    def _load_journal(s, journal):
        ''' load and mmap the journal file '''

        if isinstance(journal, str):
            # open and mmap the file (parsing not yet supported)
            s.journalfilename = _path.realpath(_path.expanduser(journal))
            if _stat(s.journalfilename).st_size != 0:
                jfile = open(s.journalfilename, 'rb')
                s.journaldata = _mmap.mmap(jfile.fileno(), 0, access=_mmap.ACCESS_READ)
        elif isinstance(journal, _mmap.mmap):
            # we already have an mmapped file
            s.journaldata = journal
        elif hasattr(journal, 'read') and hasattr(journal, 'seek'):
            s.journaldata = _mmap.mmap(jfile.fileno(), 0, access=_mmap.ACCESS_READ)
        elif journal is not None:
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


    def _parse_header(s, data):
        ''' Parse the database header in given 100 bytes '''

        # namedtuple representing the database header
        _hdr_t = _nt('database_header',
                     'headerstring pagesize writeversion '
                     'readversion reservedspace maxpayloadfraction '
                     'minpayloadfraction leafpayloadfraction '
                     'filechangecounter dbsize firstfreelisttrunkpage '
                     'totalfreelistpages schemacookie schemaformat '
                     'defaultpagecachesize largestrootbtreepage '
                     'textencoding userversion vacuummode applicationID '
                     'reserved validfor version usablepagesize '
                     'inheadersizevalid')

        # parse bytes according to Database Header Format
        fmt = '>16sH' + 'B'*6 + 'I'*12 + '20sII'
        parsed = _unpack_from(fmt, data)

        headerstring = parsed[0].decode('utf-8')
        if headerstring != 'SQLite format 3\x00':
            raise ValueError('header string should be SQLite format 3\x00')

        # database page size in bytes. Size 1 means 65536
        pagesize = parsed[1]
        if pagesize == 1:
            pagesize = 65536
        if pagesize not in [1] + [512 * i for i in range(1, 65)]:
            raise ValueError('pagesize must be a power of two between 512 '
                             'and 32768 inclusive or the value 1 to represent '
                             'page size of 65536')

        # file format write version. 1 for legacy; 2 for WAL.
        writeversion = parsed[2]
        if writeversion not in [1, 2]:
            raise ValueError('write version should be 1 or 2')

        # file format read version. 1 for legacy; 2 for WAL.
        readversion = parsed[3]
        if readversion not in [1, 2]:
            raise ValueError('read version should be 1 or 2')

        # Bytes of unused "reserved" space at the of each page. Usually 0.
        reservedspace = parsed[4]

        # maximum embedded payload fraction.
        maxpayloadfraction = parsed[5]
        if maxpayloadfraction != 64:
            raise ValueError('Max embedded payload fraction != 64')

        # minimum embedded payload fraction.
        minpayloadfraction = parsed[6]
        if minpayloadfraction != 32:
            raise ValueError('Min embedded payload fraction != 32')

        # Leaf payload fraction.
        leafpayloadfraction = parsed[7]
        if leafpayloadfraction != 32:
            raise ValueError('Leaf payload fraction must != 32')

        # File change counter. Note: the change counter
        # might not be incremented on each transaction in WAL mode.
        filechangecounter = parsed[8]

        # Size of the database file in pages, a.k.a. the "in-header
        # database size".
        dbsize = parsed[9]

        # Page number of the first freelist trunk page.
        firstfreelisttrunkpage = parsed[10]

        # Total number of freelist pages.
        totalfreelistpages = parsed[11]

        # The schema cookie.
        schemacookie = parsed[12]

        # The schema format number.
        schemaformat = parsed[13]
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

        # Default page cache size.
        defaultpagecachesize = parsed[14]

        # The page number of the largest root b-tree page
        # when in auto- or incremental vacuum mode, zero otherwise.
        largestrootbtreepage = parsed[15]

        # The database text encoding.
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
        textencoding = _encoding[parsed[16]]

        # The "user version" as read and set by the user_version
        # pragma. Not used by SQLite internally.
        userversion = parsed[17]

        # True (non-zero) for incremental-vacuum mode. False otherwise.
        vacuummode = bool(parsed[18])

        # "Application ID" set by PRAGMA application_id.
        applicationID = parsed[19]

        # 20 bytes reserved for expansion. Must be zero.
        reserved = int.from_bytes(parsed[20], byteorder='big', signed=False)
        if reserved != 0:
            raise ValueError('Data in reserved area of header should be 0x00.')

        # The version-valid-for number
        validfor = parsed[21]

        # SQLITE_VERSION_NUMBER field
        version = parsed[22]

        # calculated usable page size
        usablepagesize = pagesize - reservedspace

        # indicates if in-header database size is valid
        #   The 'in header database size' is only valid if it is nonzero
        #   and if the filechange counter matches the validfor number.
        inheadersizevalid = True
        if dbsize == 0 or filechangecounter != validfor:
            inheadersizevalid = False

        return _hdr_t(headerstring, pagesize, writeversion,
                      readversion, reservedspace, maxpayloadfraction,
                      minpayloadfraction, leafpayloadfraction,
                      filechangecounter, dbsize, firstfreelisttrunkpage,
                      totalfreelistpages, schemacookie, schemaformat,
                      defaultpagecachesize, largestrootbtreepage,
                      textencoding, userversion, vacuummode, applicationID,
                      reserved, validfor, version, usablepagesize,
                      inheadersizevalid)


    def is_page_visible_in_wal(s, pagenumber):
        ''' return True if page is visible in WAL file, False otherwise '''

        if hasattr(s, 'walfile'):
            return s.walfile.is_page_visible(pagenumber)
        return False


    def get_page_offset(s, pagenumber):
        ''' Return offset of visible page in database or WAL for pagenumber '''

        if pagenumber < 1:
            raise ValueError('pagenumbers start at 1 in SQLite fileformat')

        if s.header.inheadersizevalid:
            if pagenumber > s.header.dbsize:
                raise ValueError('pagenumber > inheader dbsize')

        if s.is_page_visible_in_wal(pagenumber):
            # return the offset of the page data in the WAL file
            walframe = s.walfile.get_visible_page_frame(pagenumber)
            return walframe.contents_offset

        if pagenumber > s.externalsize:
            raise ValueError('pagenumber > externalsize')

        # return the offset in the main database
        return (pagenumber - 1) * s.header.pagesize


    def get_page_data(s, pagenumber):
        ''' Return visible page data for given pagenumber '''

        if s.is_page_visible_in_wal(pagenumber):
            walframe = s.walfile.get_visible_page_frame(pagenumber)
            return walframe.contents

        start = s.get_page_offset(pagenumber)
        end = start + s.header.pagesize
        return s.data[start:end]


    def get_btreepage(s, pagenumber):
        ''' Parse the visible page for given pagenumber as Btree Page '''

        # get the page offset
        offset = s.get_page_offset(pagenumber)

        if s.is_page_visible_in_wal(pagenumber):
            pagesource = PageSource.WALFile
            data = s.walfile.data
        else:
            pagesource = PageSource.DatabaseFile
            data = s.data

        return BtreePage(data, offset, pagenumber, s.header.pagesize,
                         pagesource, s.header.usablepagesize)


    def freelist_pages(s):
        ''' Generate sequence of visible freelist pages in database '''

        def _fpages(pnum):
            ''' yields all freelist pages starting at the given trunkpage '''

            # when the next freelist trunkpage number is 0, we are done
            if pnum == 0:
                return

            # get the page offset
            offset = s.get_page_offset(pnum)

            if s.is_page_visible_in_wal(pnum):
                pagesource = PageSource.WALFile
                data = s.walfile.data
            else:
                pagesource = PageSource.DatabaseFile
                data = s.data

            # parse and yield the freelist trunkpage
            tpage = FreeListTrunkPage(data, offset, pnum, s.header.pagesize,
                                      pagesource, s.header.usablepagesize)
            yield tpage

            # yield all pages pointed to by the leaf pointers in the trunkpage
            for pnum in tpage.freelistleafpointers:
                offset = s.get_page_offset(pnum)
                if s.is_page_visible_in_wal(pnum):
                    pagesource = PageSource.WALFile
                    data = s.walfile.data
                else:
                    pagesource = PageSource.DatabaseFile
                    data = s.data

                lpage = FreeListLeafPage(data, offset, pnum,
                                         s.header.pagesize, pagesource,
                                         s.header.usablepagesize)
                yield lpage

            # process the next FreeList Trunk Page
            for pg in _fpages(tpage.nextfreelisttrunkpage):
                yield pg

        for pg in _fpages(s.header.firstfreelisttrunkpage):
            yield pg


# WORK IN PROGRESS BELOW THIS LINE #

    def get_page_by_rowid(s, rootpagenumber, rowid):
        ''' Find the page that (should) hold the record with given rowid

        The term 'should' is chosen deliberately: When a record is removed it
        is no longer accessible on the corresponding page, but when navigating
        the tree you still end up on the same page. Also, when you start the
        search on a page that is in the wrong subtree, you will end up with the
        wrong page altogether, so you should call this with the root page of
        the table that you are interested in. Finally, if the rowid is larger
        than the highest stored rowid, you will receive the last page in the
        btree, regardless of whether or not the rowid is actually stored there.
        '''

        rootpage = s.get_btreepage(rootpagenumber)

        if rootpage.page.pagetype not in ['table_leaf', 'table_interior']:
            raise ValueError('need the pagenumber of a table page')

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
        ''' Generates a sequence of btree pages starting at given pagenumber. The
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
        rootpage = s.get_btreepage(rootpagenumber)
        yield rootpage

        # visit the children of interior pages
        if rootpage.pagetype == PageType.TableBtreeInterior or \
                rootpage.pagetype == PageType.IndexBtreeInterior:
            # first the left pointers
            for cell in rootpage.cells:
                subpagenum = cell.left_child_pointer
                for subpage in s.treewalker(subpagenum):
                    yield subpage
            # and finally the rightmost pointer
            rmp = rootpage.rightmost_pointer
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
            if not s.header.inheadersizevalid and pagenumber > s.externalsize:
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

        if rootpage.pagetype != PageType.TableBtreeLeaf:
            if rootpage.pagetype != PageType.TableBtreeInterior:
                raise ValueError('Given page is not a Table Btree Page')

        # walk the tree
        tree = s.treewalker(rootpagenumber)

        # for table B-tree pages, records are only stored in the table leaf pages
        for page in tree:
            if page.pagetype == PageType.TableBtreeLeaf:
                # yield records on this page in rowid order, not in
                # cell-location order
                rowids_on_page = [r for r in page.rowidmap.keys()]
                rowids_on_page.sort()
                for rowid in rowids_on_page:
                    cellnum = page.rowidmap[rowid]
                    parsed_cell = page.cells[cellnum]
                    # make logical cell out of raw cell
                    pload = Payload(s, parsed_cell)
                    cell = Cell(parsed_cell, pload, cellnum, page.pagenum, page.pageoffset, page.pagesource)
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
