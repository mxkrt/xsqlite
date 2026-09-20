''' database.py - functionality related to sqlite3 database files

Copyright (c) 2014-2026 Netherlands Forensic Institute - MIT License
Copyright (c) 2025-2026 mxkrt@lsjam.nl - MIT License

The implementation of the structures and the logic is based on the description
of the database format as given on: https://www.sqlite.org/fileformat.html

NOTE: indices, views and triggers are not implemented. WITHOUT ROWID tables are
also not implemented. WAL support is implemented, but JOURNAL support is not. '''

from collections import namedtuple as _nt
import os.path as _path
from os import stat as _stat
from struct import unpack_from as _unpack_from
import mmap as _mmap

from ._wal import WalFile
from ._page import PageSource, PageType, Page, BtreePage
from ._page import FreeListLeafPage, FreeListTrunkPage
from ._page import OverflowPage, GenericPage
from ._sqlitemaster import SQLiteMaster
from ._record import recordformat


# namedtuple representing a rowid record with extra metadata
_rowidrecord_t = _nt('rowidrecord', 'pagenum pageoffset pagesource '
                                    'cellnum cell_offset rowid header body')


class Database():
    ''' class representing a SQLite3 database '''


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
            s.header = s.parse_header(hdr_frame.contents[0:100])
        else:
            s.header = s.parse_header(s.data[0:100])

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

        # parse sqlite_master table (stored in btree starting in page 1)
        s.sqlite_master = SQLiteMaster(s.rowidrecords(1), s.header.textencoding)

        # create alias for sqlite_master tables
        s.tables = s.sqlite_master.tables

        # add a list of tablenames for convenience
        s.tablenames = tuple(n for n in s.tables.keys())


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


    def parse_header(s, data, offset=0):
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
        parsed = _unpack_from(fmt, data, offset)

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


    def page_offset(s, pagenumber, ignore_wal=False):
        ''' Return offset of visible page in database or WAL for pagenumber

        if ignore_wal is True, return the offset of the page
        in the main database, ignoring the WAL file
        '''

        if pagenumber < 1:
            raise ValueError('pagenumbers start at 1 in SQLite fileformat')

        if s.header.inheadersizevalid:
            if pagenumber > s.header.dbsize:
                raise ValueError('pagenumber > inheader dbsize')

        if ignore_wal is False:
            if s.is_page_visible_in_wal(pagenumber):
                # return the offset of the page data in the WAL file
                walframe = s.walfile.get_visible_page_frame(pagenumber)
                return walframe.contents_offset

        if pagenumber > s.externalsize:
            raise ValueError('pagenumber > externalsize')

        # return the offset in the main database
        return (pagenumber - 1) * s.header.pagesize


    def _get_page_props(s, pagenumber, ignore_wal=False):
        ''' get offset, source and data object for page '''

        # get the page offset
        offset = s.page_offset(pagenumber, ignore_wal)

        # defaults
        pagesource = PageSource.DatabaseFile
        data = s.data

        if ignore_wal is False:
            if s.is_page_visible_in_wal(pagenumber):
                pagesource = PageSource.WALFile
                data = s.walfile.data

        return offset, pagesource, data


    def page_data(s, pagenumber, ignore_wal=False):
        ''' Return page data for visible page with given pagenumber '''

        offset, pagesource, data = s._get_page_props(pagenumber, ignore_wal)
        return data[offset:offset + s.header.pagesize]


    def btreepage(s, pagenumber, ignore_wal=False):
        ''' Parse the visible page for given pagenumber as Btree Page
        '''

        offset, pagesource, data = s._get_page_props(pagenumber, ignore_wal)
        return BtreePage(data, offset, pagenumber, s.header.pagesize,
                         pagesource, s.header.usablepagesize)


    def freelisttrunkpage(s, pagenumber, ignore_wal=False):
        ''' Parse the visible page for given pagenumber as Freelist Trunk Page '''

        offset, pagesource, data = s._get_page_props(pagenumber, ignore_wal)
        return FreeListTrunkPage(data, offset, pagenumber, s.header.pagesize,
                                 pagesource, s.header.usablepagesize)


    def freelistleafpage(s, pagenumber, ignore_wal=False):
        ''' Parse the visible page for given pagenumber as Freelist Leaf Page '''

        offset, pagesource, data = s._get_page_props(pagenumber, ignore_wal)
        return FreeListLeafPage(data, offset, pagenumber, s.header.pagesize,
                                pagesource, s.header.usablepagesize)


    def overflowpage(s, pagenumber, ignore_wal=False):
        ''' Parse the visible page for given pagenumber as Overflow Page '''

        offset, pagesource, data = s._get_page_props(pagenumber, ignore_wal)
        return OverflowPage(data, offset, pagenumber, s.header.pagesize,
                            pagesource, s.header.usablepagesize)


    def freelist_pages(s):
        ''' Generate sequence of visible freelist pages in database '''

        def _fpages(pnum):
            ''' yields all freelist pages starting at the given trunkpage '''

            # when the next freelist trunkpage number is 0, we are done
            if pnum == 0:
                return

            tpage = s.freelisttrunkpage(pnum)
            yield tpage

            # yield all pages pointed to by the leaf pointers in the trunkpage
            for pnum in tpage.freelistleafpointers:
                yield s.freelistleafpage(pnum)

            # process the next FreeList Trunk Page
            for pg in _fpages(tpage.nextfreelisttrunkpage):
                yield pg

        for pg in _fpages(s.header.firstfreelisttrunkpage):
            yield pg


    def btreewalker(s, rootpagenumber):
        ''' Generate Btree pages starting at given rootpage number.

        The generated sequence represents the subtree under the given page.
        Both the interior and the leaf table pages are returned so that this
        can be used for both index and table trees (index pages contain data,
        especially for WITHOUT_ROWID tables). Normally one should call this
        with the rootpage of a table or index, but you can also start at a
        lower level in the tree.

        Pages from subtrees are yielded in the same order as they are stored in
        the b-tree, so natural ordering by the table's key (mostly rowid) is
        honoured. The interior pages are yielded prior to descending into the
        subtree defined by the corresponding interior page.
        '''

        # start with the rootpage
        rootpage = s.btreepage(rootpagenumber)
        yield rootpage

        # visit the children of interior pages
        if rootpage.pagetype == PageType.TableBtreeInterior or \
                rootpage.pagetype == PageType.IndexBtreeInterior:
            # first the left pointers
            for cell in rootpage.cells:
                subpagenum = cell.left_child_pointer
                for subpage in s.btreewalker(subpagenum):
                    yield subpage
            # and finally the rightmost pointer
            rmp = rootpage.rightmost_pointer
            for subpage in s.btreewalker(rmp):
                yield subpage


    def page_by_rowid(s, rootpagenumber, rowid):
        ''' Return page that holds the record with given rowid

        NOTE: When a record is removed it is no longer accessible on the
        corresponding page, but the Btree will still lead to a page where the
        record can be potentially stored (again). Before returning the page it
        is checked if the rowid actually occurs within the page.  If not, a
        ValueError is raised, which indicates an allocated record with given
        rowid does not exist.

        Obviously, this function should be called with the rootpage of the
        table of interest.
        '''

        rootpage = s.btreepage(rootpagenumber)

        # a Table Btree Leaf page has no children
        if rootpage.pagetype == PageType.TableBtreeLeaf:
            if rowid not in rootpage.rowidmap:
                msg = f'Btree points to page {rootpage.pagenum}, but no'
                msg += f' allocated record with rowid {rowid} exists'
                raise ValueError(msg)
            return rootpage

        elif rootpage.pagetype == PageType.TableBtreeInterior:
            if rowid > rootpage.cells[-1].key:
                # go right: rmp points to subtree were keys are > cells[-1].key
                return s.page_by_rowid(rootpage.rightmost_pointer, rowid)
            else:
                # go left :leftpointer points to pages were all keys are <= key
                # from documentation: pointers to the left of a X refer to b-tree
                # pages on which all keys are less than or equal to X.
                for cell in rootpage.cells:
                    lp = cell.left_child_pointer
                    if rowid <= cell.key:
                        return s.page_by_rowid(lp, rowid)

        else:
            raise ValueError('Given rootpage is not a Table Btree Page')


    def _payload_overflow(s, cell):
        ''' return payload overflow for given parsed cell '''

        if cell.payloadsize <= len(cell.inline_payload):
            if cell.first_overflow_page is not None:
                raise ValueError('inconsistency in payloadsize and overflow')
            return None

        # if we get here, we expect overflow
        if cell.first_overflow_page is None:
            raise ValueError('missing first_overflow_page number')

        # a namedtuple to represent the overflow
        _overflow_t = _nt('overflow', 'data slack overflowpages')

        # collect the required overflow in a bytearray
        data = bytearray()
        # The toread parameter is used to check if overflow chain ends at the same
        # moment at which enough bytes are read. In addition, it is used to
        # separate payload from slack if the payload doesn't end at the last byte
        # of the last overflow page.
        toread = cell.payloadsize - len(cell.inline_payload)

        # the last overflow may theoretically have slack
        slack = None

        # collect the pagenumbers of the overflow pages
        opages = []

        # iterate over the overflow pages and collect the data
        nextpage = cell.first_overflow_page

        while nextpage != 0:
            # add the page to list of overflowpages
            opages.append(nextpage)

            if toread <= 0:
                raise ValueError('nextpage found, but no bytes to read left')

            # parse the overflow page
            opage = s.overflowpage(nextpage)
            nextpage = opage.next_overflow_page

            # copy the data into the data bytearray
            if toread >= opage.contents_size:
                data.extend(opage.get_contents())
                toread -= opage.contents_size
            else:
                contents = opage.get_contents()
                data.extend(contents[0:toread])
                slack = contents[toread:]
                toread = 0

        return _overflow_t(bytes(data), slack, opages)


    def payload(s, cell):
        ''' return payload bytes for given cell, including optional overflow
        '''

        overflow = s._payload_overflow(cell)
        if overflow is None:
            return cell.inline_payload
        else:
            return cell.inline_payload + overflow.data


    def rowidrecords(s, rootpagenumber):
        ''' Generates rowidrecords for the btree starting at the given page.

        Rootpagenumber has to be the number of a table-btree page. There is no
        sanity check wether this is actually the rootpage of the tree, it just
        starts handing out records from that point in the tree (intended
        behaviour).
        '''

        # parse the rootpage to check pagetype
        rootpage = s.btreepage(rootpagenumber)

        if rootpage.pagetype != PageType.TableBtreeLeaf:
            if rootpage.pagetype != PageType.TableBtreeInterior:
                raise ValueError('Given page is not a Table Btree Page')

        # walk the tree
        tree = s.btreewalker(rootpagenumber)

        # for table B-tree pages, records are only stored in the table leaf pages
        for page in tree:
            if page.pagetype == PageType.TableBtreeLeaf:
                # yield records on this page in rowid order
                for rowid in sorted(page.rowidmap.keys()):
                    cnum = page.rowidmap[rowid]
                    cell = page.cells[cnum]
                    pload = s.payload(cell)
                    rec = recordformat(pload, 0)
                    yield _rowidrecord_t(page.pagenum, page.offset,
                                         page.pagesource, cnum,
                                         cell.offset, rowid, rec.header,
                                         rec.body)


    def rowidrecord(s, rootpagenumber, rowid):
        ''' Returns rowidrecord for given rowid

        Arguments:
        rootpagenumber : page to start searching on
        rowid          : the rowid you are looking for
        '''

        try:
            page = s.page_by_rowid(rootpagenumber, rowid)
        except ValueError:
            return None

        if rowid in page.rowidmap:
            cnum = page.rowidmap[rowid]
            cell = page.cells[cnum]
            pload = s.payload(cell)
            rec = recordformat(pload, 0)
            return _rowidrecord_t(page.pagenum, page.offset,
                                  page.pagesource, cnum,
                                  cell.offset, rowid, rec.header,
                                  rec.body)


    def cell(s, rootpagenumber, rowid):
        ''' Return cell for given rowid '''

        try:
            page = s.page_by_rowid(rootpagenumber, rowid)
        except ValueError:
            return None

        if rowid in page.rowidmap:
            cnum = page.rowidmap[rowid]
            cell = page.cells[cnum]
            return cell


    def superseded_pages(s):
        ''' Generates sequence of pages in main db supserseded by the WAL

        The sequence contains all pages for which a newer version exists in the
        visible frames in the WAL (newest versions of each page below mxFrame)
        '''

        if not hasattr(s, 'walfile'):
            # No WAL file, no superseded pages
            return

        # we read the pages from the main database file
        pagesource = PageSource.DatabaseFile

        # iterate over the visible frames to determine the pagenumbers
        # of pages that are superseded in the main database
        for frame in s.walfile.visible_frames():
            pgnum = frame.pagenumber
            # first check if there is an associated page in the database, since
            # the WAL can have additional pages that are not yet in database file.
            # In this case, there is no superseded page for this WAL page in the
            # main database, so we can skip over these
            if pgnum > s.externalsize:
                continue
            offset = s.page_offset(pgnum, ignore_wal=True)
            yield GenericPage(s.data, offset, pgnum, s.header.pagesize,
                              pagesource, s.header.usablepagesize)
