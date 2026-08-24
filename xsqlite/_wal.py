''' _wal.py - Functionality to deal with WAL files.

Copyright (c) 2014-2026 Netherlands Forensic Institute - MIT License
Copyright (c) 2025-2026 mxkrt@lsjam.nl - MIT License
'''

from struct import unpack as _unpack
from collections import namedtuple as _nt
from struct import unpack_from as _unpack_from
import os.path as _path
import mmap as _mmap
from os import stat as _stat

from . import _exceptions
from . import _structures
from ._page import Page, PageSource


def walchecksum(integers, s0=0, s1=0):
    ''' computes the crc for the given sequence of integers '''

    for i in range(0, len(integers), 2):
        s0 += integers[i] + s1
        # limit to lower 32 bits
        s0 = s0 & 0xffffffff
        s1 += integers[i+1] + s0
        # limit to lower 32 bits
        s1 = s1 & 0xffffffff
    return s0, s1


class WalFile():
    ''' class representing the WAL file associated with a database

    From sqlite documentation:

    A WAL file consists of a header followed by zero or more "frames". Each
    frame records the revised content of a single page from the database file.
    All changes to the database are recorded by writing frames into the WAL.
    Transactions commit when a frame is written that contains a commit marker.
    A single WAL can and usually does record multiple transactions.
    Periodically, the content of the WAL is transferred back into the database
    file in an operation called a "checkpoint".

    A single WAL file can be reused multiple times. In other words, the WAL can
    fill up with frames and then be checkpointed and then new frames can
    overwrite the old ones. A WAL always grows from beginning toward the end.
    Checksums and counters attached to each frame are used to determine which
    frames within the WAL are valid and which are leftovers from prior
    checkpoints.  '''

    def __init__(s, file):
        ''' initialize a WAL file object from the given file

        Arguments:
        - file : a filename, a file-like object or an mmapped file

        Returns:
        - WalFile : initialized WALFile object
        '''

        if isinstance(file, str):
            # open and mmap the file and parse as WalFile
            s.filename = _path.realpath(_path.expanduser(file))
            if _stat(s.filename).st_size != 0:
                wfile = open(s.filename, 'rb')
                s.data = _mmap.mmap(wfile.fileno(), 0, access=_mmap.ACCESS_READ)
            else:
                print(f"[!] WalFile {s.filename} has size 0, ignored!")
        elif isinstance(file, _mmap.mmap):
            # we already have an mmapped file
            s.filename = None
            s.data = file
        elif hasattr(file, 'read') and hasattr(file, 'seek'):
            # a file-like-object, mmap
            s.filename = None
            s.data = _mmap.mmap(file.fileno(), 0, access=_mmap.ACCESS_READ)
        else:
            raise ValueError("expected filename, mmapped file or file-like object")

        # wal file size
        s.filesize = s.data.size()

        # parse the walheader
        s.header = s.walheader(s.data[0:32], 0)

        # and extract the properties to WalFile properties
        # TODO: remove these and update references accordingly
        s.pagesize = s.header.pagesize
        s.checkpoint_sequence_number = s.header.checkpoint_sequence_number
        s.salt1 = s.header.salt1
        s.salt2 = s.header.salt2
        s.checksum1 = s.header.checksum1
        s.checksum2 = s.header.checksum2
        s.checksum_endianness = s.header.checksum_endianness

        # amount of bytes available for frames is filesize minus header
        frame_bytecount = s.filesize - 32
        # each frame is pagesize + frameheader size
        s.frame_size = s.pagesize + 24
        # total number of frames is thus:
        s.frame_count = frame_bytecount // s.frame_size
        if frame_bytecount % s.frame_size != 0:

            # We have seen examples of WAL files where an additional
            # frame header exists at the end of the WAL file, with
            # some data that is not a full pagesize. This can happen
            # for various reasons, for example when the framesize has been
            # modified during the lifetime of the database, or if the
            # file has been truncated to a multiple of the filesystem
            # blocksize.

            # The existence of such slack should not hinder the processing
            # of the WAL file, thus instead of failing here, we include this
            # remaining data as slack.

            s.slack_size = s.filesize - 32 - (s.frame_count * s.frame_size)
            if s.slack_size > s.frame_size:
                raise ValueError("a mistake was made in slack calculation")

            s.slack_offset = 32 + (s.frame_count * s.frame_size)
            s.slack = s.data[s.slack_offset:s.slack_offset+s.slack_size]

        # from the sqlite amalgamation source file we learn (line numbers added):

        # 51188 ** A frame is considered valid if and only if the following conditions are¬
        # 51189 ** true:¬
        # 51190 **¬
        # 51191 **    (1) The salt-1 and salt-2 values in the frame-header match¬
        # 51192 **        salt values in the wal-header¬
        # 51193 **¬
        # 51194 **    (2) The checksum values in the final 8 bytes of the frame-header¬
        # 51195 **        exactly match the checksum computed consecutively on the¬
        # 51196 **        WAL header and the first 8 bytes and the content of all frames¬
        # 51197 **        up to and including the current frame.¬

        # so first determine the sequence of frames with valid checksums (2) by computing the
        # checksum of each frame using the previous checksum as input. Stores the last page with a
        # valid checksum in the last_valid_checksum_frame property.
        s._determine_last_valid_checksum()

        # next determine which of the frames have the same checksum as defined in the
        # wal header. Stores 4 properties: first_current_frame, last_current_frame,
        # first_outdated_frame and last_outdated_frame.
        s._check_frame_salt_values()

        # determine the last valid frame that is also a commit frame
        s._determine_mxFrame()

        # So now we have two sets of frames: those that are valid and that are still to be copied
        # into the database, which are all the frames prior to and including the mxFrame. And we
        # have the outdated frames, which are all frames beyond the mxFrame.

        # However, even within the valid frames, we can have outdated versions of the same page
        # (i.e. when multiple changes have been done sequentially). When multiple frames exist that
        # pertain to the same database page, the latest (i.e. sequentially closest to the mxFrame)
        # version is copied into the database by the checkpointer. This next function mimics the
        # checkpointer by building two dictionaries: One with a mapping of pagenumber to framenumber
        # for the latest (i.e. up to date) frame and one with a mapping of pagenumber to a list
        # of outdated/superseded framenumbers
        s._determine_checkpoint_frames()

        # We now have two dictionaries with the most recent and the outdated frames. These are used
        # as the basis for three functions to the WalFile API:
        #
        # - get_page_frame    : returns the most recent page frame for the given pageframe
        # - superseded_frames : generates frames below mxFrame that are superseded by a newer frame
        # - allocated_frames  : generates the most recent page frames


    def walheader(s, data, offset=0):
        ''' Parses given bytes as WAL header
        '''

        _walheader = _nt('wal_header', 'magic file_format_version pagesize checkpoint_sequence_number '
                                       'salt1 salt2 checksum1 checksum2 checksum_endianness')



        fmt = '>IIIIIIII'
        parsed = _unpack_from(fmt, data, offset)

        # Magic number. 0x377f0682 or 0x377f0683
        magic = parsed[0]
        # File format version. Currently 3007000
        file_format_version = parsed[1]
        # Database page size. Example: 1024
        pagesize = parsed[2]
        # Checkpoint sequence number
        checkpoint_sequence_number = parsed[3]
        # Random integer incremented with each checkpoint
        salt1 = parsed[4]
        # Different random number for each checkpoint
        salt2 = parsed[5]
        # checksum1: First part of a checksum on the first 24 bytes of header
        checksum1 = parsed[6]
        # checksum2: Second part of the checksum on the first 24 bytes of header
        checksum2 = parsed[7]

        # the endianness is only used in the checksum computation, the
        # values in the header are still big endian
        if magic == 0x377f0683:
            endianness = 'big'
        elif magic == 0x377f0682:
            endianness = 'little'
        else:
            raise ValueError('unknown magic value encountered in WAL file')

        if file_format_version != 3007000:
            raise ValueError('unexpected file format version in WAL file')

        if pagesize not in [2**i for i in range(9,17)]:
            raise ValueError('pagesize is not a power of two between 512 and 65536 inclusive')

        # calculate the checksum according to endianess
        if endianness == 'little':
            integers = _unpack_from('<IIIIII', data, 0)
        if endianness == 'big':
            integers = _unpack_from('>IIIIII', data, 0)
        calc_checksum1, calc_checksum2 = walchecksum(integers)

        # validation
        if calc_checksum1 != checksum1:
            raise ValueError('checksum1 in WAL header is incorrect')
        if calc_checksum2 != checksum2:
            raise ValueError('checksum2 in WAL header is incorrect')

        return _walheader(magic, file_format_version, pagesize,
                          checkpoint_sequence_number, salt1,
                          salt2, checksum1, checksum2, endianness)



    def _determine_last_valid_checksum(s):
        ''' returns the last frame number with a correct checksum

        The checksum stored in the previous frame is used as input for the checksum
        computation of the next frame. So this function checks which part of the
        wal file frames have a valid checksum. This is used in determination of the
        so called mxFrame.
        '''

        c1 = s.checksum1
        c2 = s.checksum2

        s.last_valid_checksum_frame = None

        for i in range(1, s.frame_count + 1):
            frame = s.get_frame(i)
            new_c1, new_c2 = frame.compute_checksum(s.checksum_endianness, c1, c2)
            if new_c1 != frame.checksum1 or new_c2 != frame.checksum2:
                return
            else:
                s.last_valid_checksum_frame = i
            c1 = new_c1
            c2 = new_c2


    def _check_frame_salt_values(s):
        ''' determine which frames have the current salt values, and which frames are leftover

        Invalidated frames are frames that have been invalidated by a checkpoint operation
        by updating the salt1 and salt2 values in the WAL header. All pages for which the
        salt values match the header salt values are valid and if their checksum is also correct,
        they are part of the database state and the last version of each page should be written
        back into the database in the next checkpoint operation '''

        # from this page: https://sqlite.org/fileformat2.html#walformat we learn

        # "After a complete checkpoint, if no other connections are in transactions that use the WAL,
        # then subsequent write transactions can overwrite the WAL file from the beginning. This is
        # called "resetting the WAL". At the start of the first new write transaction, the WAL
        # header salt-1 value is incremented and the salt-2 value is randomized. These changes to
        # the salts invalidate old frames in the WAL that have already been checkpointed but not yet
        # overwritten, and prevent them from being checkpointed again."

        # This suggests that valid frames only exist at the start of the WAL file and that we can
        # still have some ranges of older frames at the end of the file that correspond to earlier
        # database state. On one of our test databases this gives the following image:
        #
        # >>> g = db.walfile.allframes()
        # >>> [(f.salt1, f.salt2) for f in g]
        # ...
        # [(3313696399, 2889901289),
        #  (3313696399, 2889901289),
        #  ...
        #  (3313696399, 2889901289),    <-- end of current state
        #  (3313696398, 1826548311),
        #  ...
        #  (3313696398, 1826548311),    <-- end of previous state
        #  (3313696397, 334084473),
        #  (3313696397, 334084473),     <-- end of earlier state
        #  (3313696390, 511391743),
        #  (3313696375, 671756787),
        #  (3313696214, 1129315483),
        #  (3313696214, 1129315483)]    <-- end of earliest state
        #
        # Here we see that at some point there were more frames in the WAL file than
        # is currently the case, and we can see ranges of frames from those earlier periods
        # towards the end of the file.

        current_frames = []
        outdated_frames = []
        for frame in s.allframes():
            if frame.header.salt1 == s.header.salt1 and frame.header.salt2 == s.header.salt2:
                current_frames.append(frame.framenumber)
            elif frame.header.salt1 != s.header.salt1 and frame.header.salt2 != s.header.salt2:
                outdated_frames.append(frame.framenumber)
            else:
                raise ValueError("one of the two salt values matches, the other does not!")

        if len(current_frames) > 0:
            s.first_current_frame = min(current_frames)
            s.last_current_frame = max(current_frames)
            # it is our assumption that we only have current frames at the start
            # of the file and outdated frames at the end. Verify this here
            if current_frames != list(range(1, max(current_frames)+1)):
                raise _exceptions.AssumptionBrokenException("strangeness in current frame list")
        else:
            s.first_current_frame = None
            s.last_current_frame = None

        if len(outdated_frames) > 0:
            s.first_outdated_frame = min(outdated_frames)
            s.last_outdated_frame = max(outdated_frames)
            if s.last_current_frame is not None:
                if s.first_outdated_frame != s.last_current_frame + 1:
                    raise _exceptions.AssumptionBrokenException("unexpected first invalid frame")
            if s.last_outdated_frame != s.frame_count:
                raise _exceptions.AssumptionBrokenException("unexpected last invalid frame")
            if outdated_frames != list(range(min(outdated_frames), max(outdated_frames)+1)):
                raise _exceptions.AssumptionBrokenException("gaps in invalid frame list")


    def _determine_mxFrame(s):
        ''' determine the last valid frame that is also a commit frame '''

        # At the start of the source wal.c within the amalgamation file, we see:

        #    To read a page from the database (call it page number P), a reader first
        #    checks the WAL to see if it contains page P. If so, then the last valid
        #    instance of page P that is followed by a commit frame or is a commit frame
        #    itself becomes the value read. If the WAL contains no copies of page P
        #    that are valid and which are a commit frame or are followed by a commit
        #    frame, then page P is read from the database file.

        # This indicates that the last page frame for a given pagenumber represents
        # the most recent version of the page, as long as it is a commit frame, or if
        # it is followed by a commit frame.

        # Concerning the shm file, we can also read:

        #     Recovery works by doing a single pass over the WAL, from beginning to
        #     end.  The checksums are verified on each frame of the WAL as it is read.
        #     The scan stops at the end of the file or at the first invalid checksum.
        #     The mxFrame field is set to the index of the last valid commit frame in
        #     WAL. Since WAL frame numbers are indexed starting with 1, mxFrame is also
        #     the number of valid frames in the WAL. A "commit frame" is a frame that
        #     has a non-zero value in bytes 4 through 7 of the frame header. Since the
        #     recovery procedure has no way of knowing how many frames of the WAL might
        #     have previously been copied back into the database, it initializes the
        #     nBackfill value to zero.

        # So, we need to determine the last valid commit frame, which is stored in the
        # shm file as mxFrame, but can also be determined by finding the last frame with
        # the current salt values and a valid checksum that is also a commit frame.

        # first determine which is larger: the last valid checksum frame or the last
        # current frame. This serves as the absolute upper level for the mxFrame
        last_valid_frame = s.last_valid_checksum_frame
        if s.last_current_frame < last_valid_frame:
            last_valid_frame = s.last_current_frame

        s.mxFrame = None
        # iterate over the frames with correct salt and checksum
        for fnum in range(1, last_valid_frame + 1):
            frame = s.get_frame(fnum)
            # check if this is also a commit frame
            if frame.header.commit_page_count != 0:
                # this is a commit frame, update mxFrame value
                s.mxFrame = fnum


    def _determine_checkpoint_frames(s):
        ''' determines the latest frame for each pagenumber, similar to a checkpoint operation

        This function creates a dictionary mapping the pagenumber to the frameindex
        for the last (most recent) version of each page frame, and a dictionary mapping
        each pagenumber to a sequence of outdated, but valid page frames.
        '''

        # From the amalgamation a note on the waliterator struct:
        #
        #     this structure is used to implement an iterator that loops through
        #     all frames in the wal in database page order. where two or more frames
        #     correspond to the same database page, the iterator visits only the
        #     frame most recently written to the wal (in other words, the frame with
        #     the largest index)
        #
        # Further down, in the walCheckpoint function we see the following:
        #
        #     /* Iterate through the contents of the WAL, copying data to the db file */
        #     while( rc==SQLITE_OK && 0==walIteratorNext(pIter, &iDbpage, &iFrame) ){
        #       i64 iOffset;
        #       assert( walFramePgno(pWal, iFrame)==iDbpage );
        #       if( iFrame<=nBackfill || iFrame>mxSafeFrame || iDbpage>mxPage ){
        #         continue;
        #       }
        #       iOffset = walFrameOffset(iFrame, szPage) + WAL_FRAME_HDRSIZE;
        #       /* testcase( IS_BIG_INT(iOffset) ); // requires a 4GiB WAL file */
        #       rc = sqlite3OsRead(pWal->pWalFd, zBuf, szPage, iOffset);
        #       if( rc!=SQLITE_OK ) break;
        #       iOffset = (iDbpage-1)*(i64)szPage;
        #       testcase( IS_BIG_INT(iOffset) );
        #       rc = sqlite3OsWrite(pWal->pDbFd, zBuf, szPage, iOffset);
        #       if( rc!=SQLITE_OK ) break;
        #     }
        #
        # Here we see a call to the walItereratorNext function, which is documented
        # as follows:
        #
        #     Find the smallest page number out of all pages held in the WAL that
        #     has not been returned by any prior invocation of this method on the
        #     same WalIterator object.   Write into *piFrame the frame index where
        #     that page was last written into the WAL.  Write into *piPage the page
        #     number.
        #
        # From this we can infer that for each valid frame, only the latest version
        # for a particular page number is actually to be copied back into the main database
        # file. From this, in turn, we can classify all but the last wal frame for a
        # particular page as outdated/unallocated.
        #
        # Another snippet from this page: https://sqlite.org/wal.html
        #
        # The checkpointer makes an effort to do as many sequential page writes
        # to the database as it can (the pages are transferred from WAL to database in
        # ascending order) '''

        s._checkpoint_frames = {}
        s._superseded_frames = {}

        for i in range(1, s.mxFrame + 1):
            frame = s.get_frame(i)
            pgnum = frame.header.pagenumber
            if pgnum in s._checkpoint_frames:
                # the old version is superseded
                old_framenumber = s._checkpoint_frames[pgnum]
                if pgnum in s._superseded_frames:
                    s._superseded_frames[pgnum].append(old_framenumber)
                else:
                    s._superseded_frames[pgnum] = [old_framenumber]
            # add the current page to the checkpoint frames
            s._checkpoint_frames[pgnum] = i


    def _frame_offset(s, framenumber):
        ''' return offset for given framenumber. Frames are numbered starting at 1 '''

        if framenumber > (s.frame_count):
            raise _exceptions.InvalidArgumentException("framenumber exceeds frame count")

        if framenumber < 1:
            raise _exceptions.InvalidArgumentException("framenumber starts at 1")

        return 32 + s.frame_size * (framenumber - 1)


    def get_frame(s, framenumber):
        ''' return frame with given frame number '''

        offset = s._frame_offset(framenumber)

        return WalFrame(s.data, framenumber, offset, s.pagesize)


    def allframes(s, only_valid=False):
        ''' generate all frames within the WAL file '''

        for i in range(1, s.frame_count + 1):
            yield s.get_frame(i)


    def allocated_frames(s):
        ''' yields the allocated frames that have not been superseded

        These frames all exist below mxFrame and are the most recent version for their pagenumber
        '''

        for pnum, framenum in s._checkpoint_frames.items():
            yield s.get_frame(framenum)


    def superseded_frames(s):
        ''' yields the superseded frames from below mxFrame '''

        for pnum, framenums in s._superseded_frames.items():
            for framenum in framenums:
                yield s.get_frame(framenum)


    def get_page_frame(s, pagenum):
        ''' return the frame for the given pagenumber, or None if it doesn't exist '''

        if pagenum in s._checkpoint_frames:
            return s.get_frame(s._checkpoint_frames[pagenum])
        else:
            return None


    def outdated_frames(s):
        ''' generate all frames above mxFrame

        These are the frames that are not part of the current database stated
        for various reasons (i.e. different salt1/salt2, incorrect CRC, not
        followed by commit record) '''

        for i in range(s.mxFrame + 1, s.frame_count + 1):
            yield s.get_frame(i)


    def superseded_pages(s):
        ''' generate a sequence of pages from WAL file that have been superseded by a newer page

        All generated pages originate from the frames in the WAL file prior to the mxFrame '''

        # pages from the WAL file that have been superseded by a page from a later WAL frame
        for frame in s.superseded_frames():
            # determine the offset of the page in the WAL file
            pageoffset = frame.contents_offset
            # unpack as a generic page
            page = _structures.genericpage(frame.contents, 0, s.pagesize)
            from_wal = True
            yield Page(frame.contents, page, frame.pagenumber, pageoffset, from_wal)


    def outdated_pages(s):
        ''' generate a sequence of pages from WAL file that are beyond mxFrame

        These pages have been checkpointed during an earlier checkpoint operation and
        are no longer part of the database state '''

        # pages from the WAL file that have been superseded by a page from a later WAL frame
        for frame in s.outdated_frames():
            # determine the offset of the page in the WAL file
            pageoffset = frame.contents_offset
            # unpack as a generic page
            page = _structures.genericpage(frame.contents, 0, s.pagesize)
            from_wal = True
            yield Page(frame.contents, page, frame.pagenumber, pageoffset, from_wal)


class WalFrame():
    ''' class representing a single frame in a WAL file '''

    def __init__(s, mmapped_walfile, framenumber, offset, pagesize):
        ''' initialize a frame from given offset in bitstream using given pagesize '''

        s.framenumber = framenumber
        # the offset of the frame within the WAL
        s.offset = offset
        # the offset of the contents (i.e. the page data) within the WAL
        s.contents_offset = offset+24
        # separate the header and contents as so we can parse them individually
        s.header_data = mmapped_walfile[offset:s.contents_offset]
        # store the contents as bytes array
        s.contents = mmapped_walfile[s.contents_offset:s.contents_offset+pagesize]

        # parse the frame header
        s.header = s.walframeheader(s.header_data, 0)
        # and promote properties to be walframe properties
        # TODO: remove these, instead use reference to walframe header everywhere
        s.pagenumber = s.header.pagenumber
        s.commit_page_count = s.header.commit_page_count
        s.salt1 = s.header.salt1
        s.salt2 = s.header.salt2
        s.checksum1 = s.header.checksum1
        s.checksum2 = s.header.checksum2



    def walframeheader(s, data, offset=0):
        ''' Parses given data as WAL frame header

        A walheader contains the following fields:

            - pagenumber: Page number
            - commit_page_count: For commit records, the size of the database file in pages after the
                                 commit. For all other records, zero.
            - salt1: Salt-1 copied from the WAL header
            - salt2: Salt-2 copied from the WAL header
            - checksum1: Cumulative checksum up through and including this page
            - checksum2: Second half of the cumulative checksum
        '''


        _wal_frame_header = _nt('wal_frame_header', 'pagenumber commit_page_count salt1 salt2 '
                                                'checksum1 checksum2')
        fmt = '>IIIIII'
        parsed = _unpack_from(fmt, data, offset)

        pagenumber = parsed[0]
        commit_page_count = parsed[1]
        salt1 = parsed[2]
        salt2 = parsed[3]
        checksum1 = parsed[4]
        checksum2 = parsed[5]

        return _wal_frame_header(pagenumber, commit_page_count, salt1, salt2, checksum1, checksum2)



    def compute_checksum(s, endianness, init_checksum1=0, init_checksum2=0):
        ''' computes the checksum for this frame, using the provided initial values '''

        # from the amalgamation sqlite source we get (line numbers added):

        # 51194 **    (2) The checksum values in the final 8 bytes of the frame-header¬
        # 51195 **        exactly match the checksum computed consecutively on the¬
        # 51196 **        WAL header and the first 8 bytes and the content of all frames¬
        # 51197 **        up to and including the current frame.¬

        # so first, combine the data from the first 8 bytes of the header
        # and the full contents
        crc_data = s.header_data[0:8] + s.contents

        # total number of DWORDs to read
        dword_count = len(crc_data) // 4

        # read frame contents according to checksum endianess
        if endianness == 'little':
            fmt = '<' + 'I' * dword_count
            integers = _unpack(fmt, crc_data)
        elif endianness == 'big':
            fmt = '>' + 'I' * dword_count
            integers = _unpack(fmt, crc_data)

        c1,c2 = walchecksum(integers, init_checksum1, init_checksum2)
        return (c1, c2)
