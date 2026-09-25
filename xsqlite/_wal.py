''' _wal.py - Functionality to deal with WAL files.

Copyright (c) 2014-2026 Netherlands Forensic Institute - MIT License
Copyright (c) 2025-2026 mxkrt@lsjam.nl - MIT License
'''

from struct import unpack as _unpack
from collections import namedtuple as _nt
from collections import defaultdict as _defaultdict
from struct import unpack_from as _unpack_from
import os.path as _path
import mmap as _mmap
from os import stat as _stat

from . import _exceptions
from ._page import Page, PageSource, BtreePage


# In order to understand the code below, some background information and
# terminology is introduced here. This is all derived from the SQLite
# documentation and source code.

# A WAL file consists of a header followed by zero or more "frames". Each
# frame records the revised content of a single page from the database file.
# All changes to the database are recorded by writing frames into the WAL.
# Transactions commit when a frame is written that contains a commit marker
# (i.e. a non-zero dbsize field). A single WAL can and usually records multiple
# transactions.

# To read a page from the database (call it page number P), a reader first
# checks the WAL to see if it contains page P. If so, then the last valid
# instance of page P that is followed by a commit frame or is a commit frame
# itself becomes the value read. If the WAL contains no copies of page P that
# are valid and which are a commit frame or are followed by a commit frame,
# then page P is read from the database file.

# A frame is considered valid if 2 conditions are met:
# 1) the salt-1 and salt-2 values in the frame header match the salt values in
#    the WAL-header.
# 2) the checksum values in the frame-header exactly match the checksum
#    computed over the WAL header and the contents of the pages (without the
#    checksum bytes) of each frame up to and including the current frame.

# SQLite uses the concept of mxFrame to indicate the frame number of the last
# valid commit frame. Valid frames after the mxFrame are part of an uncommitted
# transaction. If the .shm file (which holds the mxFrame field) is not present,
# the mxFrame is determined by doing a single pass over the WAL, from beginning
# to end. The checksums are verified on each frame of the WAL as it is read.
# The scan stops at the end of the file or at the first invalid checksum. The
# mxFrame field is set to the index of the last valid commit frame in WAL.

# Periodically, the content of the WAL is transferred back into the database
# file in an operation called a "checkpoint". This operation *does not* clear
# up any frames, subsequent updates will continue to be written at the current
# write marker after the frames that have already been backfilled. A field in
# the .shm file (nBackfill) records how many frame have already been backfilled
# into the main database file. When nBackfill equals mxFrame, that means that
# the WAL content has been completely written back into the database and it is
# ok to reset the WAL if there are no locks held.

# A single WAL file can be reused multiple times after a reset. In other words,
# the WAL can fill up with frames that are backfilled into the main database
# and then new frames can (partially) overwrite the old ones. A WAL always
# grows from beginning toward the end.

# From this page: https://sqlite.org/fileformat2.html#walformat we learn that
# "after a complete checkpoint, if no other connections are in transactions
# that use the WAL, then subsequent write transactions can overwrite the WAL
# file from the beginning. This is called 'resetting the WAL'. At the start of
# the first new write transaction, the WAL header salt-1 value is incremented
# and the salt-2 value is randomized. These changes to the salts invalidate
# old frames in the WAL that have already been checkpointed but not yet
# overwritten, and prevent them from being checkpointed again."

# In xsqlite We define a WAL-generation as a group of frames that share the
# same (salt1, salt2) values. The generation with the same (salt1, salt2)
# values as stored in the WAL-header are part of the current consistent
# database state (if their checksum is also correct). The last version of each
# page in this set of frames (up to and including mxFrame) in combination with
# the other pages in the main database file form the most up to date consistent
# database view.

# To illustrate the different types of frames, consider the next diagram.

#   +----------------------------+
#   | header, salt1=A, salt2=B   |
#   +----------------------------+
#   | frame 1, salt1=A, salt2=B  | <- generation 0 start
#   | page 1, dbsize=0           |
#   +----------------------------+
#   | frame 2, salt1=A, salt2=B  |
#   | page 2, dbsize=0           |
#   +----------------------------+
#   | frame 3, salt1=A, salt2=B  |
#   | page 3, dbsize=0           |
#   +----------------------------+
#   | frame 4, salt1=A, salt2=B  | <- commit frame
#   | page 2, dbsize=X           |    end snapshot 0
#   +----------------------------+
#   | frame 5, salt1=A, salt2=B  |
#   | page 3, dbsize=0           |
#   +----------------------------+
#   | frame 6, salt1=A, salt2=B  | <- commit frame (mxFrame)
#   | page 4, dbsize=Y           |    end snapshot 1
#   +----------------------------+
#   | frame 7, salt1=A, salt2=B  | <- uncommitted frame
#   | page 5, dbsize=0           |
#   +----------------------------+
#   | frame 8, salt1=A, salt2=B  | <- uncommitted frame
#   | page 1, dbsize=0           |
#   +----------------------------+
#   | frame 9, salt1=C, salt2=D  | <- remaining frames from
#   | page 2, dbsize=Z           |    earlier generation
#   +----------------------------+
#   | frame10, salt1=C, salt2=D  |
#   | page 3, dbsize=0           |
#   +----------------------------+

# We can make the following observations:

# 1) Frames 1 through 8 are all part of generation 0 of the WAL-file
# 2) The last valid commit frame in generation 0 is frame 6, since frame 7 and
#    8 do not have a non-zero dbsize. We call this mxFrame
# 3) Frames 7 and 8 contain changes to the database that have not yet been
#    committed.
# 4) Frames 9 and 10 are left over from a previous generation (salt1 will be
#    lower than the salt1 of generation 0 frames)

# From this we learn that we can use frames 1 through 6 to obtain the last
# current consistent database view. Note that some of the frames may already
# have been backfilled into the database by a checkpoint operation. This will
# always be at a commit frame boundary. In above example, it may be the case
# that frames 1 through 4 are already present in the database. However, these
# will be the same as in the WAL, so there is no harm in using the WAL versions
# in this case.


class WalFile():
    ''' class representing the WAL file associated with a database '''


    def __init__(s, file):
        ''' initialize a WAL file object from the given file

        Arguments:
        - file           : filename, a file-like object or an mmapped file
        '''

        # load the WAL file, setting filename and data property
        s._load_wal(file)

        # parse the walheader
        s.header = s._parse_header(s.data[0:32], 0)

        # wal file size
        s.filesize = s.data.size()

        # amount of bytes available for frames is filesize minus header
        frame_bytecount = s.filesize - 32
        # each frame is pagesize + frameheader size
        s.frame_size = s.header.pagesize + 24
        # total number of frames is thus:
        s.frame_count = frame_bytecount // s.frame_size

        # When a WAL file is truncated to a multiple of filesystem blocks after
        # a checkpoint, we may end up with a final frame that is incomplete. We
        # have seen at least one occurence of this. In this case consider this
        # extra data WAL-slack.
        if frame_bytecount % s.frame_size != 0:
            s.slack_size = s.filesize - 32 - (s.frame_count * s.frame_size)
            if s.slack_size > s.frame_size:
                raise ValueError("a mistake was made in slack calculation")
            s.slack_offset = 32 + (s.frame_count * s.frame_size)
            s.slack = s.data[s.slack_offset:s.slack_offset+s.slack_size]

        # Group wal frames by WAL-generation and set the prior_to_reset
        # variable to True if the salt values match those in the WAL header
        # (which indicates that frames up to mxFrame should be read from the
        # WAL instead of the main databae file)
        s._determine_wal_generations()

        # Determine the highest frame with a valid checksum (condition 2)
        s._determine_highest_valid_checksum_frame()

        # determine the last valid frame that is also a commit frame
        s._determine_mxFrame()

        # determine the valid commit frames within the current generation
        s._determine_snapshot_frames()
        s.snapshot_count = len(s.snapshot_frames)

        # store the max observed page to have an upper bound in database size
        maxpgnum = max([f.pagenumber for f in s.all_frames()])
        s.highest_observed_pagenumber = maxpgnum


    def _load_wal(s, file):
        ''' open and mmap the given WAL file '''

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


    def _parse_header(s, data, offset=0):
        ''' Parse the WAL header at given offset in given data '''

        # namedtuple representing the WAL file header
        _header_t = _nt('header', 'magic file_format_version pagesize '
                                  'checkpoint_sequence_number '
                                  'salt1 salt2 checksum1 checksum2 '
                                  'checksum_endianness')

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
        # Random integer incremented with each WAL reset
        # can be seen as a WAL-generation identifier
        salt1 = parsed[4]
        # Different random number for each WAL reset
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

        return _header_t(magic, file_format_version, pagesize,
                         checkpoint_sequence_number, salt1,
                         salt2, checksum1, checksum2, endianness)


    def _frame_offset(s, framenumber):
        ''' return offset for given framenumber. Frames are numbered starting at 1 '''

        if framenumber > (s.frame_count):
            raise ValueError("framenumber exceeds frame count")
        if framenumber < 1:
            raise ValueError("framenumber starts at 1")
        return 32 + s.frame_size * (framenumber - 1)


    def get_frame(s, framenumber):
        ''' return frame with given frame number '''

        offset = s._frame_offset(framenumber)
        return WalFrame(s.data, framenumber, offset, s.header.pagesize)


    def framenumber_by_offset(s, offset):
        ''' return the frame holding the given offset in the WAL '''

        if offset < 32:
            raise ValueError("first 32 bytes of WAL is not part of a frame")
        if offset > s.filesize:
            raise ValueError("offset is outside WAL file")

        # determine in which absolute frame the offset is
        framenumber = (offset - 32) // s.frame_size
        # frame numbers start at 1
        return framenumber + 1


    def _determine_wal_generations(s):
        ''' Group WAL frames by (salt1,salt2) value (a WAL generation) '''

        # determine which frames belong to which generation (min,max)
        s.generation_frames = []
        s.generation_salts = []
        for frame in s.all_frames():
            s1 = frame.header.salt1
            s2 = frame.header.salt2
            fn = frame.framenumber
            if (s1, s2) not in s.generation_salts:
                # store the salts and start a new sequence
                s.generation_salts.append((s1, s2))
                s.generation_frames.append([fn,fn])
            else:
                s.generation_frames[-1][-1] = fn

        # convert to tuple to make immutable
        s.generation_frames = tuple(tuple(v) for v in s.generation_frames)
        s.generation_salts = tuple(v for v in s.generation_salts)

        # check if we are still prior to a WAL reset by comparing salt values
        # for generation 0 (the latest) with the header salt values
        if s.generation_salts[0] == (s.header.salt1, s.header.salt2):
            s.prior_to_reset = True
        else:
            s.prior_to_reset = False

        # since we know that writes start at the beginning of the WAL after a
        # reset and older generation frames (with lower salt1) can be left over
        # at the end of the file, we expect the generations to be ordered from
        # highest salt1 to lowest salt1, check this assumption here
        first_s1, first_s2 = s.generation_salts[0]
        for (s1, s2) in s.generation_salts:
            if s1 > first_s1:
                raise ValueError("assumption broken in salt-1 increments")


    def _determine_highest_valid_checksum_frame(s):
        ''' Determine the highest frame number with a correct checksum
        '''

        c1 = s.header.checksum1
        c2 = s.header.checksum2
        s.highest_valid_checksum_frame = None

        for i in range(1, s.frame_count + 1):
            frame = s.get_frame(i)
            new_c1, new_c2 = frame.compute_checksum(s.header.checksum_endianness, c1, c2)
            if new_c1 != frame.header.checksum1 or new_c2 != frame.header.checksum2:
                return
            else:
                s.highest_valid_checksum_frame = i
            c1 = new_c1
            c2 = new_c2


    def _determine_mxFrame(s):
        ''' determine the last valid frame that is also a commit frame 

        This function also determines if there are any corrupt frames in the
        current WAL-generation and if there are any uncommitted valid frames in
        this generation.
        '''

        # default value if no valid commit frames exist
        s.mxFrame = 0

        # In order to be a valid frame, the salt1,salt2 should match the
        # header. If no such frames exists, the prior_to_reset variable is set
        # to false by the _determine_wal_generations function.
        if s.prior_to_reset is False:
            return

        # determine upper_limit for mxFrame detection
        s._corrupt_current_frames = None
        if s.generation_frames[0][-1] < s.highest_valid_checksum_frame:
            # This indicates that frames from an older generation exist 
            # with a valid checksum. This is unlikely to happen.
            upper_limit = s.generation_frames[0][-1]
            # Raise an exception so we can investigate when this occurs
            # and how to deal with this properly
            msg = "Outdated frames with valid checksums detected!"
            raise ValueError(msg)
        elif s.generation_frames[0][-1] > s.highest_valid_checksum_frame:
            # This indicates some form of corruption in the current frames,
            # so mxFrame is limited by the highest frame with a valid checksum
            upper_limit = s.highest_valid_checksum_frame
            start = s.highest_valid_checksum_frame + 1
            end = s.generation_frames[0][-1]
            s._corrupt_current_frames = (start, end)
        else:
            upper_limit = s.highest_valid_checksum_frame

        # iterate over the frames with correct salt and checksum
        for fnum in range(1, upper_limit + 1):
            frame = s.get_frame(fnum)
            # check if this is also a commit frame
            if frame.is_commit_frame is True:
                # this is a commit frame, update mxFrame value
                s.mxFrame = fnum

        s._uncommitted_valid_frames = None
        if s.mxFrame != s.generation_frames[0][-1]:
            # This indicates that a transaction was in progress at the
            # moment the sqlite proces died. There are uncommitted changes in
            # the WAL that are not ended with a commit frame.
            start = s.mxFrame + 1
            if s._corrupt_current_frames is None:
                end = s.generation_frames[0][-1]
            else:
                end = s._corrupt_current_frames[0] - 1
            s._uncommitted_valid_frames = (start, end)


    def _determine_snapshot_frames(s):
        ''' determine the valid commit frames up to mxFrame

        A snapshot is a consistent database view reconstructed based on valid
        frames up to a commit frame. Only the commit frames up to the mxFrame
        can lead to a consistent database view. Uncommitted frames in above
        mxFrame in the current generation or frames left over from a previous
        WAL generation can not be used to reconstruct a consistent database
        snapshot.
        '''

        s.snapshot_frames = []

        # iterate over the frames up to and including mxFrame
        for i in range(1, s.mxFrame + 1):
            frame = s.get_frame(i)
            if frame.is_commit_frame is True:
                s.snapshot_frames.append(frame.framenumber)

        # convert to tuple
        s.snapshot_frames = tuple(s.snapshot_frames)

        # the last frame in this list should be mxFrame
        if s.snapshot_frames[-1] != s.mxFrame:
            raise ValueError("programming mistake in commit frame detection")


    def visible_frames(s, snapshot=-1):
        ''' Yield the visible frames in the given snapshot

        Arguments:
        - snapshot : index of the snapshot in s.snapshot_frames
                     (default -1, which is latest snapshot, up to mxFrame)

        Yields:
        - frame    : visible frame in the current snapshot
        '''

        if snapshot == -1:
            snapshot = s.snapshot_count - 1

        if not hasattr(s, '_visible_frame_cache'):
            s._visible_frame_cache = {}

        if snapshot in s._visible_frame_cache:
            visible_frames = s._visible_frame_cache[snapshot]
            for pgnum, fnum in visible_frames.items():
                yield s.get_frame(fnum)
            return

        # the commit frame to use for this snapshot
        commit_frame = s.snapshot_frames[snapshot]

        # iterate over all frames up to commit_frame to determine
        # which frame holds the most recent version of a page
        visible = {}

        for i in range(1, commit_frame + 1):
            frame = s.get_frame(i)
            pgnum = frame.header.pagenumber
            visible[pgnum] = i

        s._visible_frame_cache[snapshot] = visible

        for fnum in visible.values():
            yield s.get_frame(fnum)


    def superseded_frames(s, snapshot=-1):
        '''Yield the superseded frames in given snapshot

        Arguments:
        - snapshot : index of the snapshot in s.snapshot_frames
                     (default -1, which is latest snapshot, up to mxFrame)

        Yields:
        - frame    : superseded frame in the current snapshot
        '''

        if snapshot == -1:
            snapshot = s.snapshot_count - 1

        if not hasattr(s, '_superseded_frame_cache'):
            s._superseded_frame_cache = {}

        if snapshot in s._superseded_frame_cache:
            superseded_frames = s._superseded_frame_cache[snapshot]
            for pgnum, fnum in superseded_frames.items():
                yield s.get_frame(fnum)
            return

        # the commit frame to use for this snapshot
        commit_frame = s.snapshot_frames[snapshot]

        # determine set of visible frames
        visible = set(f.framenumber for f in s.visible_frames(snapshot))

        # all other frames are superseded
        superseded = {}
        for i in range(1, commit_frame + 1):
            if i in visible:
                continue
            frame = s.get_frame(i)
            pgnum = frame.header.pagenumber
            superseded[pgnum] = i

        s._superseded_frame_cache[snapshot] = superseded

        for fnum in superseded.values():
            yield s.get_frame(fnum)


    def get_visible_page_frame(s, pagenum, snapshot=-1):
        ''' Return the visible frame for the given pagenumber

        Arguments:
        - pagenum : pagenumber
        - snapshot : index of the snapshot in s.snapshot_frames
                     (default -1, which is latest snapshot, up to mxFrame)

        Returns:
        - frame   : visible frame for given page, or None
        '''

        if not s.is_page_visible(pagenum, snapshot):
            return None

        if snapshot == -1:
            snapshot = s.snapshot_count - 1

        if hasattr(s, '_visible_frame_cache'):
            if snapshot in s._visible_frame_cache:
                visible = s._visible_frame_cache[snapshot]
                if pagenum in visible:
                    fnum = visible[pagenum]
                    return s.get_frame(fnum)
                return None

        for frame in s.visible_frames(snapshot):
            if frame.pagenumber == pagenum:
                return frame
        return None


    def is_page_visible(s, pagenum, snapshot=-1):
        ''' return True if given pagenumber has a visible frame

        Arguments:
        - pagenum : pagenumber
        - snapshot : index of the snapshot in s.snapshot_frames
                     (default -1, which is latest snapshot, up to mxFrame)

        Returns:
        - frame   : visible frame for given page, or None
        '''

        if snapshot == -1:
            snapshot = s.snapshot_count - 1

        if hasattr(s, '_visible_frame_cache'):
            if snapshot in s._visible_frame_cache:
                visible = s._visible_frame_cache[snapshot]
                if pagenum in visible:
                    return True
                return False

        for frame in s.visible_frames(snapshot):
            if frame.pagenumber == pagenum:
                return True
        return False


    def all_frames(s):
        ''' generate all frames within the WAL file '''

        for i in range(1, s.frame_count + 1):
            yield s.get_frame(i)


    def uncommitted_valid_frames(s):
        ''' yield valid frames > mxFrame in current generation '''

        if s._uncommitted_valid_frames is None:
            return
        start, end = s._uncommitted_valid_frames
        for i in range(start, end+1):
            yield s.get_frame(i)


    def corrupt_current_frames(s):
        ''' yield corrupt frames > mxFrame in current generation '''

        if s._corrupt_current_frames is None:
            return
        start, end = s._corrupt_current_frames
        for i in range(start, end+1):
            yield s.get_frame(i)


# TODO: all above this line has been refactored


    def outdated_frames(s):
        ''' generate all frames above mxFrame

        These are the frames that are not part of the current database stated
        for various reasons (i.e. different salt1/salt2, incorrect CRC, not
        followed by commit record) '''

        # TODO: if we have uncommitted frames, these are not outdated!

        for i in range(s.mxFrame + 1, s.frame_count + 1):
            yield s.get_frame(i)


    def superseded_pages(s, usablepagesize):
        ''' generate a sequence of pages from WAL file that have been superseded by a newer page

        All generated pages originate from the frames in the WAL file prior to the mxFrame '''

        # TODO: move this to database object?

        # pages from the WAL file that have been superseded by a page from a later WAL frame
        for frame in s.superseded_frames():
            try:
                yield s.parse_page(frame, usablepagesize)
            except:
                raise
                #raise ValueError("Work in progress, detect other page types")


    def outdated_pages(s, usablepagesize):
        ''' generate a sequence of pages from WAL file that are beyond mxFrame

        These pages have been checkpointed during an earlier checkpoint operation and
        are no longer part of the database state '''

        # TODO: move this to database object?

        # pages from the WAL file that have been superseded by a page from a later WAL frame
        for frame in s.outdated_frames():
            try:
                yield s.parse_page(frame, usablepagesize)
            except:
                raise


    def parse_page(s, frame, usablepagesize):
        ''' attempt to parse the frame as Btree Page '''

        offset = frame.contents_offset
        try:
            return BtreePage(s.data, offset, frame.pagenumber,
                             s.header.pagesize, PageSource.WALFile,
                             usablepagesize)
        except:
            raise
            raise ValueError("Work in progress, detect other page types")


    def parse_frame_page(s, framenumber, usablepagesize):
        ''' attempt to parse the frame with given framenumber as Btree Page '''

        frame = s.get_frame(framenumber)
        offset = frame.contents_offset
        try:
            return BtreePage(s.data, offset, frame.pagenumber,
                             s.header.pagesize, PageSource.WALFile,
                             usablepagesize)
        except:
            raise
            raise ValueError("Work in progress, detect other page types")


    def _page_history(s, pgnum, usablepagesize):
        ''' simple idea to show page history in superseded frames '''

        for fnum in s._superseded_frames[pgnum]:
            pg = s.parse_frame_page(fnum, usablepagesize)
            yield pg
        # and the final current state
        fnum = s._visible_frames[pgnum]
        pg = s.parse_frame_page(fnum, usablepagesize)
        yield pg



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
        if s.header.dbsize != 0:
            s.is_commit_frame = True
        else:
            s.is_commit_frame = False


    def walframeheader(s, data, offset=0):
        ''' Parses given data as WAL frame header

        A walheader contains the following fields:

            - pagenumber: Page number
            - dbsize: For commit records, the size of the database file in pages after the
                      commit. For all other records, zero.
            - salt1: Salt-1 copied from the WAL header
            - salt2: Salt-2 copied from the WAL header
            - checksum1: Cumulative checksum up through and including this page
            - checksum2: Second half of the cumulative checksum
        '''

        _wal_frame_header = _nt('wal_frame_header', 'pagenumber dbsize salt1 salt2 '
                                                'checksum1 checksum2')
        fmt = '>IIIIII'
        parsed = _unpack_from(fmt, data, offset)

        pagenumber = parsed[0]
        dbsize = parsed[1]
        salt1 = parsed[2]
        salt2 = parsed[3]
        checksum1 = parsed[4]
        checksum2 = parsed[5]

        return _wal_frame_header(pagenumber, dbsize, salt1, salt2, checksum1, checksum2)


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
