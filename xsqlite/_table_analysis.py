''' _table_analysis.py - analysis of schema and allocated records

The purpose of this module is to analyse the allocated data and the schema of
the provided table in order to determine properties of the stored records.
These properties can be used to optimize the various recovery strategies.

Copyright (c) 2014-2026 Netherlands Forensic Institute - MIT License
Copyright (c) 2025-2026 mxkrt@lsjam.nl - MIT License
'''

from collections import namedtuple as _nt
from collections import OrderedDict as _OD
from collections import Counter as _Counter
from struct import pack as _pack
import statistics as _statistics
from enum import Enum as _Enum
#import bitstring as _bitstring
import re as _re
from itertools import chain as _chain

from . import _structures
from . import _exceptions
from . import _export
from . import _database



def determine_recovery_parameters(db, tablename, minimal_record_count=30, ignore_last_cols=None):
    ''' Returns properties of allocated records that can aid in filtering false positive headers

    If less than minimum_record_count allocated records exist, the function
    will raise an exception. In this case you can lower this number or,
    preferably, use a reference database to determine the recovery parameters.
    The default is rather arbitrarily set to 30 '''

    # An observation is that the first four bytes of a deleted cell record are
    # overwritten immediately by the freeblock header upon deletion. When a
    # single record is deleted it is likely to end up in unallocated space, in
    # which case the cell header remains intact, or it may end up in a
    # freeblock, in which case 4 bytes of the cell header and the first part of
    # the recordheader are overwritten.  Just how many bytes of the record
    # header are overwritten may vary based on the exact size of the cell
    # header. The cell-header is defined as follows:

    # 1. payloadsize (1-9 bytes varint)    (overwritten)
    # 2. rowid (1-9 bytes varint)          (overwritten if payloadsize uses less than 4 bytes)
    # 3. inline payload
    # 4. overflow page pointer (not present or uintbe:32)

    # The inline payload, in turn, contains the recordheader, which consists of
    # the following:

    # 1. headersize (1-9 bytes varint)     (overwritten if payloadsize + rowid use less than 4 bytes)
    # 2. serialtypes (series of varints)   (1st varint overwritten if payloadsize, rowid + headersize < 4 bytes)
    # 3. recorddata

    # From above we see that it is likely that 1 or 2 bytes of the recordheader
    # are overwritten, if the record is deleted. However, for rowid > 127 we
    # already use 2 bytes for the rowid, in which case the first varint of the
    # serialtypes is *not* overwritten.

    # Other scenario's are conceivable as well, for example when multiple
    # record are deleted, leading to a single freeblock with multiple records.
    # Now, when the freeblock is partially re-used, the freeblock will shrink
    # again. IIRC: the freeblocks are filled from the high-end to the low-end,
    # because this way only the size in the freeblock-header has to be updated,
    # the next_freeblock pointer can remain intact.  This means that in this
    # scenario (multiple deleted records in a freeblock), we also have only the
    # first 1 or 2 bytes of the recordheader overwritten (and of course part of
    # the recordheader or recorddata at the *end* of the record).

    # When the first record in a page is deleted, it ends up on in the
    # unallocated space between the last cell pointer and the (new) first
    # record. In this case, none of the fields in the recordheader are
    # overwritten. Since the cell-pointers and the records grow towards each
    # other, and since records are allocated from the high-address to the low
    # address, we can only encounter these scenario's:

    # consider this initial state:
    # +-----------------+-----------------------------------------+---------------+
    # | cellptr area    |-> unallocated         deleted record  <-| active record |
    # +-----------------+-----------------------------------------+---------------+

    # Now, if a new record is allocated that is smaller than the deleted
    # record, it will only partially overwrite the record, leaving the start of
    # the record intact. If a new record is allocated that is larger than the
    # deleted record, the entire deleted record will be overwritten and we will
    # not find a candidate there. If the deleted record was large, and it is
    # later overwritten by many smaller records we could have the situation
    # where part of the record header of the deleted record remains, whereas
    # another part is overwritten by the new cell pointers. However, since the
    # content area of the record (and probably also a significant portion of
    # the record-header) are overwritten by new records, we can probably not
    # recover the record anyway.

    # So for now, we assume that at most 2 bytes of the recordheader are
    # overwritten, the first being the headersize, and the second being the
    # first serialtype. We can also infer that if any of the varints preceding
    # the first serialtype varint is larger than 1 byte, that the entire
    # sequence of serialtypes remains intact. This happens in the following
    # scenario's:

    # 1. The cell payload > 127 or the rowid > 127
    # 2. Cell payload > 16383
    # 3. Rowid > 16383
    # 4. Any combination of the above

    # To conclude: when scanning for potential recordheaders, we should scan
    # for the total number of columns in the specific table, minus the first,
    # since this can optionally be overwritten for records with a low rowid.
    # Also when a table has been updated using the ALTER TABLE statement to add
    # columns, these are added at the end. Since we can not know for deleted
    # records if they existed prior or after the ALTER TABLE was done, we
    # should scan only for the common columns that exist in all allocated
    # records.

    _recovery_parameters = _nt('recovery_parameters', 'schema_serialtypes strict_observed_serialtypes '
                               'loose_observed_serialtypes observations_per_column '
                               'observed_max_varint_widths text_and_blob_stats added_columns '
                               'pagesize textencoding columns ipk_col common_columns '
                               'possible_headersizes max_varints_in_header '
                               'col0_prepend_list max_nr_of_cols')

    tbl = db.tables[tablename]
    schema_stypes = _schema_based_allowed_serialtypes(db, tablename)

    # obtain the typecodes from the allocated records
    typecodes = _scan_btree_typecodes(db, tbl.rootpage)
    # count occurrence of typecodes for each column
    typecode_counters = _observed_typecodes(typecodes)
    # determine strict and loose signatures
    strict_observed_stypes = _observation_based_allowed_serialtypes(typecode_counters, False)
    loose_observed_stypes = _observation_based_allowed_serialtypes(typecode_counters, True)
    # determine total number of observations per column
    observations_per_column = _observations_per_column(typecode_counters)

    if len(observations_per_column) == 0:
        msg = "given table doesn't contain allocated records, use reference database!"
        raise _exceptions.UserFeedbackException(msg)
    if max(observations_per_column) < minimal_record_count:
        msg = "only {:d} allocated records in database, lower minimal_record_count or use reference database"
        msg = msg.format(max(observations_per_column))
        raise _exceptions.UserFeedbackException(msg)

    # determine the max observed varint size for each column
    observed_max_varint_widths = _observed_max_varint_widths(typecode_counters)
    # get stats on the BLOB and TEXT values in each columns
    text_and_blob_stats = _collect_text_and_blob_size_stats(typecode_counters)
    # determine if one or more columns have been added during lifetime of database
    added_columns = _determine_added_columns(observations_per_column)

    # when scanning for varints, exclude the first column, because this is potentially
    # overwritten, and exclude the added columns, because these are not present in all records
    common_columns = (1, len(tbl.columns) - added_columns - 1)

    # The header size is at least the amount of columns and at most amount of columns
    # times the maximum size of the varint describing that column. To find this
    # number we have to know the SQLITE_MAX_LENGTH parameter. This defaults to
    # 1000000000 bytes. A BLOB of this length is represented as follows:

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

    # However, since a record is itself stored as a blob, the same restriction
    # applies to the record as a whole. This means that the entire record may
    # never exceed SQLITE_MAX_LENGTH itself. This indicates that not even a
    # single column can contain this theoretical maximum length, but throughout
    # this code we assume that any column can have a size requiring a 5 byte
    # varint size.

    # the recordheader size includes the recordheader size field itself,
    # so the minimal size is that of the common columns
    min_headersize = len(tbl.columns) - added_columns + 1

    # in principle, all columns could house a TEXT or BLOB, but for computation
    # of the max_headersize, we assume that only those with TEXT or BLOB
    # affinity can use more than 1 bytes for their serialtype varint
    single_byte_cols = len([c for c in tbl.columns if c.affinity == 'INTEGER' or c.affinity == 'REAL'])
    multi_byte_cols = len(tbl.columns) - single_byte_cols

    # for each non numeric column, add the max width of 5 for the varint, which
    # is most likely not very realistic
    max_headersize = single_byte_cols + multi_byte_cols * 5

    # it is even less realistic that we have more than 25 columns, all with a
    # TEXT or BLOB value that require a 5-byte varint to express, so limit the
    # headersize to a 1-byte varint
    if max_headersize > 127:
        max_headersize == 127

    # make sure we only have to create these size varints once
    headersizes = _OD()
    for size in range(min_headersize, max_headersize + 1):
        headersizes[size] = _structures.tovarint(size)

    # the recordheader can contain 1 varint for each column + headersize
    max_varints_in_header = len(tbl.columns) + 1

    # make a sequence of prepend bytes we can use for the first column
    # so that we only have to do this once per table
    if tbl.ipk_col == 0:
        # if col0 is the INTEGER PRIMARY KEY column, then the only allowed value is 0
        # which significantly speeds up recordheader reconstruction
        prepend_col0 = [_pack('>b', 0)]
    else:
        # otherwise, we can not be sure and we need to try them all.
        prepend_col0 = [_pack('>b', i) for i in range(0, 256) if i != 128]

    max_nr_of_cols = len(tbl.columns)

    return _recovery_parameters(schema_stypes, strict_observed_stypes, loose_observed_stypes,
                                observations_per_column,
                                observed_max_varint_widths, text_and_blob_stats, added_columns,
                                db.header.pagesize, db.header.textencoding, tbl.columns,
                                tbl.ipk_col, common_columns, headersizes,
                                max_varints_in_header, prepend_col0, max_nr_of_cols)



def _schema_based_allowed_serialtypes(db, tablename):
    ''' determine the allowed serialtypes for each column in given table based on the schema

    Here, the numbers 0 through 9 correspond to the fixed serial types as used
    in the record headers. The value -1 is used to indicate BLOB, and the value
    -2 is used to indicate TEXT, similar to signature based SQLite recovery tools.
    '''

    tbl = db.tables[tablename]

    allowed_types = []
    for idx, column in enumerate(tbl.columns):
        if idx == tbl.ipk_col:
            # the INTEGER PRIMARY KEY column has NULL value in it's record-header position
            allowed_types.append({0})
        elif column.affinity == 'TEXT':
            # columns with TEXT affinity are NULL, TEXT or BLOB
            allowed_types.append({0,-1,-2})
        else:
            # all other column affinities can be stored in any of the storage classes
            allowed_types.append({-1,-2,0,1,2,3,4,5,6,7,8,9})
        if column.notnull is True:
            # remove the null type if column has NOT NULL constraint
            allowed_types[idx].remove(0)

    return allowed_types


def _scan_btree_typecodes(db, rootpagenumber):
    ''' yield serial typecodes for allocated records in btree with the given rootpage '''

    recheaders = db.recordheaders(db.cellwalker(rootpagenumber))
    tcodes = (tuple(r.parsed_recordheader.serialtypes) for r in recheaders)
    for tc in tcodes:
        yield tc


def _observed_typecodes(tcodes):
    ''' count occurence of typecodes in each column in the sequence of typecodes

    This function is used to determine for each column how often each typecode
    occurs. This is done by merging all typecodes in a specific column into a
    Counter object, that counts the occurence of each serialtype value per
    column. This allows us to detect invariants throughout all records that can
    be used for the recovery. In addition we can build a signature from this
    that can be used for signature based recovery.

    Consider these typecodes:

        (0, 65, 9, 37, 1, 8)
        (0, 65, 8, 37, 1, 6)
        (0, 65, 8, 37, 1, 6, 6)
        (0, 64, 8, 35, 1, 8, 6, 0)

    One observation that can be made is that the total number of columns may
    vary between records. This is caused by the ALTER TABLE statement by which
    columns can be added. These added columns will have a default value, which
    is used to retreive their value for already stored records. This means that
    the old records are not updated and we can have records of varying length.

    However, since we know that new columns are only added at the end, we can
    still collect them in one list, since the common first columns always have
    the same meaning within the allocated (and removed) records. So, in the
    above example we would get the following result:

        [Counter({0:4}, Counter({65:3, 64:1}), ... , Counter({6:2}), Counter({0,1})]
    '''

    counters = []
    for tcode in tcodes:
        # make sure we have the proper amount of Counters and update as we encounter
        # wider records
        if len(counters) != len(tcode):
            added_columns = len(tcode) - len(counters)
            for i in range(added_columns):
                counters.append(_Counter())
        # and update their values
        for idx, tcode in enumerate(tcode):
            counters[idx].update([tcode])
    return counters


def _observation_based_allowed_serialtypes(typecode_counters, expand_numeric=False):
    ''' convert typecode list to set of allowed serialtypes per column '''

    numeric = {1,2,3,4,5,6,7,8,9}
    null = {0}
    blob = {-1}
    text = {-2}
    # most columns can be any of the available serialtypes
    all_types = numeric.union(null).union(blob).union(text)

    allowed_types = []
    for idx, counter in enumerate(typecode_counters):
        column_allowed = set()
        for typecode, count in counter.items():
            if typecode in numeric:
                if expand_numeric is True:
                    column_allowed.update(numeric)
                else:
                    column_allowed.add(typecode)
            elif typecode in null:
                column_allowed.update(null)
            elif typecode >= 12 and typecode % 2 == 0:
                column_allowed.update(blob)
            elif typecode >= 13 and typecode % 2 == 1:
                column_allowed.update(text)
        allowed_types.append(column_allowed)

    return allowed_types


def _observed_max_varint_widths(typecode_counters):
    ''' determined allowed width of each typecode varint based on the typecode_counters dictionary

    This can be used to determine what sequence of varints can be a potential
    record header for the associated table, based on the width of the
    individual varints in the sequence. We often see that false-positives have
    several large varint values, for example when a sequence of string
    characters are parsed as varints. Limiting the allowed width of each varint
    / typecode will remove such false positives from the sequence of potential
    record headers. This approach is a bit less strict than using full
    signatures based on the allocated data, because we only look at the size of
    each column's varint in the record-header '''

    widths = []

    for colidx, counter in enumerate(typecode_counters):
        # initially, assume that the varint for this column is < 127, consuming 1 byte
        widths.append(1)

        # now, for each occurrence, determine the actual width
        for typecode, count in counter.items():
            curwidth = None
            if typecode < 127:
                # we already assumed minimal width 1
                pass
            elif typecode < 16384:
                if widths[colidx] < 2: widths[colidx] = 2
            elif typecode < 2097152:
                if widths[colidx] < 3: widths[colidx] = 3
            elif typecode < 268435456:
                if widths[colidx] < 4: widths[colidx] = 4
            elif typecode < 34359738368:
                if widths[colidx] < 5: widths[colidx] = 5

    return widths


def _observations_per_column(typecode_counters):
    ''' for each column, store how many observations where made

    This is used to detect if columns have been added to a table using the
    ALTER TABLE statement during the existence of the database. In this case,
    the latter columns will have less observations than the earlier columns.
    This, in turn can be used to target the various number of columns in our
    recordheader detection algorithm '''

    counts = []

    for colidx, counter in enumerate(typecode_counters):
        # now, for each occurrence, determine the actual number of observations
        counts.append(sum([c for c in counter.values()]))
    return counts


def _text_and_blob_size_stats(typecode_counter):
    ''' return statistics on the TEXT and BLOB sizes in the given typecode_counter '''

    _size_stats = _nt('size_stats', 'max min mean median mode mode_frequency stdev most_common total')
    _dynamic_stats = _nt('dynamic_size_stats', 'text_stats blob_stats')

    # first determine the amount of BLOB and TEXT values in this typecode_counter
    total_texts = sum([c for tc, c in typecode_counter.items() if (tc > 13 and tc % 2 != 0)])
    total_blobs = sum([c for tc, c in typecode_counter.items() if (tc > 12 and tc % 2 == 0)])

    text_sizes = []
    blob_sizes = []
    max_text = 0
    min_text = 2**31
    max_blob = 0
    min_blob = 2**31
    text_size_counter = _Counter()
    blob_size_counter = _Counter()
    total_text = 0
    total_blob = 0

    for tc, count in typecode_counter.items():
        if tc >= 13 and tc % 2 != 0:
            size = int((tc - 13) / 2)
            size_list = [size,]*count
            text_sizes.extend(size_list)
            text_size_counter.update(size_list)
            total_text += count
            if size > max_text:
                max_text = size
            if size < min_text:
                min_text = size

        if tc >= 12 and tc % 2 == 0:
            size = int((tc - 12) / 2)
            size_list = [size,]*count
            blob_sizes.extend(size_list)
            blob_size_counter.update(size_list)
            total_blob += count
            if size > max_blob:
                max_blob = size
            if size < min_blob:
                min_blob = size

    text_stats = None
    blob_stats = None
    text_mode_fraction = None
    blob_mode_fraction = None
    if len(text_sizes) > 1 and total_texts != 0:
        try:
            text_mode = _statistics.mode(text_sizes)
            for tc, count in typecode_counter.items():
                size = int((tc - 13) / 2)
                if size == text_mode:
                    text_mode_fraction = count / total_texts
        except _statistics.StatisticsError:
            text_mode = None
            text_mode_fraction = None
        text_stats = _size_stats(max_text, min_text, _statistics.mean(text_sizes),
                                 _statistics.median(text_sizes), text_mode, text_mode_fraction,
                                 _statistics.stdev(text_sizes), text_size_counter.most_common(3),
                                 total_text)
    if len(blob_sizes) > 1:
        try:
            blob_mode = _statistics.mode(blob_sizes)
            for tc, count in typecode_counter.items():
                size = int((tc - 12) / 2)
                if size == blob_mode:
                    blob_mode_fraction = count / total_blobs
        except _statistics.StatisticsError:
            blob_mode = None
            blob_mode_fraction = None

        blob_stats = _size_stats(max_blob, min_blob, _statistics.mean(blob_sizes),
                                 _statistics.median(blob_sizes), blob_mode, blob_mode_fraction,
                                 _statistics.stdev(blob_sizes), blob_size_counter.most_common(3),
                                 total_blob)

    return _dynamic_stats(text_stats, blob_stats)


def _collect_text_and_blob_size_stats(typecode_counters):
    ''' runs text_and_blob_size_stats on each typecode_counter in the list of typecode_counters '''

    stats = []
    for counter in typecode_counters:
        results = _text_and_blob_size_stats(counter)
        if results.text_stats is None and results.blob_stats is None:
            stats.append(None)
        else:
            stats.append(results)
    return stats


def _determine_added_columns(observations_per_column):
    ''' determines if any columns have been added using the ALTER TABLE statement '''

    added_columns = 0
    if len(set(observations_per_column)) != 1:
        # not all columns occur equally often, one or more columns have been added later
        # scan over the total number of columns and count all observations count changes
        curval = observations_per_column[0]
        for s in observations_per_column:
            if s != curval:
                if s >= curval:
                    raise ValueError("we only expect later added columns to have less observations")
                added_columns += 1
    return added_columns


