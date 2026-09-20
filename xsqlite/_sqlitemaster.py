''' _sqlitemaster.py - functionality related the sqlite_master table

Copyright (c) 2014-2026 Netherlands Forensic Institute - MIT License
Copyright (c) 2025-2026 mxkrt@lsjam.nl - MIT License

The implementation of the structures and the logic is based on the description
of the database format as given on: https://www.sqlite.org/fileformat.html
'''

from collections import OrderedDict as _OD

from . import _sql
from . import _decode


class SQLiteMaster():
    ''' class representing the sqlite_master table in a database '''


    def __init__(s, master_records, textencoding):
        ''' Interprets the sqlite_master table and returns sqlite_master object.

        The sqlite_master table stores the complete database schema.
        The rootpage of the sqlite_master table is page 1.
        '''

        # store tables, indices, views and triggers in ordered dictionaries
        s.tables = _OD()
        s.virtual_tables = _OD()
        s.indices = _OD()
        s.views = _OD()
        s.triggers = _OD()

        for rec in master_records:
            record = SQLiteMasterRecord(rec, textencoding)
            if record.tbl_type == 'table':
                if record.virtual is True:
                    s.virtual_tables[record.name] = record
                else:
                    tbl = Table(record, textencoding)
                    s.tables[record.name] = tbl
            elif record.tbl_type == 'index':
                s.indices[record.name] = record
            elif record.tbl_type == 'view':
                s.views[record.name] = record
            elif record.tbl_type == 'trigger':
                s.triggers[record.name] = record
            else:
                raise ValueError('unknown table type in sqlite_master table')


class SQLiteMasterRecord():
    ''' class representing a single record in the sqlite_master table '''


    def __init__(s, rowidrecord, textencoding):
        ''' initialize SQLiteMasterRecord from given rowidrecord '''

        # the type afinities of the sqlite master table
        affinities = ['TEXT', 'TEXT', 'TEXT', 'INTEGER', 'TEXT']

        s.rowid = rowidrecord.rowid

        # decode the record using the textencoding and type affinities
        decoder = _decode.BodyDecoder(textencoding, affinities)
        body, errors = decoder.decode(rowidrecord.body)

        s.tbl_type = body[0]
        # name of the view, index, trigger or table
        s.name = body[1]
        # name of the table to which view, index, trigger or tabledef applies
        s.tbl_name = body[2]
        s.rootpage = body[3]
        s.sql = body[4]

        if s.tbl_type == 'table':
            tbldef = _sql.parse_create_table_statement(s.sql)

            # this function returns None for VIRTUAL tables. VIRTUAL tables may
            # also have an a entry in sqlite master, but they do not represent
            # any in-file structures the parse_create_table_statement function
            # returns None in such cases, so move on to the next entry if this
            # is the case
            s.virtual = False

            if tbldef is None:
                s.columns = None
                s.temporary = None
                s.tblconstraints = None
                s.withoutrowid = None
                s.ipk_column = None
                if "VIRTUAL TABLE" in s.sql:
                    s.virtual = True
                return

            # compare tblname in sql with name field (ignoring quotes in the
            # parsed sql table name)
            tbldefname = tbldef.tblname.lstrip('"\'[`').rstrip('"\']`')
            if tbldefname != s.name:
                raise ValueError('master table definition inconsistency.')

            s.dbname = tbldef.dbname
            s.columns = tbldef.columns
            s.temporary = tbldef.temp
            s.tblconstraints = tbldef.tblconstraints
            s.withoutrowid = tbldef.withoutrowid
            s.ipk_column = tbldef.ipk_column


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

        s.master_record = sqlite_master_record

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
