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
                    s.tables[record.name] = record
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
