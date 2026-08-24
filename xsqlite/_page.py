''' _page.py - functionality related to sqlite3 pages

Copyright (c) 2014-2026 Netherlands Forensic Institute - MIT License
Copyright (c) 2025-2026 mxkrt@lsjam.nl - MIT License
'''

from enum import Enum as _Enum


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
