''' make_test_db.py - script to generate a simple test database for xsqlite

Copyright (c) 2026 Netherlands Forensic Institute - MIT License
Copyright (c) 2026 mxkrt@lsjam.nl - MIT License
'''

import sqlite3
import random
import os.path
import shutil
import tempfile
import binascii


# target for the file with checkpointed and truncated WAL
TARGET1 = 'xsqlite_test_with_wal.db'
TARGET2 = 'xsqlite_test.db'
LOGFILE = 'xsqlite_test.log'


def randomstring(n):
    ''' Generates a random string of n characters. '''

    word = ''
    for i in range(n):
        word += random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!,.@:{}[]()')
    return word


def generate_testdb():
    ''' Creates a test database with some binary data, with some high-precision
    floating point values, with some random data and with some deleted records.
    '''

    log = open(LOGFILE, 'wt')

    with tempfile.TemporaryDirectory() as td:
        dbfile = os.path.join(td, TARGET1)
        con = sqlite3.connect(dbfile)
        cur = con.cursor()

        # set pagesize to 4096
        cur.execute('''PRAGMA page_size = 4096''')
        log.write('[set pagesize to 4096]\n')
        # disable secure delete
        cur.execute('''PRAGMA secure_delete = OFF''')
        log.write('[disabled secure_delete]\n')
        # enable WAL mode and try to prevent auto checkpoint
        cur.execute('''PRAGMA journal_mode = WAL''')
        log.write('[set journalmode to WAL]\n')
        cur.execute('''PRAGMA wal_autocheckpoint = 0''')
        log.write('[disable wal autocheckpoint]\n')

        # create test table
        cur.execute('''DROP TABLE IF EXISTS table_one''')
        cur.execute('''
                CREATE TABLE table_one (id INTEGER PRIMARY KEY ON CONFLICT ROLLBACK, id2 INTEGER UNIQUE NOT
                NULL, name TEXT NOT NULL, optionaltext TEXT, number INTEGER, float FLOAT, someblob BLOB)''')
        log.write('[created table_one]\n')
        cur.execute('''
                CREATE UNIQUE INDEX idx ON table_one(id2)''')
        log.write('[created index on table_one(id2)]\n')

        for i in range(10000):
            blb = random.randbytes(random.randint(0,50))
            txt = randomstring(random.randint(0,100))
            real = random.random() * random.randint(0,1000)
            nmbr = random.randint(0,2**63)
            cur.execute("INSERT INTO table_one VALUES(?,?,?,?,?,?,?)",(i, i*2, f"record_{i}", txt, nmbr, real, sqlite3.Binary(blb),))
            log.write(f'INSERT:\ttable_one\t{i}\t{i*2}\trecord_{i}\t{txt}\t{nmbr}\t{real}\t{binascii.hexlify(blb)}\n')

        con.commit()
        log.write(f'[commit]\n')

        # delete 200 consequetive records in an attempt to create freelist pages
        for id_ in range(120,220):
            cur.execute(f"DELETE FROM table_one WHERE id = {id_}")
            log.write(f'DELETE:\ttable_one\t{id_}\n')

        con.commit()
        log.write(f'[commit]\n')

        # perform a checkpoint and reset the WAL
        cur.execute("PRAGMA wal_checkpoint(RESTART)")
        log.write("[PRAGMA wal_checkpoint(RESTART)]\n")

        for i in range(10000, 15000):
            blb = random.randbytes(random.randint(0,50))
            txt = randomstring(random.randint(0,100))
            real = random.random() * random.randint(0,1000)
            nmbr = random.randint(0,2**63)
            cur.execute("INSERT INTO table_one VALUES(?,?,?,?,?,?,?)",(i, i*2, f"record_{i}", txt, nmbr, real, sqlite3.Binary(blb),))
            log.write(f'INSERT:\ttable_one\t{i}\t{i*2}\trecord_{i}\t{txt}\t{nmbr}\t{real}\t{binascii.hexlify(blb)}\n')

        con.commit()
        log.write(f'[commit]\n')

        # perform a checkpoint and reset the WAL
        cur.execute("PRAGMA wal_checkpoint(RESTART)")
        log.write("[PRAGMA wal_checkpoint(RESTART)]\n")

        # delete 200 random records
        for i in range(0, 200):
            id_ = random.randint(300,15000)
            cur.execute(f"DELETE FROM table_one WHERE id = {id_}")
            log.write(f'DELETE:\ttable_one\t{id_}\n')

        con.commit()
        log.write(f'[commit]\n')

        # delete 100 consequetive records in an attempt to create freelist pages
        for id_ in range(7720,7820):
            cur.execute(f"DELETE FROM table_one WHERE id = {id_}")
            log.write(f'DELETE:\ttable_one\t{id_}\n')

        con.commit()
        log.write(f'[commit]\n')

        # copy main db + wal to prevent cleaning up
        shutil.copy(dbfile, '.')
        shutil.copy(dbfile+"-wal", '.')
        shutil.copy(dbfile+"-shm", '.')
        log.write(f'[copied database, -wal and -shm file to prevent WAL truncate\n')

        log.write(f'[close]\n')
        con.close()
        shutil.copy(dbfile, TARGET2)
        log.write(f'[copied database after con.close()\n')


def main():
    ''' generate test database '''

    # generate database
    generate_testdb()


if __name__ == "__main__":
    main()
