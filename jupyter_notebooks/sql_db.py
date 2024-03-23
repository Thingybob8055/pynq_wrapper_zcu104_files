''' Usage: 

from sql_db import SQL_Barcodes_DB
db_barcodes = SQL_Barcodes_DB()
db_barcodes.reset_table()
db_barcodes.init_with_default_barcodes()

# Normal checks:
print(db_barcodes.is_barcode_in_db('4062139015344'), 'is_barcode_in_db(4062139015344)')
print(db_barcodes.is_barcode_in_db('5010358255255'), 'is_barcode_in_db(5010358255255)')
print(db_barcodes.is_barcode_in_db('5057753897246'), 'is_barcode_in_db(5057753897246)')
print(db_barcodes.is_barcode_in_db('4062139015405'), 'is_barcode_in_db(4062139015405)')
print(db_barcodes.is_barcode_in_db('3337875597210'), 'is_barcode_in_db(3337875597210)')

# SQL injection:
print(db_barcodes.is_barcode_in_db('333787559721 OR 1=1'), 'is_barcode_in_db(3337875597210 OR 1=1')
# 333787559721 is not in the table but "OR 1=1" will always make the returned value to be true 

'''

import sqlite3
import threading
import queue
import time
import traceback

# unsigned long long known_barcode_IDs[] = {
#     4062139015344,
#     4062139015405,
#     5057753897246,
#     5010358255255
# };
# unsigned long long known_barcode_IDs_compromised[] = {
#     4062139015344,
#     4062139015405,
#     5057753897246,
#     3337875597210 // replaced 5010358255255
# };
class SQL_Barcodes_DB:
    def __init__(self, name='db_allowed_barcode_IDs.db'):
        self.command_queue = queue.Queue()
        self.result_queue = queue.Queue()
        self.worker_thread = threading.Thread(target=self.worker, daemon=True, args=(name,))
        self.worker_thread.start()

    def worker(self, f_name='db_allowed_barcode_IDs.db'):
        ''' SQLite does not allow to access the database from multiple threads. 
        For that reason this worker handles all interactions with the database 
        using threas safe Queue as proxy for methods like add_barcode, reset_table, init_with_default_barcodes'''            
        self.conn = sqlite3.connect(f_name)
        self.c = self.conn.cursor()
        while True:
            cmd = self.command_queue.get()
            if cmd[0] == 'add_barcode':
                barcode = cmd[1]
                # secure:
                # self.c.execute("INSERT INTO allowed_barcode_IDs VALUES (?)", (barcode,))
                # vulnerable to sql injection:
                self.c.execute(f"INSERT INTO allowed_barcode_IDs VALUES ({barcode})")
                self.conn.commit()
            elif cmd[0] == 'is_barcode_in_db':
                try:
                    barcode = cmd[1]
                    # secure:
                    # self.c.execute("SELECT * FROM allowed_barcode_IDs WHERE barcode_ID = ?", (barcode,))
                    # vulnerable to sql injection:
                    self.c.execute(f"SELECT * FROM allowed_barcode_IDs WHERE barcode_ID = {barcode}")
                    self.result_queue.put(self.c.fetchone() is not None)
                except sqlite3.OperationalError as e:
                    self.result_queue.put(False)
                    traceback.print_exc()
            elif cmd[0] == 'reset_table':
                if self.c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='allowed_barcode_IDs'").fetchone():
                    self.c.execute("DROP TABLE allowed_barcode_IDs")
                self.c.execute('''CREATE TABLE allowed_barcode_IDs
                            (barcode_ID text)''')
                self.conn.commit()
            elif cmd[0] == 'init_with_default_barcodes':
                allowed_barcodes = [
                    '2417174074736', # XZ
                    '4062139015344', # SS
                    '7576926145577', # XZ
                    '4062139015405', # KDM
                    '8945719175171', # HL
                    '0165231842759', # JZ
                    '5057753897246'  # MB
                ]
                for barcode in allowed_barcodes:
                    self.add_barcode(barcode)
                self.conn.commit()
            self.command_queue.task_done()

    def reset_table(self):
        self.command_queue.put(('reset_table',None))

    def init_with_default_barcodes(self):
        self.command_queue.put(('init_with_default_barcodes',None))

    def add_barcode(self, barcode):
        self.command_queue.put(('add_barcode', barcode))

    def is_barcode_in_db(self, barcode):
        self.command_queue.put(('is_barcode_in_db', barcode))
        return self.result_queue.get(block=True)

    def __del__(self):
        self.conn.close()


if __name__ == "__main__":
    db_barcodes = SQL_Barcodes_DB()
    db_barcodes.reset_table()
    db_barcodes.init_with_default_barcodes()
    print(db_barcodes.is_barcode_in_db('4062139015344'), 'is_barcode_in_db(4062139015344)')
    print(db_barcodes.is_barcode_in_db('5010358255255'), 'is_barcode_in_db(5010358255255)')
    print(db_barcodes.is_barcode_in_db('5057753897246'), 'is_barcode_in_db(5057753897246)')
    print(db_barcodes.is_barcode_in_db('4062139015405'), 'is_barcode_in_db(4062139015405)')
    print(db_barcodes.is_barcode_in_db('3337875597210'), 'is_barcode_in_db(3337875597210)')
    print(db_barcodes.is_barcode_in_db('333787559721 OR 1=1'), 'is_barcode_in_db(3337875597210 OR 1=1)')
