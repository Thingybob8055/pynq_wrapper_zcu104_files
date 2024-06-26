import time
import threading
import queue
import os
import sys
import math

class Bram_Loader:
    ''' Loads a file into the BRAM using AXI GPIO (32 output bits) and a shift register having
        256-bit data output and 32-bit address output. In order to load the file, the AXI GPIO 
        must control the shift register and write enable pin of the BRAM. 
        
        16-bit values can be supplied to the shift register at once, meaning that 16 values
        (16x16=256) must be supplied for data, and 2 values (2x16=32) must be supplied for
        address before write enable can be set HIGH. '''

    def __init__(self, axi_gpio=None):
        self.load_progress_lock = threading.Lock()
        self.load_progress_percent = 0 # 0-100
        self.load_queue = queue.Queue()
        self.load_thread = threading.Thread(target=self.load_worker, daemon=True)
        self.load_thread.start()

        self.dry_run = (axi_gpio is None)
        if self.dry_run:
            return
        # input to shift register
        self.data_input = axi_gpio.channel1[0:16]

        # shift input of shift register
        self.shift = axi_gpio.channel1[16]

        # select data (HIGH) vs address (LOW) input of shift register
        self.select_data = axi_gpio.channel1[17]

        # write enable of bram module
        self.write_enable = axi_gpio.channel1[18]


    def shift_16bit_value(self, value):
        ''' Supply 16-bit value to shift register. '''
        if self.dry_run:
            print('  ', hex(value))
            return
        self.data_input.write(value)
        self.shift.write(0)
        self.shift.write(1) # possibly a small delay may be needed but I bet not because python itself may be slow enough
        self.shift.write(0)

    def write_256bit_value(self, value, address):
        ''' Supply shift register with data and address and set BRAM write enable to HIGH. '''
        # supply data to shift register (in 16x 16-bit chunks)
        self.select_data.write(1) # select data (instead of address) in shift register
        for i in reversed(range(16)):
            self.shift_16bit_value(value >> (i * 16) & 0xFFFF)
        if self.dry_run:
            return

        # supply address to shift register (in 2x 16-bit chunks)
        self.select_data.write(0) # select address (instead of data) in shift register
        self.data_input.write(address >> 16)
        self.shift.write(0)
        self.shift.write(1) # possibly a small delay may be needed but I bet not because python itself may be slow enough
        self.shift.write(0)
        self.data_input.write(address & 0xFFFF)
        self.shift.write(0)
        self.shift.write(1) # possibly a small delay may be needed but I bet not because python itself may be slow enough
        self.shift.write(0)
        
        # at this point the shift register data (256 bits) and address (32 bits) should be ready
        # so write enable of BRAM module can be set HIGH
        self.write_enable.write(0)
        self.write_enable.write(1)
        self.write_enable.write(0)

    def start_load(self, fname, address=0):
        # check if file exists
        if not os.path.isfile(fname):
            print(f'ERROR: File {fname} does not exist.')
            return
        with self.load_progress_lock:
            self.load_progress_percent = 0
        self.load_queue.put((fname, address))

    def load_worker(self):
        while True:
            fname, address = self.load_queue.get()
            with self.load_progress_lock:
                self.load_progress_percent = 0
            file_length = os.path.getsize(fname)
            with open(fname, 'rb') as f:
                data = f.read()
                # pad data with zeros to make it a multiple of 32 bytes
                data += b'\x00' * (32 - (len(data) % 32))
                for i, _ in enumerate(data):
                    if i % 32 > 0:
                        continue
                    val = int.from_bytes(data[i:i+32], byteorder='little')
                    self.write_256bit_value(val, address)
                    address += 1
                    with self.load_progress_lock:
                        self.load_progress_percent = math.floor(i / file_length * 100)
                    if self.dry_run:
                        print(hex(val), address)
            with self.load_progress_lock:
                self.load_progress_percent = 100
            self.load_queue.task_done()
    
    def get_load_progress(self):
        ''' Returns the current load progress. '''
        with self.load_progress_lock:
            return self.load_progress_percent
    
    def finished_loading(self):
        ''' Returns True if a file is being loaded, False otherwise. '''
        with self.load_progress_lock:
            return self.load_progress_percent == 100
    
    def wait_until_finished_loading(self):
        ''' Blocks until the file is finished loading. '''
        while not self.finished_loading():
            time.sleep(0.1)
    
if __name__ == '__main__':
    bram_loader = Bram_Loader()
    bram_loader.start_load('/home/xilinx/design_files/rv64ui-p-add.bin')
    while not bram_loader.finished_loading():
        print(bram_loader.get_load_progress())
        time.sleep(1)


