''' Usage example:
from pynq import Overlay
from pynq import allocate
from continuous_monitoring_system_controller import ContinuousMonitoringSystemController
BASE_DIR = Path('/home/xilinx/design_files')
PATH = BASE_DIR 
base = Overlay(str(BASE_DIR / 'imported_design.bit'))
cms_ctrl = ContinuousMonitoringSystemController(base.axi_gpio_cms_ctrl)

# Triggerring (exact address must match to start/stop trace)
cms_ctrl.set_trigger_trace_start_address(0x80000000)
cms_ctrl.set_trigger_trace_end_address(0x800000C)
cms_ctrl.set_trigger_trace_start_address_enabled(True)
cms_ctrl.set_trigger_trace_end_address_enabled(True)

# Filtering (in example below any address between 0x80000000 and 0x8FFFFFFF will be collected)
cms_ctrl.set_monitored_address_range_lower_bound(0x80000000)
cms_ctrl.set_monitored_address_range_upper_bound(0x8FFFFFFF)
cms_ctrl.set_monitored_address_range_lower_bound_enabled(True)
cms_ctrl.set_monitored_address_range_upper_bound_enabled(True)
'''
from packet_format import Packet_Format

import datetime
import pickle
import os
from copy import deepcopy
import json
from pathlib import Path
import pprint 


class ATF_MODE:
    PATTERN_COLLECTION = 0
    ANOMALY_DETECTION = 1

class BASIC_TRACE_FILTER_MODE:
    JUMP_BRANCH_RETURN = 0
    ALL_INSTRUCTIONS = 1
    TIME_INTERVAL = 2
    DISABLED = 3

class TIME_INTERVAL_TYPE:
    PROLONG_UNTIL_PC_CHANGE = 0
    DONT_PROLONG_UNTIL_PC_CHANGE = 1

atf_pkt_deterministic_structure = Packet_Format.atf_data_pkt_deterministic

# must match the atf_data_pkt_deterministic structure in "continuous_monitoring_system.sv" file
# atf_pkt_deterministic_structure = {
#     # from MSB to LSB
#     # 'bits T6': 64,
#     # 'bits T5': 64,
#     # 'bits T4': 64,
#     # 'bits T3': 64,
#     # 'bits S11': 64,
#     # 'bits S10': 64,
#     # 'bits S9': 64,
#     # 'bits S8': 64,
#     # 'bits S7': 64,
#     # 'bits S6': 64,
#     # 'bits S5': 64,
#     # 'bits S4': 64,
#     # 'bits S3': 64,
#     'S2': 64,
#     # 'bits A7': 64,
#     # 'bits A6': 64,
#     # 'bits A5': 64,
#     # 'bits A4': 64,
#     'A3': 64,
#     'A2': 64,
#     'A1': 64,
#     'A0': 64,
#     'S1': 64,
#     'S0 / Frame pointer': 64,
#     # 'bits T2': 64,
#     'T1': 64,
#     'T0': 64,
#     'Thread pointer': 64,
#     'Global pointer': 64,
#     'Stack pointer': 64,
#     'Return address': 64,
#     'performance_events' : 39,
#     'instr': 32,
#     'pc': 64
# }


# helper functions
def bits_in_int(n, bit_type, bit_size=1024):
    count = 0
    while n:
        n &= n - 1
        count += 1
    if bit_type == 0:
        return bit_size - count
    return count

def calculate_atf_pkt_deterministic_offset(key):
    offset = 0
    for k in atf_pkt_deterministic_structure.keys():
        if k == key:
            return offset
        offset += atf_pkt_deterministic_structure[k]

# def calculate_atf_pkt_deterministic_offset(key):
#     offset = 0
#     keys = list(atf_pkt_deterministic_structure.keys())
#     for k in reversed(keys):
#         if k == key:
#             return offset
#         offset += atf_pkt_deterministic_structure[k]

def create_seed_mask_and_range_for_values(values_dict):
    seed = 0
    mask = 0
    for k, v in values_dict.items():
        mask_chunk = ((1 << atf_pkt_deterministic_structure[k]) - 1) << calculate_atf_pkt_deterministic_offset(k)
        mask |= mask_chunk
        seed |= (v << calculate_atf_pkt_deterministic_offset(k)) & mask_chunk
    # range is a single number, it is equal to the number of bits in the mask
    # this way the specified seed must match exactly the current atf_data_pkt_deterministic, resulting in the number
    # of positive bits equal to range_
    range_ = bits_in_int(mask, bit_type=1, bit_size=1024) 
    return seed, mask, range_

# print( create_seed_mask_and_range_for_values({'A0': 0x80000000, 'A1': 0x80000000, 'A2': 0x80000000, 'A3': 0x80000000}) )
# exit()

class ContinuousMonitoringSystemController:
    # Addresses match "continuous_monitoring_system.v" file. 
    ADDR_TRIGGER_TRACE_START_ADDRESS_ENABLED = 0
    ADDR_TRIGGER_TRACE_END_ADDRESS_ENABLED = 1
    ADDR_TRIGGER_TRACE_START_ADDRESS = 2
    ADDR_TRIGGER_TRACE_END_ADDRESS = 3
    ADDR_MONITORED_ADDRESS_RANGE_LOWER_BOUND_ENABLED = 4
    ADDR_MONITORED_ADDRESS_RANGE_UPPER_BOUND_ENABLED = 5
    ADDR_MONITORED_ADDRESS_RANGE_LOWER_BOUND = 6
    ADDR_MONITORED_ADDRESS_RANGE_UPPER_BOUND = 7
    ADDR_WFI_REACHED = 8
    ADDR_CLK_COUNTER = 9
    ADDR_LAST_WRITE_TIMESTAMP = 10
    ADDR_TLAST_INTERVAL = 11
    ADDR_HALTING_ON_FULL_FIFO_ENABLED = 12
    ADDR_ARBITRARY_HALT = 13
    ADDR_ATF_SEED_INPUT = 14
    ADDR_ATF_SEED_MASK_INPUT = 15
    ADDR_ATF_SEED_ADDRESS = 16
    ADDR_ATF_SEED_WRITE_ENABLE = 17
    ADDR_ATF_LOWER_BOUND_INPUT = 18
    ADDR_ATF_UPPER_BOUND_INPUT = 19
    ADDR_ATF_RANGE_ADDRESS = 20
    ADDR_ATF_RANGE_WRITE_ENABLE = 21
    ADDR_ATF_ACTIVE = 22
    ADDR_ATF_MODE = 23
    ADDR_BASIC_TRACE_FILTER_MODE = 24
    ADDR_BASIC_TRACE_FILTER_TIME_INTERVAL_TICKS = 25
    ADDR_BASIC_TRACE_FILTER_TIME_INTERVAL_TYPE = 26
    ADDR_EXTERNAL_TRACE_FILTER_MODE = 27
    ADDR_ENABLE_FEATURE_EXTRACTOR_HALTING_CPU = 28

    CONFIG_FILE = 'cms_config.ini'

    def __init__(self, axi_gpio, verbose=False):
        # self.axi_gpio = axi_gpio
        # config is stored whenever data is sent to CMD, 
        # so it's disabled while config is restored
        self.storing_config_enabled = False

        self.sr_data_input = axi_gpio[0:16]
        self.sr_shift_signal = axi_gpio[16]
        self.ctrl_addr = axi_gpio[17:25]
        self.ctrl_write_enable = axi_gpio[25]
        self.verbose = verbose

        self.halting_cpu = False

        self.trigger_trace_start_address_enabled = False
        self.trigger_trace_end_address_enabled = False
        self.trigger_trace_start_address = 0x1000
        self.trigger_trace_end_address = 0x80000106
        self.monitored_address_range_lower_bound_enabled = False
        self.monitored_address_range_upper_bound_enabled = False
        self.monitored_address_range_lower_bound = 0x0FFF
        self.monitored_address_range_upper_bound = 0x800000FF

        self.basic_trace_filter_mode = BASIC_TRACE_FILTER_MODE.JUMP_BRANCH_RETURN
        self.basic_trace_filter_time_interval_ticks = 1000
        self.basic_trace_filter_time_interval_type = TIME_INTERVAL_TYPE.DONT_PROLONG_UNTIL_PC_CHANGE

        self.external_trace_filter_mode_enabled = False
        self.feature_extractor_halting_cpu_enabled = False

        self.atf_mode = ATF_MODE.ANOMALY_DETECTION
        self.atf_active = False
        # watchpoints are restored using different mechanism

        self.tlast_interval = 0

        self.reset_wfi_wait()
        self.reset_atf()

        loaded = self.load_config()
        if loaded:
            self.push_config_to_CMS()
        self.storing_config_enabled = True
    
    def enable_storing_config(self):
        self.storing_config_enabled = True
    
    def disable_storing_config(self):
        self.storing_config_enabled = False

    def store_config(self):
        # merge path to this file with the config file name
        f_name = Path(__file__).parent / self.CONFIG_FILE
        not_to_store = ['CONFIG_FILE', 'sr_data_input', 'sr_shift_signal', 'ctrl_addr', 'ctrl_write_enable', 'verbose', 'storing_config_enabled']
        try: 
            with open(f_name, 'wb') as f:
                d = {deepcopy(k): deepcopy(v) for k, v in self.__dict__.items() if (k not in not_to_store and not k.startswith('ADDR_') and not callable(v))}
                pickle.dump(d, f)
                if self.verbose:
                    print('continuous_monitoring_system_controller config stored:')
                    pprint.pprint(d)
        except Exception as e:
            print(f'Error while storing continuous_monitoring_system_controller config: {e}')

    def load_config(self):
        # merge path to this file with the config file name
        f_name = Path(__file__).parent / self.CONFIG_FILE
        if not os.path.exists(f_name):
            print(f'continuous_monitoring_system_controller config file not found: {f_name}')
            return False
        try:
            with open(f_name, 'rb') as f:
                loaded_dict = pickle.load(f)
                self.__dict__.update(loaded_dict)
                if self.verbose:
                    print('continuous_monitoring_system_controller config loaded:')
                    pprint.pprint(loaded_dict) 
        except Exception as e:
            print(f'Error while loading continuous_monitoring_system_controller config: {e}')
            return False
        return True
    
    def get_config(self):
        not_to_store = ['CONFIG_FILE', 'sr_data_input', 'sr_shift_signal', 'ctrl_addr', 'ctrl_write_enable', 'verbose', 'storing_config_enabled']
        return {deepcopy(k): deepcopy(v) for k, v in self.__dict__.items() if (k not in not_to_store and not k.startswith('ADDR_') and not callable(v))}

    def update_attributes(self, attributes):
        ''' Update attributes from a dictionary. '''
        errors_str = ''
        # if attribute not found in the object, it is ignored and added to the errors_str
        updated_at_least_one = False
        for k, v in attributes.items():
            if hasattr(self, k):
                setattr(self, k, v)
                updated_at_least_one = True
            else:
                errors_str += f'Attribute {k} not found in the object.\n'
        if updated_at_least_one:
            self.push_config_to_CMS()
            self.store_config()
        return errors_str

    def push_config_to_CMS(self):
        self.storing_config_enabled = False
        self.set_trigger_trace_start_address_enabled(self.trigger_trace_start_address_enabled)
        self.set_trigger_trace_end_address_enabled(self.trigger_trace_end_address_enabled)
        self.set_trigger_trace_start_address(self.trigger_trace_start_address)
        self.set_trigger_trace_end_address(self.trigger_trace_end_address)
        self.set_monitored_address_range_lower_bound_enabled(self.monitored_address_range_lower_bound_enabled)
        self.set_monitored_address_range_upper_bound_enabled(self.monitored_address_range_upper_bound_enabled)
        self.set_monitored_address_range_lower_bound(self.monitored_address_range_lower_bound)
        self.set_monitored_address_range_upper_bound(self.monitored_address_range_upper_bound)
        self.set_basic_trace_filter_mode(self.basic_trace_filter_mode)
        self.set_basic_trace_filter_time_interval_ticks(self.basic_trace_filter_time_interval_ticks)
        self.set_basic_trace_filter_time_interval_type(self.basic_trace_filter_time_interval_type)
        self.enable_external_trace_filter() if self.external_trace_filter_mode_enabled else self.disable_external_trace_filter()
        self.enable_feature_extractor_halting_cpu() if self.feature_extractor_halting_cpu_enabled else self.disable_feature_extractor_halting_cpu()
        self.set_atf_mode(self.atf_mode)
        self.enable_atf() if self.atf_active else self.disable_atf()
        self.set_tlast_interval(self.tlast_interval)
        self.enable_halting_cpu() if self.halting_cpu else self.disable_halting_cpu()
        self.storing_config_enabled = True
    
    def set_verbose(self, verbose):
        self.verbose = verbose

    def print_config(self):
        basic_trace_filter_mode_str = 'JUMP_BRANCH_RETURN' if self.basic_trace_filter_mode == BASIC_TRACE_FILTER_MODE.JUMP_BRANCH_RETURN else 'ALL_INSTRUCTIONS' if self.basic_trace_filter_mode == BASIC_TRACE_FILTER_MODE.ALL_INSTRUCTIONS else 'TIME_INTERVAL' if self.basic_trace_filter_mode == BASIC_TRACE_FILTER_MODE.TIME_INTERVAL else 'DISABLED'
        atf_mode_str = 'PATTERN_COLLECTION' if self.atf_mode == ATF_MODE.PATTERN_COLLECTION else 'ANOMALY_DETECTION'
        print()
        print('Continuous Monitoring System Controller configuration:') 
        print('    trigger_trace_start_address_enabled:', self.trigger_trace_start_address_enabled)
        print('    trigger_trace_end_address_enabled:', self.trigger_trace_end_address_enabled)
        print('    trigger_trace_start_address:', hex(self.trigger_trace_start_address))
        print('    trigger_trace_end_address:', hex(self.trigger_trace_end_address))
        print('    monitored_address_range_lower_bound_enabled:', self.monitored_address_range_lower_bound_enabled)
        print('    monitored_address_range_upper_bound_enabled:', self.monitored_address_range_upper_bound_enabled)
        print('    monitored_address_range_lower_bound:', hex(self.monitored_address_range_lower_bound))
        print('    monitored_address_range_upper_bound:', hex(self.monitored_address_range_upper_bound))
        print('    basic_trace_filter_mode:', basic_trace_filter_mode_str)
        print('    basic_trace_filter_time_interval_ticks:', self.basic_trace_filter_time_interval_ticks)
        print('    basic_trace_filter_time_interval_type:', self.basic_trace_filter_time_interval_type)
        print('    external_trace_filter_mode_enabled:', self.external_trace_filter_mode_enabled)
        print('    feature_extractor_halting_cpu_enabled:', self.feature_extractor_halting_cpu_enabled)
        print('    atf_mode:', atf_mode_str)
        print('    atf_active:', self.atf_active)
        print('    tlast_interval:', self.tlast_interval)
        print('    halting_cpu:', self.halting_cpu)
        print()

    def set_ctrl_wdata(self, value):
        for i in reversed(range(4)):
            # shift bits signal = low
            self.sr_shift_signal.write(0)
            # write LSB first
            self.sr_data_input.write((value >> (i * 16)) & 0xFFFF)
            # shift signal = high (posedge activated)
            self.sr_shift_signal.write(1)

    def send_data_to_cms(self, data, address):
        ''' Single AXI GPIO block is used to interact with control inputs ("ctrl") of CMS module having 73 bits.
            For that reason a shift register is used. It has 16 bit data input and 1 shift signal (posedge activated), 
            and outputs 64 bits to "ctrl_wdata" of the CMS module. The AXI GPIO maps to:
                0-15  : shift register input bits (16 bits)
                16    : shift register shift signal
                17-24 : "ctrl_addr" of CMS module (8 bits)
                25    : "ctrl_write_enable" of CMS module
        '''
        # write enable = low
        self.ctrl_write_enable.write(0)
        # write address
        self.ctrl_addr.write(address)
        # send ctrl_wdata (64-bits) through shift register (16 bits at a time)
        # (send 4 * 16 bits, resulting in 64bit ctrl_wdata input of CMS module)
        self.set_ctrl_wdata(data)
        self.ctrl_write_enable.write(1)
        self.ctrl_write_enable.write(0)

        if self.storing_config_enabled:
            is_address_watchpoint_related = address in [
                self.ADDR_ATF_SEED_INPUT,
                self.ADDR_ATF_SEED_MASK_INPUT,
                self.ADDR_ATF_SEED_ADDRESS,
                self.ADDR_ATF_SEED_WRITE_ENABLE,
                self.ADDR_ATF_LOWER_BOUND_INPUT,
                self.ADDR_ATF_UPPER_BOUND_INPUT,
                self.ADDR_ATF_RANGE_ADDRESS,
                self.ADDR_ATF_RANGE_WRITE_ENABLE
            ]

            if not is_address_watchpoint_related:
                self.store_config()
    
    ###############################################
    # Trigger control functions (start/stop trace when certain program counter value is executed)
    def set_trigger_trace_start_address_enabled(self, enable=True):
        self.trigger_trace_start_address_enabled = enable
        self.send_data_to_cms(enable, __class__.ADDR_TRIGGER_TRACE_START_ADDRESS_ENABLED)

    def set_trigger_trace_end_address_enabled(self, enable=True):
        self.trigger_trace_end_address_enabled = enable
        self.send_data_to_cms(enable, __class__.ADDR_TRIGGER_TRACE_END_ADDRESS_ENABLED)

    def set_trigger_trace_start_address(self, value):
        self.trigger_trace_start_address = value
        self.send_data_to_cms(value, __class__.ADDR_TRIGGER_TRACE_START_ADDRESS)

    def set_trigger_trace_end_address(self, value):
        self.trigger_trace_end_address = value
        self.send_data_to_cms(value, __class__.ADDR_TRIGGER_TRACE_END_ADDRESS)

    ###############################################
    # Monitored address range functions (collect data only when program counter is in certain range)
    def set_monitored_address_range_lower_bound_enabled(self, enable=True):
        self.monitored_address_range_lower_bound_enabled = enable
        self.send_data_to_cms(enable, __class__.ADDR_MONITORED_ADDRESS_RANGE_LOWER_BOUND_ENABLED)

    def set_monitored_address_range_upper_bound_enabled(self, enable=True):
        self.monitored_address_range_upper_bound_enabled = enable
        self.send_data_to_cms(enable, __class__.ADDR_MONITORED_ADDRESS_RANGE_UPPER_BOUND_ENABLED)

    def set_monitored_address_range_lower_bound(self, value):
        self.monitored_address_range_lower_bound = value
        self.send_data_to_cms(value, __class__.ADDR_MONITORED_ADDRESS_RANGE_LOWER_BOUND)

    def set_monitored_address_range_upper_bound(self, value):
        self.monitored_address_range_upper_bound = value
        self.send_data_to_cms(value, __class__.ADDR_MONITORED_ADDRESS_RANGE_UPPER_BOUND)

    ###############################################
    # tlast interval 
    def set_tlast_interval(self, value):
        """Sets the number of extracted items after which the tlast will be asserted.
        Tlast ends AXI/DMA transfer. It should be set to the number of items that fit 
        into allocated contiguous memory (pynq.allocate). 
        
        Setting it to 0 will disable it. """
        self.tlast_interval = value
        self.send_data_to_cms(value, __class__.ADDR_TLAST_INTERVAL)

    ###############################################
    # if a program has "wait for interrupt" (wfi) instruction at the end, 
    # the cms will stop the trace. if we decide to run/trace another program
    # we may want to use this function, otherwise trace will not start.
    # (btw another way to reset the wfi wait is to load the overlay 'bit/hwh' again)
    def reset_wfi_wait(self):
        self.send_data_to_cms(0, __class__.ADDR_WFI_REACHED)

    def reset_clk_counter(self):
        self.send_data_to_cms(0, __class__.ADDR_CLK_COUNTER)
    
    def reset_last_write_timestamp(self):
        self.send_data_to_cms(0, __class__.ADDR_LAST_WRITE_TIMESTAMP)

    ###############################################
    # halting cpu when fifo (internal trace storage) is full 
    def enable_halting_cpu(self):
        self.halting_cpu = True
        self.send_data_to_cms(1, __class__.ADDR_HALTING_ON_FULL_FIFO_ENABLED)

    def disable_halting_cpu(self):
        ''' Disabling may be useful for checking that program works well in general
        by interacting with it through console I/O. This wouldn't be possible with 
        halting enabled unless we extract data very fast.'''
        self.halting_cpu = False
        self.send_data_to_cms(0, __class__.ADDR_HALTING_ON_FULL_FIFO_ENABLED)
    
    ###############################################
    # arbitrary halt
    def activate_arbitrary_halt(self):
        self.send_data_to_cms(1, __class__.ADDR_ARBITRARY_HALT)
    
    def deactivate_arbitrary_halt(self):
        ''' If halting cpu on full data storage is enabled, the CPU will
        remain halted if the storage is full. That's why it's called "deactivate" instead of "resume_cpu" '''
        self.send_data_to_cms(0, __class__.ADDR_ARBITRARY_HALT)

    ###############################################
    # Advanced trace filter (ATF) configuration

    # Main functions to be used as public
    def set_atf_mode(self, mode):
        ''' ATF_MODE.PATTERN_COLLECTION: atf_data_pkt_deterministic collection mode
                  (for recognizing infrequent patterns/events based on binary similarity to seed values)
                  (this is done for the sake of slowing down data collection to a reasonable rate that will
                   allow detecting anomalies in software and displaying collected metrics in real time on a display)
            ATF_MODE.ANOMALY_DETECTION: data_pkt collection mode
                  (for anomaly detection)
                  
        A typical workflow for using ATF modes:
        - set gpio_rst_n to 0 to set processor in inactive state
        - enable_aft()
        - setting pattern collection mode to collect data_pkt_deterministic values
        - calculate similarities to seed values and plot them with matplotlib
        - examine the plot and decide which similarity value ranges to use
        - set seeds and ranges using methods:
                set_atf_seed_input,
                set_atf_seed_address,
                set_atf_seed_trigger_write_enable,
                set_atf_lower_bound_input,
                set_atf_upper_bound_input,
                set_atf_range_address,
                set_atf_range_trigger_write_enable
        - set anomaly detection mode to collect data_pkt values
        - data for anomaly detection (counter values) should arrive in fifo at reasonable rates
        '''
        self.atf_mode = mode
        self.send_data_to_cms(mode, __class__.ADDR_ATF_MODE)

    def set_atf_match_rule(self, seed_address, values_dict, seed=None, mask=None, bits_to_use=None):
        ''' takes one seed, the range is a number of positive bits in the mask 
        this way it results in direct match of values specified in values_dict. 

        Example use:
            values_dict = {'pc': 0x80000000, 'A0': 0x80000000, 'A1': 0x80000000, 'A2': 0x80000000, 'A3': 0x80000000}
            cms_ctrl.set_atf_match_rule(seed_address=0, values_dict)
        '''
        if seed is None or mask is None or bits_to_use is None:
            seed, mask, bits_to_use = create_seed_mask_and_range_for_values(values_dict)
        self.set_atf_seed(seed, seed_address, mask=mask)
        # to prevent watchpoints with no attributes from being triggered
        # all the time
        if bits_to_use is not None and bits_to_use > 0:
            self.set_atf_range(seed_address, range_address=0, lower_bound=bits_to_use, upper_bound=bits_to_use)
        else:
            # never matching watchpoint
            self.set_atf_range(seed_address, range_address=0, lower_bound=1023, upper_bound=0)

    def reset_atf_match_rule(self, seed_address, num_of_ranges=8):
        self.set_atf_seed(0, seed_address, seed_bit_width=1024)
        for i in range(num_of_ranges):
            self.set_atf_range(seed_address=seed_address, range_address=i, lower_bound=1023, upper_bound=0)

    def reset_atf(self, num_of_seeds=16, num_of_ranges=8):
        # makes all seeds and ranges inactive
        for i in range(num_of_seeds):
            self.reset_atf_match_rule(i, num_of_ranges=num_of_ranges)
            # self.set_atf_seed(0, i, seed_bit_width=1024)
            # for j in range(num_of_ranges):
            #     self.set_atf_range(seed_address=i, range_address=j, lower_bound=1023, upper_bound=0)

    def set_atf_seed(self, seed_value, address, mask=None, seed_bit_width=1024):
        self.set_atf_seed_address(address)
        self.set_atf_seed_input(seed_value, mask=mask, seed_bit_width=seed_bit_width)
        self.set_atf_seed_trigger_write_enable()

    def set_atf_range(self, seed_address, range_address, lower_bound, upper_bound):
        self.set_atf_seed_address(seed_address)
        self.set_atf_lower_bound_input(lower_bound)
        self.set_atf_upper_bound_input(upper_bound)
        self.set_atf_range_address(range_address)
        self.set_atf_range_trigger_write_enable()

    def enable_atf(self):
        ''' advanced trace filter is disabled by default '''
        self.atf_active = True
        self.send_data_to_cms(1, __class__.ADDR_ATF_ACTIVE)
    
    def disable_atf(self):
        self.atf_active = False
        self.send_data_to_cms(0, __class__.ADDR_ATF_ACTIVE)

    # Internal functions
    def set_atf_seed_input(self, seed_value, mask=None, seed_bit_width=1024):
        ''' The seed value may be very long (e.g. 512 bits), the ctrl_wdata is only 64 bits wide,
        for that reason it must be supplied by writing multiple times to this address.  '''
        assert type(seed_value) != str, "Seed value must be an integer, not a string."
        assert seed_bit_width % 64 == 0, "Seed bit width must be a multiple of 64."
        # mask full of ones (full seed being used)
        if mask is None:
            mask = (1 << seed_bit_width) - 1
        # send MSB first
        first_i = None
        for i in reversed(range(0, seed_bit_width, 64)):
            if first_i is None: 
                first_i = i
            # send the MSB 64 bits of the seed value
            self.send_data_to_cms(seed_value >> first_i, __class__.ADDR_ATF_SEED_INPUT)
            self.send_data_to_cms(mask >> first_i, __class__.ADDR_ATF_SEED_MASK_INPUT)
            seed_value <<= 64
            mask <<= 64

    def set_atf_seed_address(self, address):
        ''' Address range depends on the number of maximum seeds allowed by ATF.
        It is a generic parameter of the ATF module (and possibly will be generic parameter
        of the cms_wrapper_ip). '''
        self.send_data_to_cms(address, __class__.ADDR_ATF_SEED_ADDRESS)

    def set_atf_seed_trigger_write_enable(self):
        ''' The write enable signal gets automatically cleared on the next clock cycle
        after this function action is applied.  '''
        self.send_data_to_cms(1, __class__.ADDR_ATF_SEED_WRITE_ENABLE)

    def set_atf_lower_bound_input(self, lower_bound):
        self.send_data_to_cms(lower_bound, __class__.ADDR_ATF_LOWER_BOUND_INPUT)
    
    def set_atf_upper_bound_input(self, upper_bound):
        self.send_data_to_cms(upper_bound, __class__.ADDR_ATF_UPPER_BOUND_INPUT)
    
    def set_atf_range_address(self, address):
        ''' A single seed may be associated with multiple address ranges. '''
        self.send_data_to_cms(address, __class__.ADDR_ATF_RANGE_ADDRESS)

    def set_atf_range_trigger_write_enable(self):
        ''' The write enable signal gets automatically cleared on the next clock cycle
        after this function action is applied.  '''
        self.send_data_to_cms(1, __class__.ADDR_ATF_RANGE_WRITE_ENABLE)

    ###############################################
    # Basic trace filter configuration

    def set_basic_trace_filter_mode(self, mode):
        ''' Common internal function, not to be used outside of this class. '''
        self.basic_trace_filter_mode = mode
        self.send_data_to_cms(mode, __class__.ADDR_BASIC_TRACE_FILTER_MODE)

    def set_basic_trace_filter_mode_jump_branch_return(self):
        ''' Only jump, branch and return instructions will be collected.'''
        self.set_basic_trace_filter_mode(BASIC_TRACE_FILTER_MODE.JUMP_BRANCH_RETURN)

    def set_basic_trace_filter_mode_all_instructions(self):
        ''' Every instructions will be collected, regardless if it's jump, branch or return.'''
        self.set_basic_trace_filter_mode(BASIC_TRACE_FILTER_MODE.ALL_INSTRUCTIONS)

    # time interval functions
    def set_basic_trace_filter_mode_time_interval(self):
        ''' This mode will only collect instructions when pc_valid is high (it won't send 
        repeated instructions until the instruction itself changes). '''
        self.set_basic_trace_filter_mode(BASIC_TRACE_FILTER_MODE.TIME_INTERVAL)

    def set_basic_trace_filter_time_interval_ticks(self, ticks):
        ''' time interval in ticks (1 tick = 1 clock cycle)
        Only applicable when basic trace filter mode is set to TIME_INTERVAL. '''
        self.basic_trace_filter_time_interval_ticks = ticks
        self.send_data_to_cms(ticks, __class__.ADDR_BASIC_TRACE_FILTER_TIME_INTERVAL_TICKS)

    def set_basic_trace_filter_time_interval_type(self, type_):
        ''' TIME_INTERVAL_TYPE.PROLONG_UNTIL_PC_CHANGE: prolong the time interval until pc changes
            TIME_INTERVAL_TYPE.DONT_PROLONG_UNTIL_PC_CHANGE: don't prolong the time interval until pc changes
        Only applicable when basic trace filter mode is set to TIME_INTERVAL. '''
        self.basic_trace_filter_time_interval_type = type_
        self.send_data_to_cms(type_, __class__.ADDR_BASIC_TRACE_FILTER_TIME_INTERVAL_TYPE)
    
    def set_basic_trace_filter_time_interval_prolong_until_pc_change(self):
        self.set_basic_trace_filter_time_interval_type(TIME_INTERVAL_TYPE.PROLONG_UNTIL_PC_CHANGE)
    
    def set_basic_trace_filter_time_interval_dont_prolong_until_pc_change(self):
        self.set_basic_trace_filter_time_interval_type(TIME_INTERVAL_TYPE.DONT_PROLONG_UNTIL_PC_CHANGE)

    ###############################################
    # external trace filter mode (mainly for feature extractor)
    def enable_external_trace_filter(self):
        self.external_trace_filter_mode_enabled = True
        self.send_data_to_cms(1, __class__.ADDR_EXTERNAL_TRACE_FILTER_MODE)
    
    def disable_external_trace_filter(self):
        self.external_trace_filter_mode_enabled = False
        self.send_data_to_cms(0, __class__.ADDR_EXTERNAL_TRACE_FILTER_MODE)

    ###############################################
    # feature extractor halting cpu when its fifo is full
    def enable_feature_extractor_halting_cpu(self):
        self.feature_extractor_halting_cpu_enabled = True
        self.send_data_to_cms(1, __class__.ADDR_ENABLE_FEATURE_EXTRACTOR_HALTING_CPU)

    def disable_feature_extractor_halting_cpu(self):
        self.feature_extractor_halting_cpu_enabled = False
        self.send_data_to_cms(0, __class__.ADDR_ENABLE_FEATURE_EXTRACTOR_HALTING_CPU)

