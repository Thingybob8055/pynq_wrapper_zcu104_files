from tcp_server import TCP_Server, get_my_ip
from packet_format import Packet_Format
from advanced_trace_filter import ATF_Watchpoints
from parse_objdump import parse_objdump
from anomaly_detection import Anomaly_Detection

import numpy as np
from pathlib import Path
import os
import inspect
import sys
import json
import random
import time
import datetime
import math


class Nop(object):
    ''' dummy class to avoid errors due to lack of "cms_ctrl" object. '''
    def nop(*args, **kw): pass
    def __getattr__(self, _): return self.nop



PROGRAMS_DIR = Path('programs_for_tcp_server_testing_implementation')

def list_subfolders_with_paths(path):
    ''' From: https://stackoverflow.com/a/59938961/4620679 '''
    return [f.path for f in os.scandir(path) if f.is_dir()]

class MODE:
    ''' Operational mode, controlled by TCP client.
    This isn't any internal hardware mode, it is just for this PYNQ script, 
    and to allow the TCP client to control what should happen. '''
    # these can be used with bitwise operators (need to be careful if new modes are added)
    IDLE = 0
    TRAINING = 0b1
    TESTING = 0b10
    TRAINING_AND_TESTING = 0b11
    
    # This mode should be done just after training.
    # While in this mode, we should repeat all the 
    # same actions that were done during training
    # but this time the lowest encountered similarity
    # will become detection threshold for the testing
    # mode.
    DETECTION_THRESHOLD_CALIBRATION = 0b100 

class SimulatedPynqBoard:
    def __init__(self):
        # declaration of some variables that are controlled by the client.
        self.mode = MODE.IDLE    
        self.loaded_program = ''
        self.is_running = False
        self.is_halted = False
        self.dataset_size = 0
        self.is_arbitrary_halt_active = False
        self.atf_watchpoints = ATF_Watchpoints(Nop())
        self.anomaly_detection = Anomaly_Detection()
        self.pynq_restarted = True
        self.program_load_progress = 0

    def set_loaded_program(self, program_name):
        self.loaded_program = program_name
    
    def get_loaded_program(self):
        return self.loaded_program
    
    def set_is_running(self, is_running):
        self.is_running = is_running
    
    def get_is_running(self):
        return self.is_running

    def set_is_halted(self, is_halted):
        self.is_halted = is_halted

    def get_is_halted(self):
        return self.is_halted
    
    def set_mode(self, mode):
        self.mode = mode
    
    def get_mode(self):
        return self.mode
    
    # def set_dataset_size(self, dataset_size):
    #     self.dataset_size = dataset_size
    
    def get_dataset_size(self):
        # return self.dataset_size
        return self.anomaly_detection.get_dataset_size()
    
    def set_is_arbitrary_halt_active(self, is_arbitrary_halt_active):
        self.is_arbitrary_halt_active = is_arbitrary_halt_active
    
    def get_is_arbitrary_halt_active(self):
        return self.is_arbitrary_halt_active

    def set_pynq_restarted(self, pynq_restarted):
        self.pynq_restarted = pynq_restarted
    
    def get_pynq_restarted(self):
        return self.pynq_restarted

    def set_similarity_threshold(self, similarity_threshold):
        self.anomaly_detection.set_similarity_threshold(similarity_threshold)
    
    def get_similarity_threshold(self):
        return self.anomaly_detection.get_similarity_threshold()
    
    def set_program_load_progress(self, program_load_progress):
        self.program_load_progress = program_load_progress

    def get_program_load_progress(self):
        return self.program_load_progress

    def reset_dataset(self):
        self.dataset_size = 0
        self.anomaly_detection.reset_dataset()
    
    


def generate_status_update_dict():
    # function created to create consistent message for "status_update"
    # and return of "rpc_update_status", so both can be parsed
    # using the same routine
    return {
        'pynq_restarted' : simulated_pynq_board.get_pynq_restarted(),
        'dataset_size' : simulated_pynq_board.get_dataset_size(),
        'mode' : simulated_pynq_board.get_mode(),
        'is_halted' : simulated_pynq_board.get_is_halted(),
        'loaded_program' : simulated_pynq_board.get_loaded_program(),
        'is_running': simulated_pynq_board.get_is_running(),
        'program_load_progress' : simulated_pynq_board.get_program_load_progress(),
        'similarity_threshold' : simulated_pynq_board.get_similarity_threshold(),
        'features_keys' : Packet_Format.get_anomaly_detection_features_names(),
        'atf_watchpoints' : simulated_pynq_board.atf_watchpoints.get_watchpoints_as_strings()
    }

#####################################################################
# API calls for the TCP server (copy of the ones in pynq_wrapper.ipynb)
def rpc_list_programs():
    ''' TCP server API.'''
    # key=main program name (dir name in programs) value=list of programs (e.g. ecg_baseline.bin, ecg_ino_leak.bin)
    programs = {}
    for path in list_subfolders_with_paths(str(PROGRAMS_DIR)):
        p_name = os.path.basename(path)
        programs[p_name] = sorted([f_name.split('.')[0] for f_name in os.listdir(path) if f_name.endswith(".bin")])
    return programs
    #response = {'programs':programs}
    #return json.dumps(response)

def rpc_list_objdumps():
    objdumps = {}
    for path in list_subfolders_with_paths(str(PROGRAMS_DIR)):
        p_name = os.path.basename(path)
        objdump_path = Path(path) / 'objdump'
        objdumps[p_name] = sorted([f_name.split('.')[0] for f_name in os.listdir(objdump_path) if f_name.endswith(".dump")])
    return objdumps

def rpc_get_objdump_data(category, objdump_fname):
    # {'_start': {'80000000': {'name': 'entry', 'type': 'entry'},
    #             '80000004': {'branch_destination': '<park>',
    #                          'name': 'BNEZ',
    #                          'type': 'branch'},
    #             '80000010': {'branch_destination': '<main>',
    #                          'name': 'J',
    #                          'type': 'branch'}},
    # 'main': {'80000038': {'name': 'entry', 'type': 'entry'},
    #           '80000088': {'branch_destination': '<main+0x6c>', 'name': 'BEQZ', 'type': 'branch'},
    #           '80000094': {'name': 'uart_gpio_puts', 'type': 'function'},    
    if not objdump_fname.endswith('.dump'):
        objdump_fname += '.dump'
        
    full_fname = PROGRAMS_DIR / Path(category) / f'objdump/{objdump_fname}'
    try:
        return parse_objdump(full_fname)
    except Exception as e:
        error_msg = f'ERROR: failed parsing "{full_fname}" file: ' + str(e)
        print(error_msg)
        return error_msg

def rpc_load_program(name):
    ''' TCP server API. '''
    if not name.endswith('.bin'):
        name += '.bin'
    for dirpath, d_names, f_names in os.walk(str(PROGRAMS_DIR)):
        for f_name in f_names:
            if f_name != name:
                continue
            full_path = os.path.join(dirpath, name)
            loaded_program = name.split('.')[0]
            simulated_pynq_board.set_loaded_program(loaded_program)
            for n in [0, 25, 50, 75, 100]:
                time.sleep(0.5)
                simulated_pynq_board.set_program_load_progress(n)
                send_file_load_progress(n) 
            return f"OK: loaded {name} program."
            #return json.dumps({'status_update': f'OK: ran {name} program'})
    return f"ERROR: didn't find {name} program"

def rpc_run():
    simulated_pynq_board.set_is_running(True)
    simulated_pynq_board.set_is_arbitrary_halt_active(False)
    return "OK"

def rpc_halt():
    simulated_pynq_board.set_is_running(False)
    simulated_pynq_board.set_is_arbitrary_halt_active(True)
    return 'CPU halted'
    
def rpc_enable_training():
    mode = simulated_pynq_board.get_mode() | MODE.TRAINING
    simulated_pynq_board.set_mode(mode)
    return mode
    
def rpc_disable_training():
    mode = simulated_pynq_board.get_mode() & ~MODE.TRAINING
    simulated_pynq_board.set_mode(mode)
    return mode

def rpc_enable_testing():
    mode = simulated_pynq_board.get_mode() | MODE.TESTING
    simulated_pynq_board.set_mode(mode)
    return mode

def rpc_disable_testing():
    mode = simulated_pynq_board.get_mode() & ~MODE.TESTING
    simulated_pynq_board.set_mode(mode)
    return mode

def rpc_enable_detection_threshold_calibration():
    mode = simulated_pynq_board.get_mode() | MODE.DETECTION_THRESHOLD_CALIBRATION
    simulated_pynq_board.set_mode(mode)
    return mode
    
def rpc_disable_detection_threshold_calibration():
    mode = simulated_pynq_board.get_mode() & ~MODE.DETECTION_THRESHOLD_CALIBRATION
    simulated_pynq_board.set_mode(mode)
    return mode

def rpc_reset_dataset():
    simulated_pynq_board.reset_dataset()
    return 'Dataset resetted'

def rpc_update_status():
    return generate_status_update_dict()

def rpc_set_atf_watchpoint(index, is_active, json_str_attributes_dict, json_str_attributes_notes_dict={}):
    print(f'rpc_set_atf_watchpoint index={index} is_active={is_active} json_str_attributes_dict={json_str_attributes_dict}')
    try:
        attributes_dict = json.loads(json_str_attributes_dict)
    except Exception as e:
        error_msg = 'ERROR: rpc_set_atf_watchpoint: ' + str(e)
        print(error_msg)
        return error_msg
    try:
        attributes_notes_dict = json.loads(json_str_attributes_notes_dict)
    except Exception as e:
        error_msg = 'ERROR: rpc_set_atf_watchpoint (setting attributes_notes_dict): ' + str(e)
        print(error_msg)
        attributes_notes_dict = {}
    simulated_pynq_board.atf_watchpoints.set_watchpoint(index, attributes_dict, is_active, attributes_notes_dict=attributes_notes_dict)
    return f"OK_{index}"

def rpc_atf_watchpoint_set_active(index, state):
    print(f'rpc_atf_watchpoint_set_active index={index} state={state}')
    success = simulated_pynq_board.atf_watchpoints.set_watchpoint_active(int(index), state)
    return "OK" if success else f"WARNING: Watchpoint with index={index} wasn't there"

def rpc_remove_atf_watchpoint(index):
    success = simulated_pynq_board.atf_watchpoints.remove_watchpoint(index)
    return "OK" if success else f"WARNING: Watchpoint with index={index} wasn't there"

def rpc_set_similarity_threshold(threshold):
    simulated_pynq_board.set_similarity_threshold(float(threshold))
    return float(threshold)

def rpc_list_available_models():
    return simulated_pynq_board.anomaly_detection.list_datasets()

def rpc_save_detection_model(name):
    simulated_pynq_board.anomaly_detection.store_dataset(name)
    return "OK"
    
def rpc_load_detection_model(name):
    simulated_pynq_board.anomaly_detection.load_dataset(name)
    return "OK"

def rpc_send_stdin(stdin_str):
    print(f'rpc_send_stdin received but not implemented for simulated pynq board')
    return "OK"

def rpc_read_stdout():
    # if this is going to be implemented for some reason (e.g. viewing stdout in GUI)
    # then stdin_stdout_communication() function will need to store received stdout
    # in some global variable or some object
    print(f'rpc_read_stdout received but not implemented for simulated pynq board')
    return "Not implemented"

def rpc_readlines_stdout():
    print(f'rpc_readlines_stdout received but not implemented for simulated pynq board')
    return ['Not implemented']

def rcp_set_cms_ctrl_attributes(json_str_attributes_dict):
    print(f'rcp_set_cms_ctrl_attributes received but not implemented for simulated pynq board')
    return "Not implemented for simulated board"


    
#############################################################################
# Functions that the PYNQ board can use to notify all clients about 

def send_sensors_data(df_sensors, sensors_to_send):
    msg_to_server = ''
    for i in range(df_sensors.shape[0]):
        for col in sensors_to_send: #df_sensors.columns:
            val = float(df_sensors[col].iloc[i]) / 60000.0
            msg_to_server += f'add_point:{col},{val}\n'
    #print(msg_to_server)
    tcp_server.send_to_all(msg_to_server) 

def send_file_load_progress(percent):
    tcp_server.send_to_all(
        json.dumps({
            'status_update' : {
                'program_load_progress' : simulated_pynq_board.get_program_load_progress()
            }
        })
    )

def send_similarity_threshold(threshold):
    tcp_server.send_to_all(
        json.dumps({
            'status_update' : {
                'similarity_threshold' : simulated_pynq_board.get_similarity_threshold()
            }
        })
    )
    

PERIODIC_SEND_INTERVAL = 0.8 # in seconds 
# def send_periodic_update(similarities, items_since_last_send, clk_time_since_last_send, halted_time_since_last_send):
def send_periodic_update():
#     number_of_anomalies = sum(1 for s in similarities if s < simulated_pynq_board.get_similarity_threshold())
#     avg_sim_bot_1 = 1 if not similarities else np.mean( sorted(similarities)[:math.ceil(len(similarities)/100)] )
#     avg_sim = 1 if not similarities else np.mean(similarities)
# #     total_exec_time = clk_time_since_last_send + halted_time_since_last_send
# #     print('total_exec_time =', total_exec_time)
# #     print('clk_time_since_last_send =', clk_time_since_last_send)
# #     print('halted_time_since_last_send =', halted_time_since_last_send)
#     performance_rate = (1 - halted_time_since_last_send / (clk_time_since_last_send or 1)) # "or 1" prevents division by 0
    
    # is_anomalous = 0
    # if avg_sim_bot_1 != 1:
    #     is_anomalous = 1
    
    items_collected = random.randint(0, 2000)
    anomalies = random.randint(0, items_collected)
    tcp_server.send_to_all(
        json.dumps({
            'status_update' : {
                'dataset_size' : simulated_pynq_board.get_dataset_size()
            }, 
            'add_points' : {
                'Perf' : [random.uniform(0,1)],
                'Avg sim' : [random.uniform(0,1)],
                'Avg sim bot-1%' : [random.uniform(0, 1)],
                'Items collected' : [items_collected],
                'Anomalies' : [anomalies],
                'similarity_threshold' : [simulated_pynq_board.get_similarity_threshold()],
                'dataset_size' : [simulated_pynq_board.get_dataset_size()]
            }
        })
    )

def send_new_anomaly(metrics_dict, similarity, features_vector, most_similar_vector):  
    halt_agnostic_clk_counter = metrics_dict['clk_counter'] - metrics_dict['fifo_full_ticks_count']
    if most_similar_vector is None:
        # most_similar_vector can be None if the PC of features_vector isn't found 
        # at all in the dataset (because dataset is split into subdatasets grouped
        # by PC), in that case all "-1s" are sent 
        most_similar_vector = np.full_like(features_vector, -1.0)
    tcp_server.send_to_all(
        json.dumps({
            'new_anomaly' : {
                'pc' : f"0x{metrics_dict['pc']:X}",                                  # string
                'time' : datetime.datetime.now().strftime("%H:%M:%S"),               # string
                'total_clk_counter' : str(halt_agnostic_clk_counter),                # string
                'similarity' : similarity,                                           # float between 0 and 1
                'features_vector' : list(float(v) for v in features_vector),         # list of floats
                'most_similar_vector' : list(float(v) for v in most_similar_vector)  # list of floats
            }
        })
    )

if __name__ == '__main__':

    simulated_pynq_board = SimulatedPynqBoard()
    simulated_pynq_board.atf_watchpoints.load_watchpoints()

    TCP_SERVER_PORT = 9093
    tcp_server = TCP_Server(host_ip='0.0.0.0', port=TCP_SERVER_PORT, verbose=True)

    # all functions from this file that start with "rpc_"
    all_rpcs = [func for name,func in inspect.getmembers(sys.modules[__name__]) if (inspect.isfunction(func) and name.startswith('rpc_'))]
    tcp_server.register_rpcs(all_rpcs)

    tcp_server.start()
    print(f'TCP server can be accessed at localhost:{TCP_SERVER_PORT} and {get_my_ip()}:{TCP_SERVER_PORT}')

    tcp_server.send_to_all(json.dumps({'status_update': generate_status_update_dict() }))

    simulated_pynq_board.set_pynq_restarted(False)

    new_anomaly_msg = {
        'new_anomaly': {
            'features_vector': [2147484168.0, 15076565.0, 500.0, 2147571848.0, 1.0, 386841.0, 1851.0, 387128.0, 850.0, 1170031.0, 387128.0, 0.0, 729.0],
            'most_similar_vector': [2147484168.0, 15074777.0, 500.0, 2147571848.0, 1.0, 386750.0, 1787.0, 387016.0, 781.0, 1169363.0, 387016.0, 0.0, 674.0],
            'pc': '0x80000208',
            'similarity': 0.9851768022963886,
            'time': '03:28:12',
            'total_clk_counter': '15076565'
        }
    }

    while True:
        try:
            time.sleep(1)
            if not simulated_pynq_board.get_is_running() or simulated_pynq_board.get_mode() == MODE.IDLE:
                continue
            send_periodic_update()

            if simulated_pynq_board.get_mode() & MODE.TRAINING:
                simulated_pynq_board.anomaly_detection.update_dataset(np.random.rand(13))

            if simulated_pynq_board.get_mode() & MODE.TESTING:
                tcp_server.send_to_all(json.dumps(new_anomaly_msg))
                time.sleep(3)
        except KeyboardInterrupt:
            break