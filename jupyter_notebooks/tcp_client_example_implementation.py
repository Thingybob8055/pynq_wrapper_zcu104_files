'''
This file implements an example TCP client that can connect with the TCP server running
on the PYNQ board. The TCP client should be a part of a GUI application that allows the 
TCP client to do the following:
- request available programs from the TCP server
- select and load a program
- run the program
- halt the program
- resume the program
- enable/disable training state
- enable/disable testing state
- get periodical updates about the current state of the monitoring system,
  this happens every second if either training/testing is enabled and the program is running

If TCP server is restarted, it will notify the TCP client,
in that case the TCP client should ask for update of status.

If TCP client is restarted, it should ask for update of status too.


At the end of this file there is a code part (parse_tcp_message) from C++ 
based TCP client that was used for the previous demo (using Esp32 Arduino-like board). 
This Python client attempts to do the same but in a more readable way.
It also shows how to handle TCP server and TCP client restarting.
'''

import socket
import threading
import queue
import time
import json
import traceback
import pprint
import argparse

parser = argparse.ArgumentParser(description='TCP client for PYNQ monitoring system')
parser.add_argument('--ip', type=str, default='localhost', help='IP address of the TCP server')
parser.add_argument('--port', type=int, default=9093, help='Port of the TCP server')
args = parser.parse_args()

class TCP_Client:
    def __init__(self, server_ip, server_port):
        self.server_ip = server_ip
        self.server_port = server_port
        self.sock = None
        self.msg_queue = queue.Queue()
        self.receiving_thread = threading.Thread(target=self.receiving_worker, daemon=True)
        self.receiving_thread.start()
        self.connect()
    
    def __del__(self):
        self.disconnect()
    
    def connect(self):
        if self.sock:
            self.disconnect()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if not self.sock:
            print('Failed to create socket')
            return
        self.sock.connect((self.server_ip, self.server_port))
    
    def disconnect(self):
        self.sock.close()
        self.sock = None

    def send(self, data):
        if not data.endswith('\n'):
            data += '\n'
        self.sock.sendall(data.encode('utf-8'))

    # running as a thread
    def receiving_worker(self):
        ''' New line ('\n') is used as a message delimiter. 
        This function should put any new messages into self.msg_queue. 
        It should check for connection errors and reconnect if needed. '''
        data = ''
        while True:
            time.sleep(0.001)
            try:
                # append new data to data
                data += self.sock.recv(1024).decode('utf-8')
                if '\n' not in data:
                    continue
                # split data into messages
                messages = data.split('\n')
                # put all messages except the last one into the queue
                for msg in messages[:-1]:
                    self.msg_queue.put(msg)
                # the last message may be incomplete, so it should be kept in data
                data = messages[-1]

            except ConnectionResetError:
                print('Connection reset by peer')
                print('Reconnecting...')
                self.connect()
            except ConnectionAbortedError:
                print('Connection aborted by peer')
                print('Reconnecting...')
                self.connect()
            except OSError:
                print('OSError')
                print('Reconnecting...')
                self.connect()
            except Exception as e:
                print('Exception')
                print(traceback.format_exc())
                print('Reconnecting...')
                self.connect()
    
    def msg_available(self):
        return not self.msg_queue.empty()
    
    def get_msg(self):
        return self.msg_queue.get()

    def parse_tcp_message(self, msg):
        ''' Parse a message received from the TCP server. '''
        try:
            # parse the message as JSON
            msg_json = json.loads(msg)
        except Exception as e:
            print('Failed to parse json message. Message:')
            print(msg)
            return
        print('Received JSON:')
        pprint.pprint(msg_json)

        # check if the message is a status update
        if 'status_update' in msg_json:
            status_update = msg_json['status_update']
            # check if the status update is about PYNQ restart
            if 'pynq_restarted' in status_update:
                pynq_restarted = status_update['pynq_restarted']
                if pynq_restarted:
                    # ask for update of status
                    print('PYNQ restarted, asking for update of status')
                    self.send_update_status()
                    return

        if 'add_points' in msg_json:
            add_points = msg_json['add_points']
            self.handle_add_points(add_points)
        
        # check if the message is a RPC return message
        if 'RPC_return' in msg_json:
            rpc_return = msg_json['RPC_return']
            self.handle_rpc_return(rpc_return)
    
    ####################################################################
    #
    #             Handling new line plot values
    #
    ####################################################################
    def handle_add_points(self, add_points_json):
        ''' 
        "add_points" is a message that lets the server to add new datapoint to line plot/plots  

        In previous demo TCP client, line plots names were not hardcoded, any new line plot
        could be added dynamically, if it didn't exist, it was created. 

        add_points_json has a structure like this:
        { 
            "add_points" : {
                "plot_name_1": [0.1, 0.2, 0.1],
                "plot_name_2": [0.7, 0.6, 0.9],
                "plot_name_3": [50,   68,  20]
            }
        }
        '''
        print()
        for plot_name in add_points_json:
            plot_values = add_points_json[plot_name]
            # print(f'New points for plot "{plot_name}" were received: {plot_values}')
            # TODO: update GUI with new points
        print()
        
    ####################################################################
    #
    #             Sending RPCs and handling their returns
    #
    ####################################################################
    def handle_rpc_return(self, rpc_return_json):
        ''' RPC return messages are JSON objects with a common structure like this:
        { 
            "RPC_return" : {
                "function_name": "rpc_load_program",
                "function_args": ["ecg"],
                "return_status": "success",
                "return_value": "OK: loaded ecg.bin program."
            }
        }
        
        return_value is not always a string, it can be a dictionary or a list too.
        See handling of specific RPC return messages below.
        '''
        
        rpc_return_handlers = {
            'rpc_update_status': self.handle_return_update_status,
            'rpc_list_programs': self.handle_return_list_programs,
            'rpc_load_program': self.handle_return_load_program,
            'rpc_run': self.handle_return_run,
            'rpc_halt': self.handle_return_halt,
            'rpc_enable_training': self.handle_return_enable_training,
            'rpc_disable_training': self.handle_return_disable_training,
            'rpc_enable_testing': self.handle_return_enable_testing,
            'rpc_disable_testing': self.handle_return_disable_testing,
            # 'rpc_set_atf_watchpoint': self.handle_return_set_atf_watchpoint,
            # 'rpc_atf_watchpoint_set_active': self.handle_return_atf_watchpoint_set_active,
            # 'rpc_list_objdumps': self.handle_return_list_objdumps,
            # 'rpc_get_objdump': self.handle_return_get_objdump,
        } 

        if 'function_name' not in rpc_return_json:
            print('ERROR: Failed to parse RPC_return, no function_name')
            return
        function_name = rpc_return_json['function_name']
        if function_name not in rpc_return_handlers:
            print(f'ERROR: Failed to parse RPC_return, unknown function_name')
            return
        
        # handle the RPC return message
        handler_function = rpc_return_handlers[function_name]
        return_status = rpc_return_json['return_status']
        if return_status != 'success':
            print(f'ERROR: RPC call failed, return_status: {return_status}')
            return
        if 'return_value' not in rpc_return_json:
            print('ERROR: Failed to parse RPC_return, no return_value')
            return
        print(f'Handling RPC return for function {function_name}')
        handler_function(rpc_return_json)


    #-------------------------------------------------------------------
    #                      rpc_update_status
    #-------------------------------------------------------------------
    def send_update_status(self):
        ''' Ask the server to send an update of status. '''
        self.send('{"RPC": {"function_name": "rpc_update_status"}}')

    def handle_return_update_status(self, rpc_return_json):
        # check if the RPC return message is about rpc_update_status
        if 'function_name' in rpc_return_json and rpc_return_json['function_name'] == 'rpc_update_status':
            # parse the return value
            return_value = rpc_return_json['return_value']
            # check if the return value contains loaded_program
            if 'loaded_program' in return_value:
                loaded_program = return_value['loaded_program']
                # TODO: update GUI with loaded program
            # check if the return value contains dataset_size
            if 'dataset_size' in return_value:
                dataset_size = return_value['dataset_size']
                # TODO: update GUI with dataset size
            # check if the return value contains mode
            if 'mode' in return_value:
                mode = return_value['mode']
                is_training_enabled = mode & 1
                is_testing_enabled = mode & 0b10
                # TODO: update GUI with training/testing modes statuses (both are independent)
            # check if the return value contains is_halted
            if 'is_halted' in return_value:
                is_halted = return_value['is_halted']
                # TODO: update GUI with halted status 
                # (initially a program may be not running and not be halted)
                # (that's because the program was not loaded and wasn't ran for the first time yet)
            # check if the return value contains is_running
            if 'is_running' in return_value:
                is_running = return_value['is_running']
                # TODO: update GUI with running status

            # # check if the return value contains atf_watchpoints
            # if 'atf_watchpoints' in return_value:
            #     atf_watchpoints = return_value['atf_watchpoints']
            #     # please ignore this


    #-------------------------------------------------------------------
    #                      rpc_list_programs
    #-------------------------------------------------------------------
    def send_list_programs(self):
        ''' Ask the server for available programs. '''
        self.send('{"RPC": {"function_name": "rpc_list_programs"}}')

    def handle_return_list_programs(self, rpc_return_json):
        ''' return_value is a dictionary with program categories as keys and lists of programs as values.
        Example: {'ECG': ['ecg', 'ecg_info_leak', 'ecg_zigzag'], 'HW': ['echo', 'hello_world']} '''
        program_names = []
        return_value = rpc_return_json['return_value']
        for category in return_value:
            program_names += return_value[category]
        print('Available programs: ', program_names)
        # TODO: update GUI with program names (no need to update categories)
    
    #-------------------------------------------------------------------
    #                      rpc_load_program
    #-------------------------------------------------------------------
    def send_load_program(self, program_name):
        ''' Ask the server to load a program. '''
        self.send('{"RPC": {"function_name": "rpc_load_program", "function_args": ["' + program_name + '"]} }')
    
    def handle_return_load_program(self, rpc_return_json):
        ''' return_value is a string with the name of the loaded program. '''
        if 'function_args' not in rpc_return_json:
            print('ERROR: Failed to parse RPC_return, no function_args')
            return
        function_args = rpc_return_json['function_args']
        print(f'Loaded program: {function_args[0]}')
        # TODO: update GUI with loaded program name


    #-------------------------------------------------------------------
    #                      rpc_run
    #-------------------------------------------------------------------
    def send_run(self):
        ''' Ask the server to run a program. '''
        self.send('{"RPC": {"function_name": "rpc_run"}}')

    def handle_return_run(self, rpc_return_json):
        ''' return_value is a string with the name of the program that was ran. '''
        return_value = rpc_return_json['return_value']
        print(f'Running program: {return_value}')
    

    #-------------------------------------------------------------------
    #                      rpc_halt
    #-------------------------------------------------------------------
    def send_halt(self):
        ''' Ask the server to halt a program. '''
        self.send('{"RPC": {"function_name": "rpc_halt"}}')
    
    def handle_return_halt(self, rpc_return_json):
        ''' return_value is a string with the name of the program that was halted. '''
        return_value = rpc_return_json['return_value']
        print(f'Halted program: {return_value}')


    #-------------------------------------------------------------------
    #                      rpc_enable_training
    #-------------------------------------------------------------------
    def send_enable_training(self):
        ''' Ask the server to enable training mode. '''
        self.send('{"RPC": {"function_name": "rpc_enable_training"}}')

    def handle_return_enable_training(self, rpc_return_json):
        ''' return_value is an empty string. '''
        print(f'Enabled training mode')


    #-------------------------------------------------------------------
    #                      rpc_disable_training
    #-------------------------------------------------------------------
    def send_disable_training(self):
        ''' Ask the server to disable training mode. '''
        self.send('{"RPC": {"function_name": "rpc_disable_training"}}')
    
    def handle_return_disable_training(self, rpc_return_json):
        ''' return_value is an empty string. '''
        print(f'Disabled training mode')

    
    #-------------------------------------------------------------------
    #                      rpc_enable_detection_threshold_calibration
    #-------------------------------------------------------------------
    def send_enable_detection_threshold_calibration(self):
        ''' Ask the server to enable detection threshold calibration. '''
        self.send('{"RPC": {"function_name": "rpc_enable_detection_threshold_calibration"}}')
    
    def handle_return_enable_detection_threshold_calibration(self, rpc_return_json):
        ''' return_value is an empty string. '''
        print(f'Enabled detection threshold calibration')

    
    #-------------------------------------------------------------------
    #                      rpc_disable_detection_threshold_calibration
    #-------------------------------------------------------------------
    def send_disable_detection_threshold_calibration(self):
        ''' Ask the server to disable detection threshold calibration. '''
        self.send('{"RPC": {"function_name": "rpc_disable_detection_threshold_calibration"}}')

    def handle_return_disable_detection_threshold_calibration(self, rpc_return_json):
        ''' return_value is an empty string. '''
        print(f'Disabled detection threshold calibration')
    
    #-------------------------------------------------------------------
    #                      rpc_enable_testing
    #-------------------------------------------------------------------
    def send_enable_testing(self):
        ''' Ask the server to enable testing mode. '''
        self.send('{"RPC": {"function_name": "rpc_enable_testing"}}')
    
    def handle_return_enable_testing(self, rpc_return_json):
        ''' return_value is an empty string. '''
        print(f'Enabled testing mode')
    

    #-------------------------------------------------------------------
    #                      rpc_disable_testing
    #-------------------------------------------------------------------
    def send_disable_testing(self):
        ''' Ask the server to disable testing mode. '''
        self.send('{"RPC": {"function_name": "rpc_disable_testing"}}')
    
    def handle_return_disable_testing(self, rpc_return_json):
        ''' return_value is an empty string. '''
        print(f'Disabled testing mode')

    
    # #-------------------------------------------------------------------
    # #                      rpc_set_atf_watchpoint
    # #-------------------------------------------------------------------
    # def send_set_atf_watchpoint(self, watchpoint_id, active, attributes):
    #     ''' Ask the server to set an atf watchpoint. '''
    #     self.send('{"RPC": {"function_name": "rpc_set_atf_watchpoint", "function_args": [watchpoint_id, active, attributes]}}')

    # def send_atf_watchpoint_set_active(self, watchpoint_id, active):
    #     ''' Ask the server to set an atf watchpoint active/inactive. '''
    #     self.send('{"RPC": {"function_name": "rpc_atf_watchpoint_set_active", "function_args": [watchpoint_id, active]}}')
    
    # #-------------------------------------------------------------------
    # #                      rpc_list_objdumps
    # #-------------------------------------------------------------------
    # def send_list_objdumps(self):
    #     ''' Ask the server for available objdumps. '''
    #     self.send('{"RPC": {"function_name": "rpc_list_objdumps"}}')

    # def handle_return_list_objdumps(self, rpc_return_json):
    #     ''' return_value is a list of objdump names. '''
    #     return_value = rpc_return_json['return_value']
    #     print(f'Available objdumps: {return_value}')

    # #-------------------------------------------------------------------
    # #                      rpc_get_objdump
    # #-------------------------------------------------------------------
    # def send_get_objdump(self, objdump_name):
    #     ''' Ask the server to send an objdump. '''
    #     self.send('{"RPC": {"function_name": "rpc_get_objdump", "function_args": [objdump_name]}}')

    # def handle_return_get_objdump(self, rpc_return_json):
    #     ''' return_value is a string with the objdump content. '''
    #     return_value = rpc_return_json['return_value']
    #     print(f'Objdump content: {return_value}')





def interface_worker(): 
    time.sleep(1)
    default_delay = 1
    while True:
        rpcs = [
            {'name': 'rpc_update_status', 'args': [], 'func': tcp_client.send_update_status},
            {'name': 'rpc_list_programs', 'args': [], 'func': tcp_client.send_list_programs},
            {'name': 'rpc_load_program (forensic)', 'args': ['forensic'], 'func': tcp_client.send_load_program, 'delay': 4},
            {'name': 'rpc_load_program (a2time)', 'args': ['a2time'], 'func': tcp_client.send_load_program, 'delay': 4},
            {'name': 'rpc_load_program (echo)', 'args': ['echo'], 'func': tcp_client.send_load_program, 'delay': 4},
            {'name': 'rpc_run', 'args': [], 'func': tcp_client.send_run},
            {'name': 'rpc_halt', 'args': [], 'func': tcp_client.send_halt},
            {'name': 'rpc_enable_training', 'args': [], 'func': tcp_client.send_enable_training},
            {'name': 'rpc_disable_training', 'args': [], 'func': tcp_client.send_disable_training},
            {'name': 'rpc_enable_detection_threshold_calibration', 'args': [], 'func': tcp_client.send_enable_detection_threshold_calibration},
            {'name': 'rpc_disable_detection_threshold_calibration', 'args': [], 'func': tcp_client.send_disable_detection_threshold_calibration},
            {'name': 'rpc_enable_testing', 'args': [], 'func': tcp_client.send_enable_testing},
            {'name': 'rpc_disable_testing', 'args': [], 'func': tcp_client.send_disable_testing}
        ]
        print()
        print('Available rpc actions:')
        for i, rpc in enumerate(rpcs):
            print(f'{i}: {rpc["name"]}')
        print()
        inp = input('Choose RPC action:\n> ')
        if not input:
            print('\n')
            continue
        try:
            chosen_rpc_index = int(inp)
        except ValueError:
            print('\nERROR: Invalid input\n')
            continue
        chosen_rpc = rpcs[chosen_rpc_index]
        print('Sending RPC...')
        chosen_rpc['func'](*chosen_rpc['args'])
        time.sleep(chosen_rpc.get('delay', default_delay))


if __name__ == '__main__':
    tcp_client = TCP_Client(args.ip, args.port)

    print('TCP Client (GUI application) just started, so it will send rpc_update_status to the server to get the current status of the PYNQ system.')
    tcp_client.send_update_status()

    interface_thread = threading.Thread(target=interface_worker, daemon=True)
    interface_thread.start()

    while True:
        if not tcp_client.msg_available():
            time.sleep(0.001)
            continue
        msg = tcp_client.get_msg()
        tcp_client.parse_tcp_message(msg)


        



    




'''
void parse_tcp_message(String line) {
    cJSON *root = cJSON_Parse(line.c_str());
    if (root == NULL) {
        Serial.println("Failed to parse json. Line:");
        Serial.println(line);
        return;
    }
    // String *msg_json = new String( "{ \"local_status_update\":{\"tcp_connection_status\" : \"" + msg + "\"}}");
    // parse the msg_json
    if (cJSON_HasObjectItem(root, "local_status_update")) {
        cJSON *local_status_update_obj = cJSON_GetObjectItem(root, "local_status_update");
        if (cJSON_HasObjectItem(local_status_update_obj, "tcp_connection_status")) {
            cJSON *tcp_connection_status_obj = cJSON_GetObjectItem(local_status_update_obj, "tcp_connection_status");
            String tcp_connection_status = tcp_connection_status_obj->valuestring;
            gui->get_state_main()->set_tcp_conn_status(tcp_connection_status);
        }
    }

    // // Parse string with the following json:
    // // '{
    // //    programs: {
    // //      "ECG": ["ecg_info_leak.bin", "ecg_baseline.bin"], 
    // //      "ANOTHER": ["another0.bin", "another1.bin"]
    // //    },
    // // }'
    // if (cJSON_HasObjectItem(root, "programs")) {
    //     cJSON *programs_obj = cJSON_GetObjectItem(root, "programs");
    //     cJSON *program_category_obj = programs_obj->child;
    //     while(program_category_obj) {
    //         Serial.println(program_category_obj->string);
    //         for (int i=0; i<cJSON_GetArraySize(program_category_obj); i++) {
    //             cJSON *program_name_obj = cJSON_GetArrayItem(program_category_obj, i);
    //             String program_name = program_name_obj->valuestring;
    //             Serial.print("Program: ");
    //             Serial.println(program_name);
    //         }
    //         program_category_obj = program_category_obj->next;
    //     }
    // }

    // // Parse string with the following json:
    // // { "status_update": "OK: Running program: ecg_info_leak.bin" }
    // if (cJSON_HasObjectItem(root, "status_update")) {
    //     cJSON *status_update_obj = cJSON_GetObjectItem(root, "status_update");
    //     // Print response
    //     Serial.print("Status update: ");
    //     Serial.println(status_update_obj->valuestring);
    // }

    // Parse string with the following json:
    // {
    //    add_points: {
    //      "ECG": [0.1, 0.2, 0.1], 
    //      "ANOTHER": [0.7, 0.6, 0.9]
    //    },
    // }

    // adding points to pynq plot
    if (cJSON_HasObjectItem(root, "add_points")) {
        cJSON *add_points_obj = cJSON_GetObjectItem(root, "add_points");
        cJSON *plot_name_obj = add_points_obj->child;

        GUI_Graph *pynq_graph = gui_main_state->get_pynq_graph();
        while(plot_name_obj) {
            // Serial.println('add_points for ' + plot_name_obj->string);

            for (int i=0; i<cJSON_GetArraySize(plot_name_obj); i++) {
                cJSON *plot_value = cJSON_GetArrayItem(plot_name_obj, i);
                // Do something with new plot value

                String plot_name = plot_name_obj->string;
                double value = plot_value->valuedouble;
                // LinePlot* line_plot = ecg_graph.get_plot(plot_name);
                LinePlot* line_plot = pynq_graph->get_plot(plot_name);
                if (!line_plot) {
                    Serial.printf("add_point was used but plot %s does not exist. Creating it now.\n", plot_name.c_str());
                    line_plot = pynq_graph->add_plot(plot_name, create_new_line_plot());
                }

                line_plot->add_point(value);

                // if (gui->get_current_state_id() == GUI_STATE_MAIN) {
                //     line_plot->draw(BLACK);
                //     line_plot->add_point(value);
                //     line_plot->draw();
                // } else {
                //     line_plot->add_point(value);
                // }
            }
            plot_name_obj = plot_name_obj->next;
        }

        if (gui->get_current_state_id() == GUI_STATE_MAIN) 
            pynq_graph->draw_plots();
    }

    // // copy for the risc-v plot (ecg)
    // if (cJSON_HasObjectItem(root, "add_points_risc_v")) {
    //     cJSON *add_points_obj = cJSON_GetObjectItem(root, "add_points_risc_v");
    //     cJSON *plot_name_obj = add_points_obj->child;
    //     while(plot_name_obj) {
    //         Serial.println(plot_name_obj->string);

    //         for (int i=0; i<cJSON_GetArraySize(plot_name_obj); i++) {
    //             cJSON *plot_value = cJSON_GetArrayItem(plot_name_obj, i);
    //             // Do something with new plot value

    //             String plot_name = plot_name_obj->string;
    //             double value = plot_value->valuedouble;
    //             // LinePlot* line_plot = ecg_graph.get_plot(plot_name);
    //             GUI_Graph *ecg_graph = gui_main_state->get_ecg_graph();
    //             LinePlot* line_plot = ecg_graph->get_plot(plot_name);
    //             if (!line_plot) {
    //                 Serial.printf("add_point was used but plot %s does not exist. Creating it now.\n", plot_name.c_str());
    //                 line_plot = ecg_graph->add_plot(plot_name, create_new_line_plot(GREEN));
    //             }

    //             if (gui->get_current_state_id() == GUI_STATE_MAIN) {
    //                 line_plot->draw(BLACK);
    //                 line_plot->add_point(value);
    //                 line_plot->draw();
    //             } else {
    //                 line_plot->add_point(value);
    //             }
    //         }
    //         plot_name_obj = plot_name_obj->next;
    //     }
    // }

    // // Parse string with the following json:
    // {
    //     "status_update" : {
    //         "program_finished": "ecg_baseline.bin",
    //         "pynq_restarted" : true
    //     }
    // }
    if (cJSON_HasObjectItem(root, "status_update")) {
        cJSON *status_update_obj = cJSON_GetObjectItem(root, "status_update");
        if (cJSON_HasObjectItem(status_update_obj, "program_finished")) {
            cJSON *program_finished_obj = cJSON_GetObjectItem(status_update_obj, "program_finished");
            String program = program_finished_obj->valuestring;
            Serial.print("Program finished: ");
            Serial.println(program);
            gui->get_state_main()->set_run_status("Finished");
        }

        if (cJSON_HasObjectItem(status_update_obj, "pynq_restarted")) {
            cJSON *pynq_restarted_obj = cJSON_GetObjectItem(status_update_obj, "pynq_restarted");
            bool pynq_restarted = pynq_restarted_obj->valueint;
            Serial.print("Pynq restarted: ");
            Serial.println(pynq_restarted);
            // gui->get_state_main()->set_run_status("Pynq restarted");
            gui->get_state_main()->reset();

            rpc_no_args("rpc_update_status");
        }

        if (cJSON_HasObjectItem(status_update_obj, "mode")) {
            cJSON *mode_obj = cJSON_GetObjectItem(status_update_obj, "mode");
            int mode = mode_obj->valueint;
            Serial.print("Mode: ");
            Serial.println(mode);
            update_mode(mode);
            // gui->get_state_main()->set_run_status("Pynq restarted");
        }

        if (cJSON_HasObjectItem(status_update_obj, "dataset_size")) {
            cJSON *dataset_size_obj = cJSON_GetObjectItem(status_update_obj, "dataset_size");
            int size = dataset_size_obj->valueint;
            // Serial.print("Dataset size: ");
            // Serial.println(size);
            gui->get_state_main()->set_dataset_size(size);
            
            // gui->get_state_main()->set_run_status("Pynq restarted");
        }

    }

// {
//     "RPC_return" : {
//         "function_name": "rpc_list_programs",
//         "return_value": {
//             "ECG" : ["ecg_baseline.bin", "ecg_info_leak.bin"],
//             "ANOTHER_CATEGORY" : ["another_program_baseline.bin", "another_program_anomalous_version.bin"]
//         }, 
//         "return_status": "success" // alternative would be "error"
//     }
// }
    // Parse string with the json above
    if (cJSON_HasObjectItem(root, "RPC_return")) {

        // gui->notify(line, 1500);

        if (!cJSON_HasObjectItem(root, "RPC_return")) { Serial.println("Failed to parse RPC_return"); return; } 
        cJSON *rpc_return_obj = cJSON_GetObjectItem(root, "RPC_return");
        if (!cJSON_HasObjectItem(rpc_return_obj, "function_name")) { Serial.println("Failed to parse function_name"); return; }
        if (!cJSON_HasObjectItem(rpc_return_obj, "return_value"))  { Serial.println("Failed to parse return_value");  return; }
        if (!cJSON_HasObjectItem(rpc_return_obj, "return_status")) { Serial.println("Failed to parse return_status"); return; }
        if (!cJSON_HasObjectItem(rpc_return_obj, "function_args")) { Serial.println("Failed to parse function_args"); return; }
        cJSON *function_name_obj = cJSON_GetObjectItem(rpc_return_obj, "function_name");
        cJSON *return_value_obj = cJSON_GetObjectItem(rpc_return_obj, "return_value");
        cJSON *return_status_obj = cJSON_GetObjectItem(rpc_return_obj, "return_status");
        cJSON *function_args_obj = cJSON_GetObjectItem(rpc_return_obj, "function_args");
        String function_name = function_name_obj->valuestring;
        String return_status = return_status_obj->valuestring;
        // Print response
        Serial.print("RPC_return, function_name: ");
        Serial.print(function_name);
        Serial.print(", status: ");
        Serial.print(return_status);
        Serial.println(" return_value:");

        if (!return_status.equals("success")) {
            Serial.println("RPC call failed");
            return;
        }

        if (function_name.equals("rpc_load_program")) {
            String loaded_program = cJSON_GetArrayItem(function_args_obj, 0)->valuestring;
            Serial.printf("rpc_load_program, loaded_program: %s\n", loaded_program.c_str());
            gui->get_state_main()->set_loaded_program(loaded_program);
        }

        if (function_name.equals("rpc_list_programs") || function_name.equals("rpc_list_objdumps")) {
            cJSON *program_category_obj = return_value_obj->child;
            while(program_category_obj) {
                String category = program_category_obj->string;
                std::vector<String> programs;
                Serial.println(category);
                for (int i=0; i<cJSON_GetArraySize(program_category_obj); i++) {
                    cJSON *program_name_obj = cJSON_GetArrayItem(program_category_obj, i);
                    String program_name = program_name_obj->valuestring;
                    Serial.print("Program: ");
                    Serial.println(program_name);
                    programs.push_back(program_name);

                    // make a button or something, maybe change gui state into program selection?
                }
                program_category_obj = program_category_obj->next;
                gui->get_state_select_option()->add_options(category, programs);
            }
        }

        if (function_name.equals("rpc_run")) {
            String return_value = return_value_obj->valuestring;
            gui->get_state_main()->set_run_status("Running");
        }
        if (function_name.equals("rpc_halt")) {
            String return_value = return_value_obj->valuestring;
            gui->get_state_main()->set_run_status("Halted");
        }

        if (function_name.equals("rpc_enable_training") || function_name.equals("rpc_disable_training") || function_name.equals("rpc_enable_testing") || function_name.equals("rpc_disable_testing")) {
            int mode = 0;
            if (function_name.equals("rpc_enable_training"))  mode = return_value_obj->valueint;
            if (function_name.equals("rpc_disable_training")) mode = return_value_obj->valueint;
            if (function_name.equals("rpc_enable_testing"))   mode = return_value_obj->valueint;
            if (function_name.equals("rpc_disable_testing"))  mode = return_value_obj->valueint;
            update_mode(mode);
        }

        if (function_name.equals("rpc_update_status")) {
            if (cJSON_HasObjectItem(return_value_obj, "loaded_program")) {
                cJSON *loaded_program_obj = cJSON_GetObjectItem(return_value_obj, "loaded_program");
                String loaded_program = loaded_program_obj->valuestring;
                gui->get_state_main()->set_loaded_program(loaded_program);
            }
            // 'dataset_size' : anomaly_detection.get_dataset_size(),
            // 'mode' : mode,
            // 'is_halted' : is_arbitrary_halt_active,
            // 'loaded_program' : loaded_program},
            // 'is_running' : is_running,
            if (cJSON_HasObjectItem(return_value_obj, "dataset_size")) {
                cJSON *dataset_size_obj = cJSON_GetObjectItem(return_value_obj, "dataset_size");
                int dataset_size = dataset_size_obj->valueint;
                // gui->get_state_main()->set_dataset_size(dataset_size);
            }
            if (cJSON_HasObjectItem(return_value_obj, "mode")) {
                cJSON *mode_obj = cJSON_GetObjectItem(return_value_obj, "mode");
                int mode = mode_obj->valueint;
                if (mode & 0b1) {
                    gui->get_state_main()->set_training_status("Training");
                } else {
                    gui->get_state_main()->set_training_status("-");
                }
                if (mode & 0b10) {
                    gui->get_state_main()->set_testing_status("Testing");
                } else {
                    gui->get_state_main()->set_testing_status("-");
                }
            }
            
            bool is_running = false;
            int is_halted = false;
            if (cJSON_HasObjectItem(return_value_obj, "is_running")) {
                cJSON *is_running_obj = cJSON_GetObjectItem(return_value_obj, "is_running");
                is_running = is_running_obj->valueint;
            }
            if (cJSON_HasObjectItem(return_value_obj, "is_halted")) {
                cJSON *is_halted_obj = cJSON_GetObjectItem(return_value_obj, "is_halted");
                bool is_halted = is_halted_obj->valueint;
            }
            if (!is_running && !is_halted) {
                gui->get_state_main()->set_run_status("-");
            } else if (is_running) {
                gui->get_state_main()->set_run_status("Running");
            } else {
                gui->get_state_main()->set_run_status("Halted");
            }

// {"atf_watchpoints": {"-1": {"active": false, "attributes": {}}, "0": {"active": true, "attributes": {"PC": 2147485676}}, "1": {"active": false, "attributes": {}}, "2": {"active": false, "attributes": {}}}
            if (cJSON_HasObjectItem(return_value_obj, "atf_watchpoints")) {
                // clear old watchpoints
                gui->get_state_main()->clear_atf_watchpoints();
                cJSON *atf_watchpoints_obj = cJSON_GetObjectItem(return_value_obj, "atf_watchpoints");
                for (int i=0; i<cJSON_GetArraySize(atf_watchpoints_obj); i++) {
                    cJSON *watchpoint_obj = cJSON_GetArrayItem(atf_watchpoints_obj, i);
                    // Do something with new plot value

                    int watchpoint_id = atoi(watchpoint_obj->string);
                    Serial.print("Watchpoint id: ");
                    Serial.println(watchpoint_id);

                    Watchpoint *watchpoint = gui_main_state->add_atf_watchpoint();

                    cJSON *active_obj = cJSON_GetObjectItem(watchpoint_obj, "active");
                    bool active = active_obj->valueint;
                    Serial.print("Active: ");
                    Serial.println(active);

                    cJSON *attributes_obj = cJSON_GetObjectItem(watchpoint_obj, "attributes");
                    if (attributes_obj) {
                        for (int j=0; j<cJSON_GetArraySize(attributes_obj); j++) {
                            cJSON *attribute_obj = cJSON_GetArrayItem(attributes_obj, j);
                            // Do something with new plot value

                            String attribute_name = attribute_obj->string;
                            Serial.print("Attribute name: ");
                            Serial.println(attribute_name);

                            // cJSON does not support 64-bit values so strings are used instead 
                            // Serial.printf("Converting %s to 64-bit value\n", attribute_obj->valuestring);
                            long long attribute_value = strtoll(attribute_obj->valuestring, NULL, 16);
                            Serial.print("Attribute value: ");
                            Serial.println(attribute_value);

                            watchpoint->set_attribute(attribute_name, attribute_value);
                        }
                    }
                    watchpoint->set_active(active);
                }
            }
        }

        if (function_name.equals("rpc_reset_dataset")) {
            gui->get_state_main()->set_dataset_size(0);
        }

            // rpc_get_objdump_data
        if (function_name.equals("rpc_get_objdump_data")) {
            // if (cJSON_HasObjectItem(return_value_obj, "objdump_data")) {
                // cJSON *objdump_data_obj = cJSON_GetObjectItem(return_value_obj, "objdump_data");
                // String objdump_data = objdump_data_obj->valuestring;
                // set function/basic-block selection state and fill it with received data
                GUI_State_Explore_Objdump *state_explore_objdump = gui->get_state_explore_objdump();
                bool success = state_explore_objdump->set_objdump(return_value_obj);
                if (success) {
                    state_explore_objdump->push_function("_start");
                    state_explore_objdump->set_on_address_selected([](long long address) {
                        gui->get_state_edit_watchpoint()->set_attribute("PC", address);
                    });
                    gui->push_state(GUI_STATE_EXPLORE_OBJDUMP);
                } else {
                    Serial.println("Failed to set objdump data");
                }
            // }
        }
    }

//    if (line.startsWith("add_point")) {
//        char plot_name[20];
//        double value;
//        sscanf(line.c_str(), "add_point:%[^,],%lf", plot_name, &value);
//        LinePlot* line_plot = ecg_graph.get_plot(plot_name);
//        if (!line_plot) {
//            Serial.printf("add_point was used but plot %s does not exist. Creating it now.\n", plot_name);
//            line_plot = ecg_graph.add_plot(String(plot_name), create_new_line_plot());
//        }
//        line_plot->draw(BLACK);
//        line_plot->add_point(value);
//        line_plot->draw();
//    }

    cJSON_Delete(root);
}
'''