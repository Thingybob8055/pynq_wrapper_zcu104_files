
# HPCS_COUNT = 39 # how many HPCs there are
# HPC_WIDTH = 7
HPCS_SELECTED_COUNT = 44 # non-zero events that were selected to be propagated outside Flute
HPCS_USED_COUNT = 8      # number of events counted by HPC (only 8 to limit size, each is 32 bits)
HPC_WIDTH = 32
PC_WIDTH = 64
INSTR_WIDTH = 32
CLK_COUNTER_WIDTH = 64
FIFO_FULL_TICKS_COUNT_WIDTH = 64
GP_REGISTER_WIDTH = 64
FEATURE_EXTRACTOR_RESULT_WIDTH = 40

# performance_events_local[1] = events[3][0]; // Core__BRANCH
# performance_events_local[2] = events[4][0]; // Core__JAL
# performance_events_local[5] = events[7][0]; // Core__LOAD
# performance_events_local[6] = events[8][0]; // Core__STORE
# performance_events_local[14] = events[32][0]; // L1I__LD
# performance_events_local[18] = events[48][0]; // L1D__LD
# performance_events_local[23] = events[64][0]; // TGC__WRITE
# performance_events_local[25] = events[66][0]; // TGC__READ
perf_counters = [
    'Core__BRANCH',
    'Core__JAL',
    'Core__LOAD',
    'Core__STORE',
    'L1I__LD',
    'L1D__LD',
    'TGC__WRITE',
    'TGC__READ'
]

# perf_counters = [
#     'Core__TRAP',
#     'Core__BRANCH',
#     'Core__JAL',
#     'Core__JALR',
#     'Core__AUIPC',
#     'Core__LOAD',
#     'Core__STORE',
#     'Core__SERIAL_SHIFT',
#     'Core__LOAD_WAIT',
#     'Core__STORE_WAIT',
#     'Core__F_BUSY_NO_CONSUME',
#     'Core__1_BUSY_NO_CONSUME',
#     'Core__2_BUSY_NO_CONSUME',
#     'Core__INTERRUPT',
#     'L1I__LD',
#     'L1I__LD_MISS',
#     'L1I__LD_MISS_LAT',
#     'L1I__TLB',
#     'L1D__LD',
#     'L1D__LD_MISS',
#     'L1D__LD_MISS_LAT',
#     'L1D__ST',
#     'L1D__TLB',
#     'TGC__READ',
#     'TGC__READ_MISS',
#     'AXI4_Slave__AW_FLIT',
#     'AXI4_Slave__W_FLIT',
#     'AXI4_Slave__W_FLIT_FINAL',
#     'AXI4_Slave__B_FLIT',
#     'AXI4_Slave__AR_FLIT',
#     'AXI4_Slave__R_FLIT',
#     'AXI4_Slave__R_FLIT_FINAL',
#     'AXI4_Master__AW_FLIT',
#     'AXI4_Master__W_FLIT',
#     'AXI4_Master__W_FLIT_FINAL',
#     'AXI4_Master__B_FLIT',
#     'AXI4_Master__AR_FLIT',
#     'AXI4_Master__R_FLIT',
#     'AXI4_Master__R_FLIT_FINAL'
# ]


class Packet_Format:
    ''' This class determines how to parse DMA receive buffer '''

    data_pkt = {
        **{name:HPC_WIDTH for name in perf_counters},
        'HPC_overflow_map' : HPCS_USED_COUNT,
        'pc' : PC_WIDTH,
        'clk_counter' : CLK_COUNTER_WIDTH,
        'instr' : INSTR_WIDTH,
        'fifo_full_ticks_count' : FIFO_FULL_TICKS_COUNT_WIDTH,
        'A0' : GP_REGISTER_WIDTH,
        'A1' : GP_REGISTER_WIDTH,
        'A2' : GP_REGISTER_WIDTH,
        'A3' : GP_REGISTER_WIDTH,
        'feature_extractor_result' : FEATURE_EXTRACTOR_RESULT_WIDTH,
        'cumulative_xor_pc' : PC_WIDTH
    }
    
    # must match the atf_data_pkt_deterministic structure in "continuous_monitoring_system.sv" file
    atf_data_pkt_deterministic = {
        'pc' : PC_WIDTH,
        'instr' : INSTR_WIDTH,
        'HPC_event_map' : HPCS_USED_COUNT,
        'RA' : GP_REGISTER_WIDTH,
        'SP' : GP_REGISTER_WIDTH,
        'GP' : GP_REGISTER_WIDTH,
        'TP' : GP_REGISTER_WIDTH,
        'T0' : GP_REGISTER_WIDTH,
        'T1' : GP_REGISTER_WIDTH,
        'FP' : GP_REGISTER_WIDTH,
        #'S1' : GP_REGISTER_WIDTH,
        'A0' : GP_REGISTER_WIDTH,
        'A1' : GP_REGISTER_WIDTH,
        'A2' : GP_REGISTER_WIDTH,
        'A3' : GP_REGISTER_WIDTH,
        #'S2' : GP_REGISTER_WIDTH
        'clk_counter' : CLK_COUNTER_WIDTH,
        'fifo_full_ticks_count' : FIFO_FULL_TICKS_COUNT_WIDTH
    }

    @staticmethod
    def get_perf_counters_dict_from_metrics_dict(metrics_dict):
        ''' Returns a list of performance counters from dataframe metrics '''
        return {name:metrics_dict[name] for name in perf_counters}

    # metrics that will be used for anomaly detection aside of HPCs
    metrics_to_use_aside_hpcs = ['pc', 'clk_counter', 'A0', 'A1', 'A2', 'A3']
    @staticmethod 
    def get_vector_for_anomaly_detection_from_metrics_dict(metrics_dict):
        ''' Returns a list of items that are used for anomaly detection from dataframe metrics '''
        return list(__class__.get_dict_for_anomaly_detection_from_metrics_dict(metrics_dict).values())

    @staticmethod
    def get_dict_for_anomaly_detection_from_metrics_dict(metrics_dict):
        ''' Returns a list of items that are used for anomaly detection from dataframe metrics '''
        perf_counters_dict = Packet_Format.get_perf_counters_dict_from_metrics_dict(metrics_dict)
        metrics_to_use_dict = {m:metrics_dict[m] for m in __class__.metrics_to_use_aside_hpcs}
        return {**metrics_to_use_dict, **perf_counters_dict}
    
    @staticmethod
    def get_anomaly_detection_features_names():
        ''' Returns a list of items that are used for anomaly detection from dataframe metrics '''
        return __class__.metrics_to_use_aside_hpcs + perf_counters

    @staticmethod
    def get_anomaly_detection_features_indices(metrics_names):
        ''' Returns a list of indices that are used for given anomaly detection from dataframe metrics.
        Helpful for calculating similarity based on specific metrics. '''
        indices = []
        for m in __class__.get_anomaly_detection_features_names():
            if m in metrics_names:
                indices.append(metrics_names.index(m))
            else:
                print(f"WARNING: {m} not found in metrics_names ({metrics_names})")
        return indices


class DataFrame_Columns_Order:
    ''' This class determines dataset columns order.
    
    Members of this class are supplied as format list to "reorder_df_columns" which leaves
    the columns that were not mentioned in their original order (at the end). So not every 
    column must be specified, only those we want to put at the begining, and only those we 
    want to reorder.
    '''
    data_pkt_columns = ['pc', 
                        
                        'instr', 
                        'instr_names', 
                        'instr_strings',
                        
                        'feature_extractor_result',
                       
                        'clk_counter', 
                        'fifo_full_ticks_count', 
                        'clk_counter_halt_agnostic', 
                        
                        'total_clk_counter', 
                        'total_fifo_full_ticks_count', 
                        'total_clk_counter_halt_agnostic', 
                        
                        'A0', 
                        'A1', 
                        'A2', 
                        'A3', 

                        'HPC_overflow_map'
                        ]
    
    atf_data_pkt_deterministic_columns = ['pc', 
                                          
                                          'instr', 
                                          'instr_names', 
                                          'instr_strings', 
                                          
                                          'clk_counter', 
                                          'fifo_full_ticks_count', 
                                          'clk_counter_halt_agnostic', 

                                          'total_clk_counter', 
                                          'total_fifo_full_ticks_count', 
                                          'total_clk_counter_halt_agnostic',
                                          
                                          'HPC_event_map', 
                                          
                                          'RA', 
                                          'SP', 
                                          'GP', 
                                          'TP', 
                                          'T0', 
                                          'T1', 
                                          'FP', 
                                          #'S1', 
                                          'A0', 
                                          'A1', 
                                          'A2', 
                                          'A3'
                                          #'S2'
                                         ]

# def pop_n_bits_value(val, n):
#     ''' pop_n_bits_value(0xFFFF, 4) returns tuple like: (0xFFF, 0xF) '''
#     bits_value = val & ((1<<n)-1)
#     return val >> n, bits_value

# def parse_fifo_item(fifo_item, format_list):
#     ''' Parses a single fifo item (e.g. 1024 bits) numerical value. 
#         Single fifo item = {59bits padding, performance_counters805(7bits*115counters), instr32, clk_counter_delta64, pc64}
#         Padding is used because only power of 2s can be used as size in fifo generator block (or axi in general?)'''
#     metrics_dict = {}
#     for metric_name, bit_width in format_list:
#         fifo_item, metric_value = pop_n_bits_value(fifo_item, bit_width)
#         metrics_dict[metric_name] = metric_value
#     return metrics_dict

# def construct_example_fifo_item():
#     fifo_item = 0
#     for i in range(38):
#         fifo_item = (fifo_item << 7) + i
#     fifo_item = (fifo_item << 38) + 0x3ffffffff # overflow map
#     fifo_item = (fifo_item << 64) + 0xdeadbeef # pc
#     fifo_item = (fifo_item << 32) + 0x11111111 # instr
#     fifo_item = (fifo_item << 64) + 0x22222222 # clk_counter
#     fifo_item = (fifo_item << 64) + 0x33333333 # fifo_full_ticks_count
#     fifo_item = (fifo_item << 64) + 0x44444444 # A0
#     fifo_item = (fifo_item << 64) + 0x55555555 # A1
#     fifo_item = (fifo_item << 64) + 0x66666666 # A2
#     fifo_item = (fifo_item << 64) + 0x77777777 # A3
#     return fifo_item

# # for key, val in parse_fifo_item(construct_example_fifo_item(), PACKET_FORMAT.data_pkt_format).items():
# #   print(key, hex(val))

# import pandas as pd

# data = [
#     {'a' : 1, 'b' : 2},
#     {'a' : 2},
#     {'a' : 3}
# ]


# df = pd.DataFrame(data)
# df2 = pd.DataFrame(data)
# print(df.append(df2, ignore_index=True))


# # reorder dataframe columns

# def reorder_df_columns(df, columns_order):
#     ''' function to reorder specified columns, columns not mentioned
#     in columns_order will be appended to the end of the dataframe '''
#     columns = df.columns.tolist()
#     for column in columns_order:
#         columns.remove(column)
#     columns = columns_order + columns
#     return df[columns]

# df = reorder_df_columns(df, ['b'])

# print(df)


