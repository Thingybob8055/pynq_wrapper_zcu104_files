
import os
import pickle
from copy import deepcopy
from threading import Lock
import pprint

lock = Lock()
lock_type = type(lock)

class Operational_Config:
    def __init__(self, f_name='config.pickle'):
        self.disable_saving = True
        self.f_name = f_name
        self.periodic_send_interval_seconds = 0.8
        self.items_collected_processing_limit = 500
        # max_interval * multiplier = threshold after which "lack of matches" anomaly will be sent to GUI
        self.lack_of_matches_threshold_multiplier_of_max_interval = 1.5
        self.raw_data_send_enable = False
        self.disable_saving = False

    def save(self):
        print(f'Saving config: ', self.__dict__)
        not_to_store = ['disable_saving', 'f_name']
        try:
            with open(self.f_name, 'wb') as f:
                d = {deepcopy(k): deepcopy(v) for k, v in self.__dict__.items() if (k not in not_to_store and not callable(v) and not isinstance(v, lock_type))}
                pickle.dump(d, f)
        except Exception as e:
            print(f'Error while saving operational config: {e}')

    def load(self):
        if not os.path.isfile(self.f_name):
            print(f"File {self.f_name} does not exist.")
            return
        try:
            with open(self.f_name, 'rb') as f:
                self.__dict__.update(pickle.load(f))
        except Exception as e:
            print(f'Error while loading operational config: {e}')
            return False
        return True
    
    def get_config(self):
        not_to_store = ['disable_saving', 'f_name']
        return {deepcopy(k): deepcopy(v) for k, v in self.__dict__.items() if (k not in not_to_store and not callable(v) and not isinstance(v, lock_type))}
    
    def update_attributes(self, attributes):
        ''' Update attributes from a dictionary. '''
        errors_str = ''
        # if attribute not found in the object, it is ignored and added to the errors_str
        updated_at_least_one = False
        self.disable_saving = True
        for k, v in attributes.items():
            if hasattr(self, k):
                setattr(self, k, v)
                updated_at_least_one = True
            else:
                errors_str += f'{__class__.__name__}.update_attributes: Attribute {k} not found in the object.\n'
        self.disable_saving = False
        if updated_at_least_one:
            self.save()
        return errors_str

    # on every change of the config, save it to the file
    def __setattr__(self, name, value):
        with lock:
            super().__setattr__(name, value)
        if name == 'disable_saving':
            return
        if not self.disable_saving:
            self.save()
    
    def __getattribute__(self, name):
        with lock:
            return super().__getattribute__(name)

    def get_periodic_send_interval_seconds(self):
        return self.periodic_send_interval_seconds
    
    def set_periodic_send_interval_seconds(self, value):
        self.periodic_send_interval_seconds = value
    
    def get_items_collected_processing_limit(self):
        return self.items_collected_processing_limit
    
    def set_items_collected_processing_limit(self, value):
        self.items_collected_processing_limit = value

    def get_lack_of_matches_threshold_multiplier_of_max_interval(self):
        return self.lack_of_matches_threshold_multiplier_of_max_interval
    
    def set_lack_of_matches_threshold_multiplier_of_max_interval(self, value):
        self.lack_of_matches_threshold_multiplier_of_max_interval = value

    def is_raw_data_send_enabled(self):
        return self.raw_data_send_enable
    
    def enable_raw_data_send(self):
        self.raw_data_send_enable = True
    
    def disable_raw_data_send(self):
        self.raw_data_send_enable = False

    def __str__(self):
        return f'{__class__.__name__}({pprint.pformat(self.__dict__)})'
    