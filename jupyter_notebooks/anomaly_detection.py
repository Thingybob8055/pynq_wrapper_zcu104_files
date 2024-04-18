# TODO: consider adding metadata columns to the dataset (e.g. timestamp, program counter, watchpoint_id)

# TODO: introduce "subdatasets" dictionary where multiple datasets are stored.
#       Keys would be special column/columns (e.g. program counter) and values 
#       would be individual datasets associated with particular key (program counter value).
#       This would improve performance of detection because values obtained from different 
#       program areas would be compared only with vectors from the same area. 
#       It would be helpful when multiple watchpoints are used.
#       "Special columns" used as keys should be deterministic (e.g. clk counter probably wouldn't be the best choice)

import numpy as np
from threading import Lock
import datetime
from pathlib import Path
import os
import glob
import pickle
from copy import deepcopy

from packet_format import Packet_Format

class Anomaly_Detection:
    ''' Relative/mean difference based detection.  '''
    def __init__(self, datasets_dir="anomaly_detection_datasets"):
        # self.n_features = None
        self.datasets_dir = datasets_dir
        # special columns indices purpose is to split dataset into multiple subdatasets
        # each subdataset is associated with a particular value of the special column
        # (using this we can have separate dataset for each program counter value)
        self.n_special_columns = 0
        # self.n_features = None
        self.special_columns_indices = []
        self.dataset_lock = Lock()
        self.dataset = {'default': None}
        self.vectors_hashes = {'default':set()}
        self.similarity_threshold = 1.0
        self.has_unsaved_changes_ = False
        self.current_model_name = 'None'
        self.on_has_unsaved_changes = lambda state: None
        self.on_model_name_change = lambda name: None
        self.on_max_interval_change = lambda interval: None
        self.on_feature_enabled_change = lambda feature_name, state: None

        self.used_features = {f:True for f in Packet_Format.data_pkt.keys()}

        # max interval is a time interval between receiving two vectors 
        # during training. It can be used during testing/monitoring to 
        # recognize that the watchpoints are not matching frequently enough 
        # (possibly not at all). 
        self.max_interval = 0.0

        def get_sim(val1, val2):
            if val1 < val2:
                return val1 / val2
            if val1 == 0 and val2 == 0:
                return 1.0
            return val2 / val1
        # self.calculate_similarities = np.vectorize(lambda x, y: x/y if x < y else y/x)
        self.calculate_similarities = np.vectorize(get_sim)

    def get_used_features(self):
        return self.used_features
    
    def is_model_empty(self):
        return self.get_dataset_size() == 0

    def set_feature_enabled(self, feature_name, is_enabled):
        ''' Enabling/disabling features must be disabled by the UI when model is not empty. '''
        if not self.is_model_empty():
            error_msg = 'AnomalyDetection.set_feature_enabled: model is not empty (features cannot be changed)'
            return error_msg
        if feature_name not in self.used_features:
            error_msg = f'AnomalyDetection.set_feature_enabled: feature "{feature_name}" not found'
            return error_msg
        if self.used_features[feature_name] == is_enabled:
            error_msg = f'AnomalyDetection.set_feature_enabled: feature "{feature_name}" already has is_enabled equal to {is_enabled}'
            return error_msg
        self.used_features[feature_name] = is_enabled
        self.on_feature_enabled_change(feature_name, is_enabled)
        # self.set_has_unsaved_changes(True)
        return ''
    
    def set_special_columns_indices(self, special_columns_indices):
        self.special_columns_indices = special_columns_indices
        self.n_special_columns = len(special_columns_indices)

    def init_dataset(self, n_features, key='default'):
        self.dataset[key] = np.empty((0, n_features))
        self.vectors_hashes[key] = set()
        # self.n_features = n_features
        # self.n_features_columns = n_features - self.n_special_columns

    def reset_dataset(self):
        with self.dataset_lock:
            keys_list = list(self.dataset.keys())
            for key in keys_list:
                del self.dataset[key]
                del self.vectors_hashes[key]
            # del self.dataset
            # del self.vectors_hashes
            # self.n_features = None

            # self.dataset = None
            # self.vectors_hashes = set()

            # for key in keys_list:
            #     self.dataset[key] = None
            #     self.vectors_hashes[key] = set()

            self.set_max_interval(0.0)
        self.set_has_unsaved_changes(False)
        self.set_model_name('None')

        
    def get_key_from_vector(self, vector):
        if self.n_special_columns == 0:
            return 'default'
        return tuple(vector[i] for i in self.special_columns_indices)
    
    def hash_vector(self, features_values):
        ''' Result may be different after each run for the same values. 
        This needs to be remembered if we want to save the hashes and load them later. '''
        return hash(tuple(features_values))

    def update_dataset(self, features_values):
        key = self.get_key_from_vector(features_values)
        with self.dataset_lock:
            if self.dataset.get(key, None) is None:
                self.init_dataset(len(features_values), key=key)
        features_values = abs(np.array(features_values).astype(float))

        vector_hash = self.hash_vector(features_values)
        if not self.is_vector_hash_in_dataset(vector_hash, key=key):
            with self.dataset_lock:
                self.vectors_hashes[key].add(vector_hash)
                # print(self.dataset)
                # print(features_values)
                self.dataset[key] = np.vstack([self.dataset[key], features_values])
                self.set_has_unsaved_changes(True)

    def is_vector_hash_in_dataset(self, vector_hash, key='default'):
        with self.dataset_lock:
            return vector_hash in self.vectors_hashes.get(key, set())

    def get_max_cosine_similarity(self, features_values):
        ''' Returns the maximum cosine similarity between the dataset and 
        the given vector together with the most similar vector.  '''
        key = self.get_key_from_vector(features_values)
        with self.dataset_lock:
            if self.dataset.get(key, None) is None:
                return 0,None
                # self.init_dataset(len(features_values))

        vector_hash = self.hash_vector(features_values)
        if self.is_vector_hash_in_dataset(vector_hash, key=key): 
            return 1, features_values
        with self.dataset_lock:
            dot_product = np.dot(self.dataset[key], features_values) / (np.linalg.norm(self.dataset[key], axis=1) * np.linalg.norm(features_values))
            max_value = np.max(dot_product)
            index = np.argmax(dot_product)
            return max_value, self.dataset[key][index]

    # def get_min_euclidean_distance(self, features_values):
    #     ''' Returns the minimum euclidean distance between the dataset and 
    #     the given vector. If the dataset is empty, returns -1. '''
    #     key = self.get_key_from_vector(features_values)
    #     with self.dataset_lock:
    #         if self.dataset.get(key, None) is None:
    #             return 0, None
    #             # self.init_dataset(len(features_values))
    #     return np.min(np.linalg.norm(self.dataset[key] - features_values, axis=1))

    # def get_min_scaled_euclidean_distance(self, features_values):
    #     ''' Returns the minimum scaled euclidean distance between the dataset and 
    #     the given vector. If the dataset is empty, returns -1. '''
    #     key = self.get_key_from_vector(features_values)
    #     with self.dataset_lock:
    #         if self.dataset.get(key, None) is None:
    #             return 0, None
    #             # self.init_dataset(len(features_values))
    #     return np.min(np.linalg.norm(self.dataset[key] - features_values, axis=1) / np.linalg.norm(self.dataset[key], axis=1))

    def get_similarity(self, features_values):
        key = self.get_key_from_vector(features_values)
        with self.dataset_lock:
            if self.dataset.get(key, None) is None:
                return 0.0, None
                # self.init_dataset(len(features_values))
        features_values = abs(np.array(features_values).astype(float))
        
        vector_hash = self.hash_vector(features_values)
        if self.is_vector_hash_in_dataset(vector_hash, key=key): 
            return 1.0, features_values
        # print('dataset=', self.dataset)
        # print('features_values=', features_values)
        sims = self.calculate_similarities(self.dataset[key], features_values).mean(axis=1)
        max_sim = np.max(sims)
        index = np.argmax(sims)
        return float(max_sim), self.dataset[key][index]
        
    def get_vector_by_index(self, index):
        with self.dataset_lock:
            if self.dataset is None:
                return []
            return self.dataset[index]


    # def get_min_distance(self, features_values):
    #     if self.dataset.shape[0] == 0: return -1
    #     return np.min(np.linalg.norm(self.dataset - features_values, axis=1))

    # def add_random_value_to_dataset(self):
    #     self.dataset = np.vstack([self.dataset, np.random.rand(self.n_features)])
    
    def get_dataset_size(self):
        sum = 0
        with self.dataset_lock:
            for key in self.dataset:
                sub_dataset = self.dataset.get(key, [])
                if sub_dataset is not None:
                    sum += sub_dataset.shape[0]
        return sum
    
    # def get_dataset_max_value(self):
    #     return np.max(self.dataset)
    
    def is_vector_anomaly(self, features_values):
        # threshold = self.get_dataset_max_value() * threshold_factor
        # return self.get_min_distance(features_values) > threshold
        sim, index = self.get_max_cosine_similarity(features_values) 
        return sim < 0.8

    def get_subdataset_by_key(self, key):
        with self.dataset_lock:
            return self.dataset.get(key, None)

    def get_subdataset_for_vector(self, features_values):
        key = self.get_key_from_vector(features_values)
        with self.dataset_lock:
            return self.dataset.get(key, None) 

    def store_dataset(self, f_name=None):
        self.ensure_datasets_dir_exists()
        if f_name is None:
            # yyyy_mm_dd__hh_mm_ss
            f_name = datetime.datetime.now().strftime("%Y_%m_%d__%H_%M_%S") + '.npy'
        f_name = os.path.join(self.datasets_dir, f_name)
        if not f_name.endswith('.npy'):
            f_name += '.npy'
        if not os.path.exists(self.datasets_dir):
            os.makedirs(self.datasets_dir)
        not_to_store = ['dataset_lock', "calculate_similarities", "get_sim", "has_unsaved_changes_", "current_model_name"]
        with open(f_name, 'wb') as f:
            with self.dataset_lock:
                d = {deepcopy(k): deepcopy(v) for k, v in self.__dict__.items() if (k not in not_to_store and not callable(v))}
                pickle.dump(d, f)
                self.set_model_name(f_name)
                self.set_has_unsaved_changes(False)

    def load_dataset(self, f_name):
        self.ensure_datasets_dir_exists()
        f_name = os.path.join(self.datasets_dir, f_name)
        if not f_name.endswith('.npy'):
            f_name += '.npy'
        with open(f_name, 'rb') as f:
            with self.dataset_lock:
                self.__dict__.update(pickle.load(f))
                self.set_model_name(f_name)
                self.set_has_unsaved_changes(False)

    def list_datasets(self):
        ''' return list of strings with filenames only, not full paths'''
        self.ensure_datasets_dir_exists()
        return [os.path.basename(f) for f in glob.glob(os.path.join(self.datasets_dir, '*.npy'))]

    def ensure_datasets_dir_exists(self):
        if not os.path.exists(self.datasets_dir):
            os.makedirs(self.datasets_dir)

    def set_similarity_threshold(self, threshold):
        with self.dataset_lock:
            self.similarity_threshold = float(threshold)
            self.set_has_unsaved_changes(True)

    def get_similarity_threshold(self):
        with self.dataset_lock:
            return self.similarity_threshold

    def update_max_interval(self, interval):
        ''' updates only if higher than current '''
        with self.dataset_lock:
            if interval > self.max_interval:
                self.set_max_interval(interval)
                self.set_has_unsaved_changes(True)
    
    def get_max_interval(self):
        with self.dataset_lock:
            return self.max_interval

    # def get_lack_of_matches_threshold(self):
    #     with self.dataset_lock:
    #         return self.max_interval * 2

    def get_current_model_name(self):
        with self.dataset_lock:
            return self.current_model_name
    
    def set_has_unsaved_changes(self, value):
        if value != self.has_unsaved_changes_:
            self.on_has_unsaved_changes(value)
        self.has_unsaved_changes_ = value

    def set_model_name(self, name):
        name = os.path.basename(name)
        # remove extension but keep the same text even if it contains dots
        if '.' in name:
            name = '.'.join(name.split('.')[:-1])
        self.current_model_name = name
        self.on_model_name_change(name)
    
    def set_max_interval(self, interval):
        ''' sets even if lower than current (unlike the update function) '''
        self.max_interval = interval
        self.on_max_interval_change(interval)
    
    def has_unsaved_changes(self):
        with self.dataset_lock:
            return self.has_unsaved_changes_

    def set_on_has_unsaved_changes_callback(self, callback):

        if not callable(callback):
            print('AnomalyDetection.set_on_has_unsaved_changes: callback is not callable')
            return
        self.on_has_unsaved_changes = callback
    
    def set_on_model_current_name_callback(self, callback):
        if not callable(callback):
            print('AnomalyDetection.set_on_model_name_change_callback: callback is not callable')
            return
        self.on_model_name_change = callback
    
    def set_on_max_interval_change_callback(self, callback):
        if not callable(callback):
            print('AnomalyDetection.set_on_max_interval_change_callback: callback is not callable')
            return
        self.on_max_interval_change = callback
    
    def set_on_feature_enabled_change_callback(self, callback):
        if not callable(callback):
            print('AnomalyDetection.set_on_feature_enabled_change_callback: callback is not callable')
            return
        self.on_feature_enabled_change = callback


    
if __name__ == '__main__':
    anomaly_detection = Anomaly_Detection()
    get_dataset_size = anomaly_detection.get_dataset_size()
    # program counter will become a special column
    # this means that a separate dataset will be 
    # created for each distinct program counter value
    anomaly_detection.set_special_columns_indices([0])
    get_dataset_size = anomaly_detection.get_dataset_size()


    # RANDOM VALUES TESTING
    # n_samples = 1000
    # for i in range(n_samples):
    #     features_values = np.random.randint(0,100, 50)
    #     anomaly_detection.update_dataset(features_values)
    #     last_features_values = features_values
    
    # n_tests = 10
    # for i in range(n_tests):
    #     features_values = np.random.randint(0,100, 50)
    #     if i == n_tests - 1:
    #         features_values = last_features_values
    #         features_values[0] = 2000
    #     # print(f'Min distance: {anomaly_detection.get_min_distance(features_values)}')
    #     print(f'Max cosine similarity: {anomaly_detection.get_max_cosine_similarity(features_values)}')
    #     print(f'Is anomaly: {anomaly_detection.is_vector_anomaly(features_values)}')
    #     print()

    # training_vectors = [
    #     [1,2,3_000_000]
    # ]

    # testing_vectors = [
    #     [1,2,3_000_001],
    #     [2,2,3_000_000],
    #     [1,3,3_000_000]
    # ]

    training_vectors = [
        # vector of features (HPCs + GPRs) obtained at single point in time
        [0,10,30000] 
    ]

    testing_vectors = [
        # vectors of (HPCs + GPRs) obtained when watchpoints were hit
        [0,10,30000], # 1st hit
        [1,10,30000], # 2nd hit
        [0,10,0],     # 3rd hit
        [0,10,1000],  # 4th hit
        [0,10,5000],  # 5th hit
        [0,10,15000], # 6th hit
    ]

    anomaly_detection.load_dataset('test_dataset.npy')
    print(anomaly_detection.get_dataset_size())
    # print(anomaly_detection.dataset)
    # for vector in training_vectors:
    #     anomaly_detection.update_dataset(vector)

    for vector in testing_vectors:
        # print(f'Similarity: {anomaly_detection.get_similarity(vector)[0]}')
        # print(f'Max cosine similarity: {anomaly_detection.get_max_cosine_similarity(vector)[0]}')
        
        sim = anomaly_detection.get_similarity(vector)[0]
        cos_sim = anomaly_detection.get_max_cosine_similarity(vector)[0]
        print(f'{vector}  {cos_sim:.10f} | {sim:.2f}')

    print()

    # anomaly_detection.store_dataset('test_dataset.npy')

    # raise SystemExit


    anomaly_detection.reset_dataset()
    # anomalous_vector = [386837, 1846, 387124, 850, 1169981, 387124, 0, 736, 0, 2147571072, 1]
    # dataset = [
    #     [ 1672, 772, 1941, 1652, 11653, 1941, 0, 1451, 500, 2147742848, 18],
    #     [ 641027, 2, 641028, 0, 1923104, 641028, 0, 0, 0, 2147742848, 18],
    #     [ 641027, 2, 641028, 0, 1923095, 641028, 0, 0, 0, 2147742848, 18],
    #     [ 641027, 3, 641028, 0, 1923099, 641028, 0, 0, 300, 2147742848, 18],
    #     [ 385402, 354, 385659, 828, 1159645, 385659, 0, 751, 500, 2147742848, 18],
    #     [ 641027, 2, 641028, 0, 1923097, 641028, 0, 0, 0, 2147742848, 18],
    #     [ 641027, 2, 641028, 0, 1923097, 641028, 0, 0, 1, 2147742848, 18],
    #     [ 386747, 1784, 387013, 781, 1169333, 387013, 0, 677, 500, 2147571072, 1],
    #     [ 641027, 2, 641028, 0, 1923099, 641028, 0, 0, 0, 2147571072, 1],
    #     [ 641027, 3, 641028, 0, 1923099, 641028, 0, 0, 300, 2147571072, 1],
    #     [ 384872, 137, 385020, 318, 1156023, 385020, 0, 296, 500, 2147742848, 18],
    #     [ 385402, 354, 385659, 828, 1159559, 385659, 0, 736, 500, 2147742848, 18],
    #     [ 386749, 1785, 387015, 781, 1169320, 387015, 0, 677, 0, 2147571072, 1],
    #     [ 384872, 137, 385020, 318, 1156017, 385020, 0, 293, 500, 2147742848, 18],
    #     [ 385402, 354, 385659, 828, 1159557, 385659, 0, 739, 500, 2147742848, 18],
    #     [ 641027, 2, 641028, 0, 1923099, 641028, 0, 0, 1, 2147742848, 18],
    #     [ 386753, 1789, 387019, 781, 1169353, 387019, 0, 677, 0, 2147571072, 1],
    #     [ 641027, 2, 641028, 0, 1923095, 641028, 0, 0, 0, 2147571072, 1],
    #     [ 384872, 137, 385020, 318, 1156015, 385020, 0, 293, 500, 2147742848, 18]
    # ]

    # first value changed on purpose to match some rows 
    anomalous_vector = [385402, 1846, 387124, 850, 1169981, 387124, 0, 736, 0, 2147571072, 1]
    dataset = [
        [ 1672, 772, 1941, 1652, 11653, 1941, 0, 1451, 500, 2147742848, 18],
        [ 641027, 2, 641028, 0, 1923104, 641028, 0, 0, 0, 2147742848, 18],
        [ 641027, 2, 641028, 0, 1923095, 641028, 0, 0, 0, 2147742848, 18],
        [ 641027, 3, 641028, 0, 1923099, 641028, 0, 0, 300, 2147742848, 18],
        [ 385402, 354, 385659, 828, 1159645, 385659, 0, 751, 500, 2147742848, 18],
        [ 641027, 2, 641028, 0, 1923097, 641028, 0, 0, 0, 2147742848, 18],
        [ 641027, 2, 641028, 0, 1923097, 641028, 0, 0, 1, 2147742848, 18],
        [ 386747, 1784, 387013, 781, 1169333, 387013, 0, 677, 500, 2147571072, 1],
        [ 641027, 2, 641028, 0, 1923099, 641028, 0, 0, 0, 2147571072, 1],
        [ 641027, 3, 641028, 0, 1923099, 641028, 0, 0, 300, 2147571072, 1],
        [ 384872, 137, 385020, 318, 1156023, 385020, 0, 296, 500, 2147742848, 18],
        [ 385402, 354, 385659, 828, 1159559, 385659, 0, 736, 500, 2147742848, 18],
        [ 386749, 1785, 387015, 781, 1169320, 387015, 0, 677, 0, 2147571072, 1],
        [ 384872, 137, 385020, 318, 1156017, 385020, 0, 293, 500, 2147742848, 18],
        [ 385402, 354, 385659, 828, 1159557, 385659, 0, 739, 500, 2147742848, 18],
        [ 641027, 2, 641028, 0, 1923099, 641028, 0, 0, 1, 2147742848, 18],
        [ 386753, 1789, 387019, 781, 1169353, 387019, 0, 677, 0, 2147571072, 1],
        [ 641027, 2, 641028, 0, 1923095, 641028, 0, 0, 0, 2147571072, 1],
        [ 384872, 137, 385020, 318, 1156015, 385020, 0, 293, 500, 2147742848, 18]
    ]


    for i, vector in enumerate(dataset):
        # print(i, vector, len(vector))
        anomaly_detection.update_dataset(vector)

    sub_dataset = anomaly_detection.get_subdataset_for_vector(anomalous_vector)

    for vector in sub_dataset:
        sim = anomaly_detection.calculate_similarities([[vector]], anomalous_vector)[0].mean(axis=1).max()
        vector_str = ', '.join([f'{x:.0f}' for x in vector])
        print(f'{vector_str:<80} Similarity: {sim}')

    anomaly_detection.store_dataset()

    # print( get_similarity([[1,4,0]], [2,3,30000]) )




