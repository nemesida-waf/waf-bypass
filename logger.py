#!/usr/bin/env python3

from colorama import Fore, Style


def read_all_log(processing_result):   

    # init
    ret = {}
    
    try:
        for result in processing_result:
            k = result.split(" : ")[1]
            v = result.split(" : ")[0]
            ret[k] = v
    except Exception as e:
        print(f'{Fore.RED}An error occurred while processing result: {e}{Style.RESET_ALL}')

    return ret


def write_log_stat(processing_result, statuses):
    
    test = read_all_log(processing_result)
    passed, fn, fp, error = [], [], [], []

    for key, value in test.items():
        if value == statuses[1]:
            passed.append(key)
        elif value == statuses[2]:
            error.append(key)
        elif value == statuses[3]:
            fp.append(key)
        elif value == statuses[4]:
            fn.append(key)
    
    return passed, fn, fp, error


def logger_stat(processing_result, statuses):
    
    count_passed, count_fn, count_fp, count_error = 0, 0, 0, 0
    ret = dict()

    items_stat = read_all_log(processing_result)
    for item in items_stat.values():
        
        if item == statuses[1]:
            count_passed += 1
        elif item == statuses[2]:
            count_error += 1
        elif item == statuses[3]:
            count_fp += 1
        elif item == statuses[4]:
            count_fn += 1
        
        ret[statuses[1]] = count_passed
        ret[statuses[2]] = count_error
        ret[statuses[4]] = count_fn
        ret[statuses[3]] = count_fp

    return ret
