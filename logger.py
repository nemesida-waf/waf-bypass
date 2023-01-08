#!/usr/bin/env python3

import os
from colorama import Fore, Style


def read_all_log():
    
    log_dict = dict()
    directory = '/tmp/waf-bypass-log/'
    log_file = directory + 'all.log'
    
    if not os.path.exists(log_file):
        os.mknod(log_file)

    with open(log_file, 'r') as opened_log:
        logs = opened_log.readlines()

    try:
        for log in logs:
            key = log.split(" : ")[1]
            value = log.split(" : ")[0]
            log_dict[key] = value
    except Exception as e:
        print(f'{Fore.RED}Error: {e}. More details in file {log_file}{Style.RESET_ALL}')

    return log_dict


def write_log_stat():
    
    test = read_all_log()
    passed_log, failed_fn_log, failed_fp_log, error_log = [], [], [], []

    for key, value in test.items():
        if value == 'PASSED':
            passed_log.append(key)
        elif value == 'FAILED_FN':
            failed_fn_log.append(key)
        elif value == 'FAILED_FP':
            failed_fp_log.append(key)
        elif value == 'ERROR':
            error_log.append(key)
    
    return passed_log, failed_fn_log, failed_fp_log, error_log


def logger_stat():
    
    count_passed, count_failed_fn, count_failed_fp, count_error = 0, 0, 0, 0
    stat_req = dict()

    items_stat = read_all_log()
    for item in items_stat.values():
        
        if item == 'PASSED':
            count_passed += 1
        elif item == 'FAILED_FN':
            count_failed_fn += 1
        elif item == 'FAILED_FP':
            count_failed_fp += 1
        elif item == 'ERROR':
            count_error += 1

        stat_req['PASSED'] = count_passed
        stat_req['FAILED_FN'] = count_failed_fn
        stat_req['FAILED_FP'] = count_failed_fp
        stat_req['ERROR'] = count_error
    
    return stat_req
