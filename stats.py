#!/usr/bin/env python3

def processing_result(wb_result, status):

    ret = {}

    for item in get_stats(wb_result, status):
        k = item.split(':')[1]
        v = item.split(':')[0]
        ret[k] = v

    return ret


def get_details(wb_result, statuses):

    passed, fn, fp, error = [], [], [], []

    for status in statuses:
        result = processing_result(wb_result, status)
        for key, value in result.items():
            if value == statuses[1]:
                passed.append(key)
            elif value == statuses[2]:
                error.append(key)
            elif value == statuses[3]:
                fp.append(key)
            elif value == statuses[4]:
                fn.append(key)
    
    return passed, fn, fp, error


def get_stats(wb_result, status):    
    return [k for k, v in wb_result.items() if v == status]
