#!/usr/bin/env python3

import tableprint as tp
from prettytable import PrettyTable


def get_stats(wb_result, status):    
    return [k for k, v in wb_result.items() if v == status]


def get_percent_str(i, a):
    return str(round((i/a)*100, 2) if a != 0 else '0.00')


def table_get_result_details(fp, fn):

    def get_result_details(fx, status):
        
        if not fx:
            return ''

        if status == 'FP':
            col_1 = 10 * ' ' + 'FALSE POSITIVE PAYLOAD' + 10 * ' '
            col_2 = 25 * ' ' + 'ZONE' + 25 * ' '
            table = PrettyTable([col_1, col_2])
            table.align[col_1] = 'l'
        elif status == 'FN':
            col_1 = 10 * ' ' + 'FALSE NEGATIVE PAYLOAD' + 10 * ' '
            col_2 = 25 * ' ' + 'ZONE' + 25 * ' '
            table = PrettyTable([col_1, col_2])
            table.align[col_1] = 'l'
        else:
            col_1 = 10 * ' ' + 'PAYLOAD' + 10 * ' '
            col_2 = 25 * ' ' + 'ZONE' + 25 * ' '
            table = PrettyTable([col_1, col_2])
            table.align[col_1] = 'l'

        for k, v in fx.items():
            table.add_row([k, v])

        print(table)

    # FX details table
    print('')
    get_result_details(fp, 'FP')
    get_result_details(fn, 'FN')


def table_get_result_summary(wb_result):

    print('')

    # init
    payloads_summary_dict = {}
    payloads_summary_list = []
    table_headers = ['PAYLOAD TYPE', 'PASSED', 'NOT PASSED', 'FALSE POSITIVE', 'FALSE NEGATIVE', 'ERROR']

    # get payloads type list
    payloads_type_list = list(set(['/'.join(k.split(':')[0].split('/')[:-1]) for k in wb_result.keys()]))
    
    # create result dictionary by payloads type
    for payloads_type in payloads_type_list:
        passed = len([k for k, v in wb_result.items() if k.startswith(payloads_type) and v == 'PASSED'])
        error = len([k for k, v in wb_result.items() if k.startswith(payloads_type) and v == 'ERROR'])
        fp = len([k for k, v in wb_result.items() if k.startswith(payloads_type) and v == 'FP'])
        fn = len([k for k, v in wb_result.items() if k.startswith(payloads_type) and v == 'FN'])
        summ = passed + error + fp + fn
        k = payloads_type.split('/payload/')[1].split('/')[0]  # leave payload type only
        payloads_summary_dict[k] = [summ, passed, error, fp, fn]

    # create table's body of the payloads
    for k in sorted(payloads_summary_dict.keys()):
        
        v = payloads_summary_dict[k]
        
        passed = str(v[1]) + ' (' + get_percent_str(v[1], v[0]) + '%)'
        not_passed = str(v[0] - v[1]) + ' (' + get_percent_str(v[0] - v[1], v[0]) + '%)'
        error = str(v[2]) + ' (' + get_percent_str(v[2], v[0]) + '%)'
        fp = str(v[3]) + ' (' + get_percent_str(v[3], v[0]) + '%)'
        fn = str(v[4]) + ' (' + get_percent_str(v[4], v[0]) + '%)'
        
        payloads_summary_list.append([
            k,
            passed,
            not_passed,
            fp,
            fn,
            error
        ])

    tp.table(payloads_summary_list, table_headers)

    ##
    # add all summary to result
    ##

    # init
    summ = 0
    payloads_summary_list = []
    table_headers = ['TOTAL CHECKS', 'PASSED', 'NOT PASSED', 'FALSE POSITIVE', 'FALSE NEGATIVE', 'ERROR']

    i = len([k for k, v in wb_result.items() if v == 'PASSED'])
    passed = str(i) + ' (' + get_percent_str(i, len(wb_result)) + '%)'
    summ = summ + i
    
    i = len([k for k, v in wb_result.items() if v == 'ERROR'])
    error = str(i) + ' (' + get_percent_str(i, len(wb_result)) + '%)'
    summ = summ + i

    i = len([k for k, v in wb_result.items() if v == 'FP'])
    fp = str(i) + ' (' + get_percent_str(i, len(wb_result)) + '%)'
    summ = summ + i

    i = len([k for k, v in wb_result.items() if v == 'FN'])
    fn = str(i) + ' (' + get_percent_str(i, len(wb_result)) + '%)'
    summ = summ + i

    i = len(wb_result) - len([k for k, v in wb_result.items() if v == 'PASSED'])
    not_passed = str(i) + ' (' + get_percent_str(i, len(wb_result)) + '%)'

    payloads_summary_list.append([
        str(len(wb_result.items())) + ' (100%)',
        passed,
        not_passed,
        fp,
        fn,
        error
    ])

    tp.table(payloads_summary_list, table_headers)

    # summary validation
    if summ != len(wb_result):
        print('ERROR: Summary processing is incorrect ({} != {})'.format(summ, len(wb_result)))
