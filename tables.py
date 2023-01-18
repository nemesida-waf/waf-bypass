#!/usr/bin/env python3

import tableprint as tp
from prettytable import PrettyTable


def get_stats(wb_result, status):    
    return [k for k, v in wb_result.items() if v == status]


def get_percent_str(i, a):
    return round((i/a)*100, 2) if a != 0 else 0.00


def table_get_result_details(fp, fn):

    def get_result_details(fx, status):
        
        if not fx:
            return ''

        if status == 'FP':
            col_1 = 10 * ' ' + 'FALSE POSITIVE PAYLOAD' + 10 * ' '
            col_2 = 210 * ' ' + 'ZONE' + 25*' '
            table = PrettyTable([col_1, col_2])
            table.align[col_1] = 'l'
        elif status == 'FN':
            col_1 = 10 * ' ' + 'FALSE NEGATIVE PAYLOAD' + 10 * ' '
            col_2 = 210 * ' ' + 'ZONE' + 25*' '
            table = PrettyTable([col_1, col_2])
            table.align[col_1] = 'l'
        else:
            col_1 = 10 * ' ' + 'PAYLOAD' + 10 * ' '
            col_2 = 210 * ' ' + 'ZONE' + 25*' '
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
    payloads_summary_list_fp = []
    payloads_summary_list_fn = []
    table_headers_fn = [7 * ' ' + 'PAYLOAD TYPE', 10 * ' ' + 'PASSED', 10 * ' ' + 'BYPASSED', 10 * ' ' + 'ERROR']
    table_headers_fp = [14 * ' ' + 'TOTAL', 10 * ' ' + 'PASSED', 10 * ' ' + 'FALSED', 10 * ' ' + 'ERROR']

    # get payloads type list
    payloads_type_list = list(set(['/'.join(k.split(':')[0].split('/')[:-1]) for k in wb_result.keys()]))
    
    # create result dictionary by payloads type
    for payloads_type in payloads_type_list:
        
        k = payloads_type.split('/payload/')[1].split('/')[0]  # leave payload type only
        k_type = 'FP' if k == 'FP' else 'FN'

        passed = len([k for k, v in wb_result.items() if k.startswith(payloads_type) and v == 'PASSED'])
        fx = len([k for k, v in wb_result.items() if k.startswith(payloads_type) and v == k_type])
        error = len([k for k, v in wb_result.items() if k.startswith(payloads_type) and v == 'ERROR'])        
        total = passed + error + fx

        payloads_summary_dict[k] = [total, passed, fx, error]

    # create table's body of the payloads
    for k in sorted(payloads_summary_dict.keys()):
        
        v = payloads_summary_dict[k]

        total = v[0]

        prcnt = get_percent_str(v[1], v[0])
        passed = str(v[1]) + ' (' + str(prcnt) + '%)' if prcnt > 0 else '0'

        prcnt = get_percent_str(v[2], v[0])
        fx = str(v[2]) + ' (' + str(prcnt) + '%)' if prcnt > 0 else '0'

        prcnt = get_percent_str(v[3], v[0])
        error = str(v[3]) + ' (' + str(prcnt) + '%)' if prcnt > 0 else '0'
        
        if k == 'FP':
            payloads_summary_list_fp.append([total, passed, fx, error])
        else:
            payloads_summary_list_fn.append([k, passed, fx, error])

    ##
    # Print FP/FN tables
    ##

    tp.banner('FALSE NEGATIVE TEST ', style='banner')
    tp.table(payloads_summary_list_fn, table_headers_fn)

    print('')
    tp.banner('FALSE POSITIVE TEST ', style='banner')
    tp.table(payloads_summary_list_fp, table_headers_fp)

    ##
    # Add all summary to result
    ##

    # init
    total = 0
    payloads_summary_list = []
    table_headers = ['TOTAL PAYLOADS', 5 * ' ' + 'PASSED', 5 * ' ' + 'NOT PASSED', 5 * ' ' + 'FALSE POSITIVE', 5 * ' ' + 'FALSE NEGATIVE', 5 * ' ' + 'ERROR']

    i = len([k for k, v in wb_result.items() if v == 'PASSED'])
    prcnt = get_percent_str(i, len(wb_result))
    passed = str(i) + ' (' + str(prcnt) + '%)' if prcnt > 0 else '0'
    total = total + i
    
    i = len([k for k, v in wb_result.items() if v == 'ERROR'])
    prcnt = get_percent_str(i, len(wb_result))
    error = str(i) + ' (' + str(prcnt) + '%)' if prcnt > 0 else '0'
    total = total + i

    i = len([k for k, v in wb_result.items() if v == 'FP'])
    prcnt = get_percent_str(i, len(wb_result))
    fp = str(i) + ' (' + str(prcnt) + '%)' if prcnt > 0 else '0'
    total = total + i

    i = len([k for k, v in wb_result.items() if v == 'FN'])
    prcnt = get_percent_str(i, len(wb_result))
    fn = str(i) + ' (' + str(prcnt) + '%)' if prcnt > 0 else '0'
    total = total + i

    i = len(wb_result) - len([k for k, v in wb_result.items() if v == 'PASSED'])
    prcnt = get_percent_str(i, len(wb_result))
    not_passed = str(i) + ' (' + str(prcnt) + '%)' if prcnt > 0 else '0'

    payloads_summary_list.append([
        len(wb_result.items()),
        passed,
        not_passed,
        fp,
        fn,
        error
    ])

    print('')
    tp.banner('TOTAL SUMMARY ', style='banner')
    tp.table(payloads_summary_list, table_headers)

    # summary validation
    if total != len(wb_result):
        print('ERROR: Summary processing is incorrect ({} != {})'.format(total, len(wb_result)))
