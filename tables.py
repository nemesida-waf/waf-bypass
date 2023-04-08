#!/usr/bin/env python3

import tableprint as tp


def get_stats(wb_result, status):    
    return [k for k, v in wb_result.items() if v == status]


def get_percent_str(i, a):
    return round((i/a)*100, 2) if a != 0 else 0.00


def table_get_result_details(fp, fn):

    def get_result_details(fx, status):
        
        if not fx:
            return ''

        # print header
        print('')
        print('')
        fx_type = '>> FALSE POSITIVE PAYLOADS' if status == 'FALSED' else '>> FALSE NEGATIVE PAYLOADS'
        print(fx_type)
        print('')

        # print payloads
        for k, v in fx.items():
            print('  {} in zone {}'.format(k, v))

    # FX details table
    get_result_details(fp, 'FALSED')
    get_result_details(fn, 'BYPASSED')


def table_get_result_summary(wb_result, pdl):

    # init
    payloads_summary_dict = {}
    payloads_summary_list_fp = []
    payloads_summary_list_fn = []
    table_headers_fn = [7 * ' ' + 'PAYLOAD TYPE', 10 * ' ' + 'PASSED', 10 * ' ' + 'BYPASSED', 10 * ' ' + 'FAILED']
    table_headers_fp = [7 * ' ' + 'PAYLOAD TYPE', 10 * ' ' + 'PASSED', 10 * ' ' + 'FALSED', 10 * ' ' + 'FAILED']

    # get payloads type list
    payloads_list = list(set([pdl.join(k.split(':', 1)[0].split(pdl)[:-1]) for k in wb_result.keys()]))
    
    # create result dictionary by payloads type
    for payloads in payloads_list:
        
        payloads_type = payloads.split(pdl + 'payload' + pdl)[1].split(pdl)[0]  # leave payload type only
        fx_type = 'FALSED' if payloads_type == 'FP' else 'BYPASSED'

        passed = len([k for k, v in wb_result.items() if k.startswith(payloads) and v == 'PASSED'])
        failed = len([k for k, v in wb_result.items() if k.startswith(payloads) and v == 'FAILED']) 
        fx = len([k for k, v in wb_result.items() if k.startswith(payloads) and v == fx_type])
        total = passed + failed + fx

        payloads_summary_dict[payloads_type] = [total, passed, fx, failed]

    # create table's body of the payloads
    for k in sorted(payloads_summary_dict.keys()):
        
        v = payloads_summary_dict[k]

        prcnt = get_percent_str(v[1], v[0])
        passed = str(v[1]) + ' (' + str(prcnt) + '%)' if prcnt > 0 else '0'

        prcnt = get_percent_str(v[2], v[0])
        fx = str(v[2]) + ' (' + str(prcnt) + '%)' if prcnt > 0 else '0'

        prcnt = get_percent_str(v[3], v[0])
        failed = str(v[3]) + ' (' + str(prcnt) + '%)' if prcnt > 0 else '0'
        
        if k == 'FP':
            payloads_summary_list_fp.append([k, passed, fx, failed])
        else:
            payloads_summary_list_fn.append([k, passed, fx, failed])

    ##
    # Print FALSED/BYPASSED tables
    ##

    if payloads_summary_list_fn:
        print('')
        tp.banner('FALSE NEGATIVE TEST ', style='banner')
        tp.table(payloads_summary_list_fn, table_headers_fn)

    if payloads_summary_list_fp:
        print('')
        tp.banner('FALSE POSITIVE TEST ', style='banner')
        tp.table(payloads_summary_list_fp, table_headers_fp)

    ##
    # Add all summary to result
    ##

    # init
    total = 0
    payloads_summary_list = []
    table_headers = ['TOTAL PAYLOADS', 'PASSED (OK)', 'FALSED (FP)', 'BYPASSED (FN)', 'FAILED']

    i = len([k for k, v in wb_result.items() if v == 'PASSED'])
    prcnt = get_percent_str(i, len(wb_result))
    passed = str(i) + ' (' + str(prcnt) + '%)' if prcnt > 0 else '0'
    total = total + i
    
    i = len([k for k, v in wb_result.items() if v == 'FAILED'])
    prcnt = get_percent_str(i, len(wb_result))
    failed = str(i) + ' (' + str(prcnt) + '%)' if prcnt > 0 else '0'
    total = total + i

    i = len([k for k, v in wb_result.items() if v == 'FALSED'])
    prcnt = get_percent_str(i, len(wb_result))
    falsed = str(i) + ' (' + str(prcnt) + '%)' if prcnt > 0 else '0'
    total = total + i

    i = len([k for k, v in wb_result.items() if v == 'BYPASSED'])
    prcnt = get_percent_str(i, len(wb_result))
    bypassed = str(i) + ' (' + str(prcnt) + '%)' if prcnt > 0 else '0'
    total = total + i

    payloads_summary_list.append([
        len(wb_result.items()),
        passed,
        falsed,
        bypassed,
        failed
    ])

    print('')
    tp.banner('TOTAL SUMMARY ', style='banner')
    tp.table(payloads_summary_list, table_headers)

    # summary validation
    if total != len(wb_result):
        print('An error occurred while processing the result: {} != {}'.format(total, len(wb_result)))
