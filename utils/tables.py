#!/usr/bin/env python3

import tableprint as tp


def get_stats(result, status):
    return [k for k, v in result.items() if v == status]


def get_percent_str(i, a):
    return round((i/a)*100, 2) if a != 0 else 0.00


def table_get_result_details(fp, fn):

    def get_result_details(fx, status):

        if not fx:
            return ''

        # show header
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


def table_get_result_replay(wb_result):

    def get_result_replay(status, result):

        # extract the data
        data = [x for x in result['cURL'][status] if x]

        # skip empty
        if not data:
            return

        # print header
        print('')
        print('')
        print('>> CURL COMMAND REPLAY:')
        print('')

        # print payloads
        for item in data:

            # init
            plp = item[0]
            pzn = item[1]
            pcc = item[2]

            print('  {} in zone {} ({}): {}'.format(plp, pzn, status, pcc))
            print('')

    # skip empty
    if not wb_result['cURL']:
        return ''

    # result processing
    for k in wb_result['cURL']:
    
        # show data
        get_result_replay(k, wb_result)


def table_get_result_summary(statuses, wb_result):

    # init
    result = {}
    payloads_type = set()
    payloads_summary_dict = {}
    payloads_summary_list_fp = []
    payloads_summary_list_fn = []

    table_headers_fn = [7 * ' ' + 'PAYLOAD TYPE', 10 * ' ' + 'PASSED', 10 * ' ' + 'BYPASSED', 10 * ' ' + 'FAILED']
    table_headers_fp = [7 * ' ' + 'PAYLOAD TYPE', 10 * ' ' + 'PASSED', 10 * ' ' + 'FALSED', 10 * ' ' + 'FAILED']

    # result processing
    for k in statuses:
        for item in wb_result[k]:

            # extract the data
            t = item[0].split('/')[0]
            z = item[1]

            # update payloads type list
            payloads_type.add(t)

            # update summary
            result[item[0] + ':' + z] = k

    # create result dictionary by payloads type
    for pt in payloads_type:

        fx_type = 'FALSED' if pt == 'FP' else 'BYPASSED'
        passed = len([k for k, v in result.items() if k.startswith(pt + '/') and v == 'PASSED'])
        failed = len([k for k, v in result.items() if k.startswith(pt + '/') and v == 'FAILED'])
        fx = len([k for k, v in result.items() if k.startswith(pt + '/') and v == fx_type])
        payloads_summary_dict[pt] = [passed + failed + fx, passed, fx, failed]

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

    i = len([k for k, v in result.items() if v == 'PASSED'])
    prcnt = get_percent_str(i, len(result))
    passed = str(i) + ' (' + str(prcnt) + '%)' if prcnt > 0 else '0'
    total = total + i

    i = len([k for k, v in result.items() if v == 'FAILED'])
    prcnt = get_percent_str(i, len(result))
    failed = str(i) + ' (' + str(prcnt) + '%)' if prcnt > 0 else '0'
    total = total + i

    i = len([k for k, v in result.items() if v == 'FALSED'])
    prcnt = get_percent_str(i, len(result))
    falsed = str(i) + ' (' + str(prcnt) + '%)' if prcnt > 0 else '0'
    total = total + i

    i = len([k for k, v in result.items() if v == 'BYPASSED'])
    prcnt = get_percent_str(i, len(result))
    bypassed = str(i) + ' (' + str(prcnt) + '%)' if prcnt > 0 else '0'
    total = total + i

    payloads_summary_list.append([
        len(result.items()),
        passed,
        falsed,
        bypassed,
        failed
    ])

    print('')
    tp.banner('TOTAL SUMMARY ', style='banner')
    tp.table(payloads_summary_list, table_headers)

    # summary validation
    if total != len(result):
        print('An error occurred while processing the result: {} != {}'.format(total, len(result)))
