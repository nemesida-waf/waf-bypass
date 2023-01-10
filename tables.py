#!/usr/bin/env python3

from colorama import Fore, Style
from prettytable import PrettyTable


def get_stats(wb_result, status):    
    return [k for k, v in wb_result.items() if v == status]


def fx_table_processing(fx):
    
    # init
    res = {}

    # skip empty list
    if not len(fx):
        return res
    
    # list processing
    for item in fx:
        k = item.split(':')[0]
        v = item.split(':')[1]
        if k not in res:
            res[k] = []
        res[k].append(v)
    
    # dictionary processing
    for k, v in res.items():
        res[k] = '|'.join(v)

    # return result
    return res


def get_result_details(wb_result, statuses):
    
    fp = [k for k, v in wb_result.items() if v == statuses[3]]
    fn = [k for k, v in wb_result.items() if v == statuses[4]]

    fp.sort()
    fn.sort()

    fp = fx_table_processing(fp)
    fn = fx_table_processing(fn)

    def items_processing(fx, status):
        
        if not len(fx):
            return ''

        if status == 'FP':
            table = PrettyTable([10 * ' ' + 'FALSE POSITIVE PAYLOAD' + 10 * ' ', 25 * ' ' + 'ZONE' + 25 * ' '])
            table.align['FALSE POSITIVE PAYLOAD'] = 'l'
        elif status == 'FN':
            table = PrettyTable([10 * ' ' + 'FALSE NEGATIVE PAYLOAD' + 10 * ' ', 25 * ' ' + 'ZONE' + 25 * ' '])
            table.align['FALSE NEGATIVE PAYLOAD'] = 'l'
        else:
            table = PrettyTable([10 * ' ' + 'PAYLOAD' + 10 * ' ', 25 * ' ' + 'ZONE' + 25 * ' '])
            table.align['PAYLOAD'] = 'l'

        for k, v in fx.items():
            table.add_row([k, v])

        print(table)

    """ Payload-Zone table print """
    print('\n')
    items_processing(fp, statuses[3])
    items_processing(fn, statuses[4])
    """ End of the table """


def table_get_result_accuracy(wb_result, statuses):

    r, g, y, w, n = Fore.RED, Fore.GREEN, Fore.YELLOW, Style.BRIGHT, Style.RESET_ALL

    count_of_passed = len(get_stats(wb_result, statuses[1]))
    count_of_errors = len(get_stats(wb_result, statuses[2]))
    count_of_fp = len(get_stats(wb_result, statuses[3]))
    count_of_fn = len(get_stats(wb_result, statuses[4]))
    count_of_failed = count_of_fn + count_of_fp
    count_of_all = count_of_passed + count_of_failed + count_of_errors

    passed_accuracy = round((count_of_passed/count_of_all)*100, 2) if count_of_all != 0 else '0.00'
    failed_accuracy = round((count_of_failed/count_of_all)*100, 2) if count_of_all != 0 else '0.00'
    errors_accuracy = round((count_of_errors/count_of_all)*100, 2) if count_of_all != 0 else '0.00'

    table = PrettyTable([f'STATUS', f'COUNT', f'ACCURACY'])
    table.title = f'{w}SUMMARY{n}'
    table.align[f'STATUS'] = "l"
    
    table.add_row([f'PASSED', f'{g}{count_of_passed}{n}', f'{g}{passed_accuracy}%{n}'])
    if count_of_failed > 0:
        table.add_row([f'FAILED', f'{r}{count_of_failed}{n}', f'{r}{failed_accuracy}%{n}'])
    if count_of_errors > 0:
        table.add_row([f'ERROR', f'{y}{count_of_errors}{n}', f'{y}{errors_accuracy}%{n}'])
    
    print('\n')
    print(table)
