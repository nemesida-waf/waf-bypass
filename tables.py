#!/usr/bin/env python3

from colorama import Fore, Style
from prettytable import PrettyTable


def get_stats(wb_result, status):    
    return [k for k, v in wb_result.items() if v == status]


def get_result_details(wb_result, statuses):
    
    fp = [k for k, v in wb_result.items() if v == statuses[3]]
    fn = [k for k, v in wb_result.items() if v == statuses[4]]

    fp.sort()
    fn.sort()

    def items_processing(data, status):
        
        if not len(data):
            return ''

        if status == 'FP':
            table = PrettyTable([15 * ' ' + 'FALSE POSITIVE PAYLOAD' + 15 * ' ', 15 * ' ' + 'ZONE' + 15 * ' '])
        elif status == 'FN':
            table = PrettyTable([15 * ' ' + 'FALSE NEGATIVE PAYLOAD' + 15 * ' ', 15 * ' ' + 'ZONE' + 15 * ' '])
        else:
            table = PrettyTable([15 * ' ' + 'PAYLOAD' + 15 * ' ', 15 * ' ' + 'ZONE' + 15 * ' '])

        for item in data:
            k = item.split(':')[0]
            v = item.split(':')[1]
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
