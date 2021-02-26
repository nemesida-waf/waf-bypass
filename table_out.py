#!/usr/bin/env python3

from prettytable import PrettyTable
from logger import logger_stat, write_log_stat
from collections import OrderedDict
from colorama import Fore as f
from colorama import Style as s


def table_payload_zone():
    red, green, yellow, white_br, reset = f.RED, f.GREEN, f.YELLOW, s.BRIGHT, s.RESET_ALL
    directory = '/tmp/waf-bypass-log/'
    passed, failed_fn, failed_fp, errors = write_log_stat()

    def items_processing(passed_or_failed):
        dictionary = {}
        table = PrettyTable(['Payload', 'Zone'])
        for i in ['passed.log', 'failed_fn.log', 'failed_fp.log', 'errors.log']:
            with open(directory + i, 'w') as opened_file:
                for items in passed_or_failed:
                    opened_file.writelines(items)

        if passed_or_failed == passed:
            file_name = 'passed.log'
        elif passed_or_failed == failed_fn:
            file_name = 'failed_fn.log'
        elif passed_or_failed == failed_fp:
            file_name = 'failed_fp.log'
        else:
            file_name = 'errors.log'

        for i in passed_or_failed:
            source, zone = i.split(" in ")
            formatted_zone = zone.strip('\n')
            if formatted_zone in ('Body', 'ARGS', 'Referer', 'UA', 'Cookie', 'Header', 'URL'):
                dictionary.setdefault(source, []).append(formatted_zone.lower())

        b = OrderedDict(sorted(dictionary.items(), key=lambda t: t[0]))

        for key, value in b.items():
            value_str = ' '.join(value)
            table.add_row([key, value_str])

        string_table = table.get_string()

        with open(directory + file_name, 'w') as file_pass:
            file_pass.write(string_table)
            file_pass.close()
        return dictionary

    def add_line_to_table_payload_zone(dictionary_selected, colour):
        for payload_path, value in dictionary_selected.items():
            all_zone_arguments = ' '.join(value)
            print('|{:^51}'.format(payload_path) + '|' + '{:^55}'.format(colour + all_zone_arguments + reset) + '|')

    """Payload-Zone table elements"""
    crossbar = '+' + 51 * '-' + '+' + 46 * '-' + '+'
    table_header_1 = crossbar + '\n|' + 22 * ' ' + f'{white_br}Payload{reset}' + 22 * ' ' + '|' \
                                     + 21 * ' ' + f'{white_br}Zone{reset}' + 21 * ' ' + '|\n' + \
                     crossbar + '\n|' + 44 * ' ' + 'False Positive' + 40 * ' ' + '|' + '\n' + crossbar
    table_header_2 = crossbar + '\n|' + 44 * ' ' + 'False Negative' + 40 * ' ' + '|' + '\n' + crossbar

    """Payload-Zone table print"""
    print(table_header_1)
    add_line_to_table_payload_zone(items_processing(failed_fp), red)
    print(table_header_2)
    add_line_to_table_payload_zone(items_processing(failed_fn), red)
    print(crossbar)
    """End of the table"""


def table_status_count_accuracy():
    r, g, y, w, n = f.RED, f.GREEN, f.YELLOW, s.BRIGHT, s.RESET_ALL

    count_of_passed = logger_stat()['PASSED']
    count_of_failed_fn = logger_stat()['FAILED_FN']
    count_of_failed_fp = logger_stat()['FAILED_FP']
    count_of_errors = logger_stat()['ERROR']

    failed_sum = count_of_failed_fn + count_of_failed_fp
    sum_all = count_of_passed + failed_sum + count_of_errors

    passed_accuracy = round((count_of_passed/sum_all)*100, 2) if sum_all != 0 else '0.00'
    failed_accuracy = round((failed_sum/sum_all)*100, 2) if sum_all != 0 else '0.00'
    errors_accuracy = round((count_of_errors/sum_all)*100, 2) if sum_all != 0 else '0.00'

    table = PrettyTable([f'Status',     f'Count',                       f'Accuracy'])
    table.add_row(      [f'PASSED',     f'{g}{count_of_passed}{n}',     f'{g}{passed_accuracy}%{n}'])
    table.add_row(      [f'FAILED',     f'{r}{failed_sum}{n}',          f'{r}{failed_accuracy}%{n}'])
    table.add_row(      [f'ERROR',      f'{y}{count_of_errors}{n}',     f'{y}{errors_accuracy}%{n}'])
    table.title = f'{w}Summary{n}'
    table.align[f'Status'] = "l"

    print('\n')
    print(table)
