#!/usr/bin/env python3

from collections import OrderedDict
from colorama import Fore, Style
from prettytable import PrettyTable
from stats import get_stats, get_details


def get_result_details(wb_result, statuses):

    red, green, yellow, white_br, reset = Fore.RED, Fore.GREEN, Fore.YELLOW, Style.BRIGHT, Style.RESET_ALL
    passed, failed_fn, failed_fp, errors = get_details(wb_result, statuses)

    def items_processing(passed_or_failed):
        dictionary = {}
        table = PrettyTable(['Payload', 'Zone'])

        for i in passed_or_failed:
            source, zone = i.split(" in ")
            formatted_zone = zone.strip('\n')
            if formatted_zone in ('URL', 'ARGS', 'BODY', 'COOKIE', 'USER-AGENT', 'REFERER', 'HEADER'):
                dictionary.setdefault(source, []).append(formatted_zone.upper())

        b = OrderedDict(sorted(dictionary.items(), key=lambda t: t[0]))

        for key, value in b.items():
            value_str = ' '.join(value)
            table.add_row([key, value_str])

        return dictionary

    def add_line_to_get_result_details(dictionary_selected, colour):
        for payload_path, value in dictionary_selected.items():
            all_zone_arguments = ' '.join(value)
            print('|{:^51}'.format(payload_path) + '|' + '{:^55}'.format(colour + all_zone_arguments + reset) + '|')

    """ Payload-Zone table elements """
    crossbar = '+' + 51 * '-' + '+' + 46 * '-' + '+'
    table_header_1 = crossbar + '\n|' + 22 * ' ' + f'{white_br}Payload{reset}' + 22 * ' ' + '|' + \
        21 * ' ' + f'{white_br}Zone{reset}' + 21 * ' ' + '|\n' + \
        crossbar + '\n|' + 44 * ' ' + 'False Positive' + 40 * ' ' + '|' + '\n' + crossbar
    table_header_2 = crossbar + '\n|' + 44 * ' ' + 'False Negative' + 40 * ' ' + '|' + '\n' + crossbar

    """ Payload-Zone table print """
    print('\n')
    print(table_header_1)
    add_line_to_get_result_details(items_processing(failed_fp), red)
    print(table_header_2)
    add_line_to_get_result_details(items_processing(failed_fn), red)
    print(crossbar)
    """ End of the table """


def table_get_result_accuracy(wb_result, statuses):

    r, g, y, w, n = Fore.RED, Fore.GREEN, Fore.YELLOW, Style.BRIGHT, Style.RESET_ALL

    count_of_passed = len(get_stats(wb_result, statuses[1]))
    count_of_errors = len(get_stats(wb_result, statuses[2]))
    count_of_failed_fp = len(get_stats(wb_result, statuses[3]))
    count_of_failed_fn = len(get_stats(wb_result, statuses[4]))

    failed_sum = count_of_failed_fn + count_of_failed_fp
    sum_all = count_of_passed + failed_sum + count_of_errors

    passed_accuracy = round((count_of_passed/sum_all)*100, 2) if sum_all != 0 else '0.00'
    failed_accuracy = round((failed_sum/sum_all)*100, 2) if sum_all != 0 else '0.00'
    errors_accuracy = round((count_of_errors/sum_all)*100, 2) if sum_all != 0 else '0.00'

    table = PrettyTable([f'Status', f'Count', f'Accuracy'])
    table.add_row([f'PASSED', f'{g}{count_of_passed}{n}', f'{g}{passed_accuracy}%{n}'])
    table.add_row([f'FAILED', f'{r}{failed_sum}{n}', f'{r}{failed_accuracy}%{n}'])
    if count_of_errors > 0:
        table.add_row([f'ERROR', f'{y}{count_of_errors}{n}', f'{y}{errors_accuracy}%{n}'])
    table.title = f'{w}Summary{n}'
    table.align[f'Status'] = "l"

    print('\n')
    print(table)
