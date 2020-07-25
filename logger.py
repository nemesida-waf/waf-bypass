from colorama import Fore, Style
from prettytable import PrettyTable



def read_log():
    log_dict =dict()
    with open('app.log', 'r') as log_file:
        logs = log_file.readlines() 

    for log in logs:
        key= log.split(" : ")[1] 
        value = log.split(" : ")[0] 
        log_dict[key] = value

    return log_dict



def write_log_stat():
    test = read_log()
    bypass_log = list()
    blocked_log = list()
    for key, value in test.items():
        if value == 'BYPASSED':
            bypass_log.append(key)
        else:
            blocked_log.append(key)
    return bypass_log

    

def logger_stat():
    count_pass = 0
    count_block = 0
    stat_req = dict()

    items_stat = read_log()
    for item in items_stat.values():
        if item == 'BYPASSED':
            count_pass +=1
        else:
            count_block +=1
        stat_req['BYPASSED'] = count_pass
        stat_req['BLOCKED'] = count_block


    return stat_req



