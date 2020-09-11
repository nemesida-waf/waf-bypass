from prettytable import PrettyTable, PLAIN_COLUMNS, MSWORD_FRIENDLY
from colorama import Fore, Style
from logger import logger_stat
from logger import write_log_stat
from collections import OrderedDict


def print_table():
    passed = Fore.RED+"BYPASSED"+Style.RESET_ALL
    passed_count =Fore.RED+ str(logger_stat()['BYPASSED'])+Style.RESET_ALL

    blocked = Fore.GREEN+"BLOCKED"+Style.RESET_ALL
    blocked_count =Fore.GREEN+ str(logger_stat()['BLOCKED'])+Style.RESET_ALL

    table_status = PrettyTable()
    table_status.field_names = ['Status','Count']
    table_status.add_row([passed,passed_count])
    table_status.add_row([blocked, blocked_count])
    print("\n")
    return print(table_status)



def bypass_table():
    table_bypass_color = PrettyTable()
    table_bypass_uncolor = PrettyTable()
    table_blocked_uncolor = PrettyTable()
    

    
    dict_bypass={}
    dict_blocked={}

    table_bypass_color.field_names = ['Payload', 'Zone']
    table_bypass_uncolor.field_names = ['Payload', 'Zone']
    table_blocked_uncolor.field_names = ['Payload', 'Zone']

    table_bypass_color.align = "c"
    table_bypass_uncolor.align = "c"
    table_blocked_uncolor.align = "c"

    passeds, blockeds = write_log_stat()
    
    with open('log/bypass.log', 'w') as bypass_file:
        for passed in passeds:
            bypass_file.writelines(passed)
    with open('log/blocked.log','w') as blocked_file:
        for blocked in blockeds:
            blocked_file.writelines(blocked)




    for passed in passeds:
        source, zone = passed.split(" in ")
        if zone == 'Body\n':
            dict_bypass.setdefault(source, []).append("BODY")

        
        elif zone == 'ARGS\n':
            dict_bypass.setdefault(source, []).append("ARGS")

        elif zone == 'UA\n':
            dict_bypass.setdefault(source, []).append("UA")

        elif zone == 'Cookie\n' or zone == 'Cookie':
            dict_bypass.setdefault(source, []).append("Cookie")

        elif zone == 'URL\n' or zone == 'URL':
            dict_bypass.setdefault(source, []).append("URL")

        elif zone == 'Referer\n' or zone == 'Referer':
            dict_bypass.setdefault(source, []).append("Referer")
    


        elif zone == 'Header\n' or zone == 'Header':
            dict_bypass.setdefault(source, []).append("HEADER")
    

    b = OrderedDict(sorted(dict_bypass.items(),key=lambda t:t[0]))
    
    
    for key, value in b.items():            
        value_str = Fore.RED+' '.join(value)+Style.RESET_ALL
        table_bypass_color.add_row([key, value_str])
    
    for key, value in b.items():
        value_str =' '.join(value)
        table_bypass_uncolor.add_row([key,value_str])

    string_table = table_bypass_uncolor.get_string()
    with open('log/bypass_zone.log','w') as file_pass:
        file_pass.write(string_table)


#blocked zone

    for blocked in blockeds:
        source, zone = blocked.split(" in ")
        if zone == 'Body\n':
            dict_blocked.setdefault(source, []).append("BODY")

        
        elif zone == 'ARGS\n':
            dict_blocked.setdefault(source, []).append("ARGS")
        elif zone == 'Referer\n' or zone == 'Referer':
            dict_blocked.setdefault(source, []).append("Referer")

        elif zone == 'UA\n':
            dict_blocked.setdefault(source, []).append("UA")

        elif zone == 'Cookie\n' or zone == 'Cookie':
            dict_blocked.setdefault(source, []).append("Cookie")

        elif zone == 'Header\n' or zone == 'Header':
            dict_blocked.setdefault(source, []).append("HEADER")

        elif zone == 'URL\n' or zone == 'URL':
            dict_blocked.setdefault(source, []).append("URL")
    

    b = OrderedDict(sorted(dict_blocked.items(),key=lambda t:t[0]))
    
    
    for key, value in b.items():
        value_str =' '.join(value)
        table_blocked_uncolor.add_row([key,value_str])

    string_table = table_blocked_uncolor.get_string()
    with open('log/blocked_zone.log','w') as file_block:
        file_block.write(string_table)    
    
    
    return print(table_bypass_color)


    


  
