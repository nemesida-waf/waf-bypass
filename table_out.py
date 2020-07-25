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
    

    
    dict_bypass={}

    table_bypass_color.field_names = ['Payload', 'Zone']
    table_bypass_uncolor.field_names = ['Payload', 'Zone']

    table_bypass_color.align = "c"
    table_bypass_uncolor.align = "c"

    passeds= write_log_stat()
    
    for passed in passeds:
        source, zone = passed.split(" in ")
        if zone == 'Body\n':
            dict_bypass.setdefault(source, []).append("BODY")

        
        elif zone == 'ARGS\n':
            dict_bypass.setdefault(source, []).append("ARGS")

        elif zone == 'UA\n':
            dict_bypass.setdefault(source, []).append("UA")


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
    with open('bypass.log','w') as file_pass:
        file_pass.write(string_table)
    
    
    return print(table_bypass_color)

    


  
