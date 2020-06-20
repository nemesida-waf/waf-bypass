#!/usr/bin/python3

import sys
from requests.exceptions import MissingSchema
from signatures_test import SignaturesTest

options = {}
try:
    with open('options.txt') as f:
        for line in f:
            name, value = line.split('=')
            options[name] = value.strip('\n\'"')
except FileNotFoundError:
    print('Отсутствует файл с настройками - options.txt')
    sys.exit()
        
test = SignaturesTest(**options)

try:
    test.start_test()
except MissingSchema:
    print('В настройках host и proxy обязателен протокол')
