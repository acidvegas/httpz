#!/usr/bin/env python3
# Hyperfast Scalable HTTP Scanner - Developed by acidvegas (https://github.com/acidvegas)

import logging
import time

# ANSI color codes
class Colors:
    GREEN        = '\033[92m'
    DARK_GREEN   = '\033[32m'
    YELLOW       = '\033[93m'
    RED          = '\033[91m'
    DARK_RED     = '\033[31m'
    GRAY         = '\033[90m'
    BLUE         = '\033[94m'
    DARK_BLUE    = '\033[34m'
    PINK         = '\033[95m'
    ORANGE       = '\033[38;5;208m'
    RESET        = '\033[0m'
    UNDERLINE    = '\033[4m'
    CYAN         = '\033[36m'
    BRIGHT_GREEN = '\033[92m'
    PURPLE       = '\033[35m'


class ColoredFormatter(logging.Formatter):
    '''Custom formatter to add timestamp and color to the log messages'''

    def format(self, record: logging.LogRecord) -> str:
        '''
        Format the log message with timestamp and color

        :param record: The log record to format
        '''
        
        timestamp = f'{Colors.GRAY}{time.strftime("%Y-%m-%d %H:%M:%S")} │{Colors.RESET}'
        
        return f'{timestamp} {record.msg}'


def get_status_color(status_code: int) -> str:
    '''
    Get the color for the status code
    
    :param status_code: The status code
    '''
    
    return (Colors.GREEN if status_code < 300 else Colors.YELLOW if status_code < 400 else Colors.RED if status_code < 600 else Colors.GRAY)


def read_domains(file_obj):
    '''
    Generator to read domains line by line
    
    :param file_obj: File object to read from
    '''
    
    for line in file_obj:
        if domain := line.strip():
            yield domain