#!/usr/bin/python3

# Standard Python modules
from contextlib import contextmanager
import logging
import logging.config
import os
import re
import sys
import tomllib

# 3rd-party modules
import platformdirs
import serial
import serial.tools.list_ports

# Our own modules
from .version import __version__


def bytes_as_hex_str(bytes_data):
    return ' '.join('{:02X}'.format(x) for x in bytes_data)

def printable_char(byteval):
    aschar = chr(byteval)
    if ' ' <= aschar <= '~':
        return aschar
    elif aschar == '\n':
        return '\\n'
    elif aschar == '\r':
        return '\\r'
    else:
        return '?'

def bytes_as_printable_str(bytes_data):
    return ' '.join('{:2}'.format(printable_char(x)) for x in bytes_data)


def logging_init1():
    ch = logging.StreamHandler(sys.stdout)
    #ch.setLevel(logging.INFO)
    ch.setLevel(logging.DEBUG)
    # create formatter and add it to the handlers
    formatter = logging.Formatter('%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s',
                                    datefmt='%Y-%m-%d %H:%M:%S')
    ch.setFormatter(formatter)
    # add the handlers to the logger
    logger = logging.getLogger('')
    logger.addHandler(ch)
    logger.setLevel(logging.DEBUG)

def logging_init2(args):
    for filename in reversed(args.loggingconfig):
        filename = os.path.expanduser(filename)
        logging.getLogger('config').debug('Search logging config file: {}'.format(filename))
    for filename in reversed(args.loggingconfig):
        filename = os.path.expanduser(filename)
        if os.path.exists(filename):
            extension = os.path.splitext(filename)[1].lower()
            if extension == '.conf':
                logging.config.fileConfig(filename, disable_existing_loggers=False)
            elif extension == '.toml':
                with open(filename, 'rb') as f:
                    config = tomllib.load(f)
                    logging.config.dictConfig(config)
            logging.getLogger('config').debug('Use logging config file: {}'.format(filename))
            break

def natsort(s, _nsre=re.compile('([0-9]+)')):
    return [int(text) if text.isdigit() else text.lower()
            for text in _nsre.split(s)]

def get_com_ports():
    com_ports = []
    for port_info in serial.tools.list_ports.comports():
        if port_info.description:
            port_str = '{}: {}'.format(port_info.device, port_info.description)
        else:
            port_str = port_info.device
        com_ports.append(port_str)
    com_ports = sorted(com_ports, key=natsort)
    return com_ports

def list_serial_ports(*args, **kwargs):
    print("Serial Ports\n")
    for port in get_com_ports():
        print("  {}".format(port))
    sys.exit(1)

def get_arguments():
    '''Get command line arguments, and config file(s)
    '''
    config_dir = platformdirs.user_config_dir('zmodem-py', 'zmodem-py', roaming=True)
    logging.getLogger('config').debug('Config dir: {}'.format(config_dir))
    try:
        # Using 3rd-party module (command-line plus config file)
        import configargparse

        default_config_files=[ os.path.join(config_dir, 'zmodem-py.conf'), ]
        parser = configargparse.ArgParser(default_config_files=default_config_files,
                                          ignore_unknown_config_file_keys=True)
    except ImportError:
        # Using Python standard module (command-line only)
        import argparse

        parser = argparse.ArgumentParser(description='ZMODEM send/receive.')
    parser.add_argument('-l', '--loggingconfig', action='append', metavar='FILE',
                        default=[ os.path.join(config_dir, 'logging.conf'),
                                  os.path.join(config_dir, 'logging.toml'), ],
                        help='Logging config file')
    parser.add_argument('-V', '--version', action='version',
                        version='%(prog)s {version}'.format(version=__version__))

    # Input possibilities (mutually exclusive)
    ingroup = parser.add_mutually_exclusive_group(required=True)
    ingroup.add_argument('-p', '--serialport', metavar='PORT',
                        help='Serial port for ZMODEM send/receive')
    ingroup.add_argument('-L', '--listserialports', action='store_true',
                        help='List available serial ports')

    # Input options
    parser.add_argument('-b', '--bitrate', metavar='BPS', type=int, default=115200,
                        help='Serial port bit rate')

    # Action options
    actiongroup = parser.add_mutually_exclusive_group(required=True)
    actiongroup.add_argument('-s', '--send', action='store_true',
                            help='Send a file')
    actiongroup.add_argument('-r', '--receive', action='store_true',
                            help='Receive a file')

    parser.add_argument('-f', '--file', metavar='FILENAME',
                        help='Filename')

    args = parser.parse_args()

    if args.listserialports:
        list_serial_ports()

    return args

def main():
    # Initialise logging -- part 1
    logging_init1()

    args = get_arguments()

    try:
        # Initialise logging -- part 2 after getting arguments and changing privileges
        logging_init2(args)

        logger_rx_raw = logging.getLogger('rx.raw')
        logger_tx_raw = logging.getLogger('tx.raw')

        logging.getLogger('info').info('Press Ctrl-C to stop')

        # Open serial
        with serial.Serial(args.serialport, args.bitrate, timeout=0.25) as s:

            logging.getLogger('info').info('Get data')
            # Get input data
            while True:
                d = s.read(128)
                if d:
                    logger_rx_raw.debug(bytes_as_hex_str(d))
                    logger_rx_raw.debug(bytes_as_printable_str(d))
    except KeyboardInterrupt:
        logging.getLogger('zmodem').info('Stopping')

if __name__ == '__main__':
    main()
