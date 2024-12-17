#!/usr/bin/python3

# Standard Python modules
from collections import deque
from contextlib import contextmanager
from enum import IntEnum
from itertools import islice
import logging
import logging.config
import os
import re
import sys
import time
import tomllib

# 3rd-party modules
import crcmod.predefined
import platformdirs
import serial
import serial.tools.list_ports

# Our own modules
from .version import __version__


CRC_16  = crcmod.predefined.mkCrcFun('xmodem')
CRC_32  = crcmod.predefined.mkCrcFun('crc-32')

ZPAD = ord(b'*')
ZDLE = ord(b'\x18')
ZBIN = ord(b'A')
ZHEX = ord(b'B')
ZBIN32 = ord(b'C')


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

class FileWriter:
    def __init__(self):
        self.f = None

    def open(self, filename):
        if self.f:
            try:
                self.f.close()
            except Exception:
                pass
            self.f = None
        self.f = open(filename, 'wb')
        return self.f

    def write(self, data):
        return self.f.write()

class Zmodem:
    #l_rx_raw = logging.getLogger('zmodem.rx.raw')
    #l_tx_raw = logging.getLogger('zmodem.tx.raw')
    class RxState(IntEnum):
        WAIT_HEADER_START = 0
        WAIT_FULL_HEADER  = 1

    def __init__(self, zf):
        self.zf = zf
        self.input_queue = deque()
        self.l_rx_raw = logging.getLogger('zmodem.rx.raw')
        self.l_tx_raw = logging.getLogger('zmodem.tx.raw')

    def close(self):
        if self.zf:
            try:
                self.zf.close()
            except Exception:
                pass
            self.zf = None

    def read_input(self):
        #logging.getLogger('zmodem.rx').info('read')
        #self.l_rx_raw.info('read')
        d = self.zf.read(128)
        if d:
            self.l_rx_raw.debug(bytes_as_hex_str(d))
            self.l_rx_raw.debug(bytes_as_printable_str(d))
            self.input_queue.extend(d)

    @staticmethod
    def get_header_start(iterable):
        """Return True if header start is present.
        Raise StopIteration if insufficient bytes are present."""
        it = iter(iterable)
        x = next(it)
        if x != ZPAD:
            return False
        x = next(it)
        if x != ZDLE:
            return False
        x = next(it)
        return x == ZHEX or x == ZBIN # or x == ZBIN32

    @staticmethod
    def lower_hex_to_int(byte_val):
        if 0x30 <= byte_val <= 0x39:
            return byte_val - 0x30
        if 0x61 <= byte_val <= 0x66:
            return byte_val - 0x57
        raise ValueError('Invalid value for lowercase hexadecimal')

    @staticmethod
    def get_lower_hex(it, count, size=1):
        for _ in range(count):
            x = 0
            for _ in range(2 * size):
                x = x * 16 + Zmodem.lower_hex_to_int(next(it))
            yield x

    @staticmethod
    def get_hex_header(iterable):
        """Return True if valid hex header is present.
        Raise StopIteration if insufficient bytes are present."""
        it = iter(iterable)
        x = next(it)
        if x != ZPAD:
            return False
        x = next(it)
        if x != ZDLE:
            return False
        x = next(it)
        if x != ZHEX:
            return False
        try:
            header_data = bytes(Zmodem.get_lower_hex(it, 5))
            crc16_val = next(Zmodem.get_lower_hex(it, 1, 2))
        except ValueError:
            return False
        logging.getLogger('rx.header.hex.data').info(bytes_as_hex_str(header_data))
        crc16_calc_val = CRC_16(header_data)
        if crc16_val == crc16_calc_val:
            return header_data
        else:
            logging.getLogger('rx.header.hex.crc').warning('{!r}; calc {!r}'.format(crc16_val, crc16_calc_val))
            return False

class ZmodemReceive(Zmodem):
    def __init__(self, zf, file_writer):
        super().__init__(zf)
        self.file_writer = file_writer
        self.rx_state = self.RxState.WAIT_HEADER_START

    def process_input(self):
        logging.getLogger('rx.q').debug(bytes_as_hex_str(self.input_queue))
        if self.rx_state == self.RxState.WAIT_HEADER_START:
            # Discard bytes until finding a header start byte.
            while self.input_queue:
                try:
                    result = Zmodem.get_header_start(self.input_queue)
                except StopIteration:
                    break
                else:
                    if result:
                        self.rx_state = self.RxState.WAIT_FULL_HEADER
                        break
                    else:
                        self.input_queue.popleft()
        if self.rx_state == self.RxState.WAIT_FULL_HEADER:
            try:
                result = Zmodem.get_hex_header(self.input_queue)
            except StopIteration:
                pass
            else:
                if result:
                    logging.getLogger('rx.header.hex').info(bytes_as_hex_str(result))

    def process(self):
        self.read_input()
        self.process_input()

def main():
    # Initialise logging -- part 1
    logging_init1()

    args = get_arguments()

    try:
        # Initialise logging -- part 2 after getting arguments and changing privileges
        logging_init2(args)

        logging.getLogger('info').info('Press Ctrl-C to stop')

        # Open serial
        with serial.Serial(args.serialport, args.bitrate, timeout=0.25) as s:

            rz = ZmodemReceive(s, None)
            logging.getLogger('info').info('Get data')
            # Get input data
            while True:
                rz.process()
                time.sleep(0.5)
    except KeyboardInterrupt:
        logging.getLogger('zmodem').info('Stopping')
        raise
    finally:
        rz.close()

if __name__ == '__main__':
    main()
