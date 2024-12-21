#!/usr/bin/python3

# Standard Python modules
from collections import deque
from contextlib import contextmanager
from enum import IntEnum
from itertools import islice
import codecs
import logging
import logging.config
import os
import re
import struct
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

CAN  = ord(b'\x18')
ZDLE = ord(b'\x18')
ZPAD = ord(b'*')
ZBIN = ord(b'A')
ZHEX = ord(b'B')
ZBIN32 = ord(b'C')

# Subpacket identifiers
ZCRCE = ord(b'h')   # End of frame. Header packet follows.
ZCRCG = ord(b'i')   # Frame continues nonstop. ZACK not expected.
ZCRCQ = ord(b'j')   # Frame continues, ZACK expected.
ZCRCW = ord(b'k')   # Waiting end of frame, ZACK expected, header packet follows

class ZType(IntEnum):
    ZRQINIT     = 0
    ZRINIT      = 1
    ZSINIT      = 2
    ZACK        = 3
    ZFILE       = 4
    ZSKIP       = 5
    ZNAK        = 6
    ZABORT      = 7
    ZFIN        = 8
    ZRPOS       = 9
    ZDATA       = 10
    ZEOF        = 11
    ZFERR       = 12
    ZCRC        = 13
    ZCHALLENGE  = 14
    ZCOMPL      = 15
    ZFREECNT    = 17
    ZCOMMAND    = 18
    ZSTDERR     = 19

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
        WAIT_HEADER_START   = 0
        WAIT_ZDLE           = 1
        WAIT_HEADER_TYPE    = 2
        GET_HEADER          = 3
        GET_SUBPACKET       = 4

    def __init__(self, zf):
        self.zf = zf
        self.input_queue = deque()
        self.get_subpacket_gen = None
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
    def lower_hex_to_int(byte_val):
        """Convert lower-case hexadecimal character to a nibble value.
        Input value is the integer value of an ASCII character.
        Accept only characters 0-9 and a-f."""
        if 0x30 <= byte_val <= 0x39:
            return byte_val - 0x30
        if 0x61 <= byte_val <= 0x66:
            return byte_val - 0x57
        raise ValueError('Invalid value for lowercase hexadecimal')

    @staticmethod
    def get_lower_hex(count, word_size=1):
        """Generator to parse hex digits and yield word values (by default, bytes).
        Send RX bytes to this generator with send().
        It will yield integer values one-by-one."""
        result = None
        for _ in range(count):
            x = 0
            for _ in range(2 * word_size - 1):
                byteval = yield result
                result = None
                x = x * 16 + Zmodem.lower_hex_to_int(byteval)
            byteval = yield result
            result = x * 16 + Zmodem.lower_hex_to_int(byteval)
        yield result

    @staticmethod
    def get_hex_header():
        """Generator to parse a ZMODEM hex header.
        Send RX bytes to this generator with send().
        It will yield 5 bytes of header contents (1-byte type and 4 bytes of accompanying data)
        when a complete header with valid CRC has been received."""
        try:
            # Get 10 hex digits, representing 5 header bytes.
            g = Zmodem.get_lower_hex(5)
            next(g)
            header_data = bytearray()
            while len(header_data) < 5:
                byteval = yield
                result = g.send(byteval)
                if result is not None:
                    header_data.append(result)
            logging.getLogger('rx.header.hex.data').debug(bytes_as_hex_str(header_data))

            # Get 4 hex digits, representing 16-bit CRC value.
            g = Zmodem.get_lower_hex(1, 2)
            next(g)
            # crc16_val = g.send(byteval)  # use last byteval from previously
            crc16_val = None
            while crc16_val is None:
                byteval = yield
                crc16_val = g.send(byteval)
        except ValueError:
            return False

        logging.getLogger('rx.header.hex.crc').debug('{:04X}'.format(crc16_val))
        crc16_calc_val = CRC_16(header_data)
        if crc16_val == crc16_calc_val:
            yield header_data
        else:
            logging.getLogger('rx.header.hex.crc').warning('{:04X}; calc {:04X}'.format(crc16_val, crc16_calc_val))

    @staticmethod
    def get_bin_escaped(count, word_size=1):
        """Generator to parse binary bytes, possibly escaped, and yield word values (by default, bytes).
        Send RX bytes to this generator with send().
        It will yield integer values one-by-one."""
        result = None
        for _ in range(count):
            x = 0
            for _ in range(word_size - 1):
                byteval = yield result
                result = None
                if byteval == ZDLE:
                    byteval = yield
                    if byteval & 0x60 != 0x40:
                        return byteval
                    byteval ^= 0x40
                x = x * 256 + byteval
            byteval = yield result
            if byteval == ZDLE:
                byteval = yield
                if byteval & 0x60 != 0x40:
                    return byteval
                byteval ^= 0x40
            result = x * 256 + byteval
        yield result

    @staticmethod
    def get_bin_header():
        """Generator to parse a ZMODEM binary header.
        Send RX bytes to this generator with send().
        It will yield 5 bytes of header contents (1-byte type and 4 bytes of accompanying data)
        when a complete header with valid CRC has been received."""
        try:
            # Get 5 binary values, possibly escaped.
            g = Zmodem.get_bin_escaped(5)
            next(g)
            header_data = bytearray()
            while len(header_data) < 5:
                byteval = yield
                result = g.send(byteval)
                if result is not None:
                    header_data.append(result)
            logging.getLogger('rx.header.bin.data').debug(bytes_as_hex_str(header_data))

            # Get 2 binary values, possibly escaped.
            g = Zmodem.get_bin_escaped(1, 2)
            next(g)
            # crc16_val = g.send(byteval)  # use last byteval from previously
            crc16_val = None
            while crc16_val is None:
                byteval = yield
                crc16_val = g.send(byteval)
        except ValueError:
            return False

        logging.getLogger('rx.header.bin.crc').debug('{:04X}'.format(crc16_val))
        crc16_calc_val = CRC_16(header_data)
        if crc16_val == crc16_calc_val:
            yield header_data
        else:
            logging.getLogger('rx.header.bin.crc').warning('{:04X}; calc {:04X}'.format(crc16_val, crc16_calc_val))

    @staticmethod
    def get_subpacket():
        """Generator to parse a ZMODEM subpacket.
        Send RX bytes to this generator with send().
        It will yield however many bytes of data after the subpacket terminator followed by
        a valid CRC has been received."""
        try:
            # Get data, possibly escaped.
            g = Zmodem.get_bin_escaped(2**32)
            next(g)
            subpacket_data = bytearray()
            subpacket_type = b''
            try:
                while True:
                    byteval = yield
                    result = g.send(byteval)
                    if result is not None:
                        subpacket_data.append(result)
            except StopIteration as e:
                subpacket_type = bytes((e.value,))
                if e.value == ZCRCE:
                    pass
                elif e.value == ZCRCG:
                    pass
                elif e.value == ZCRCQ:
                    pass
                elif e.value == ZCRCW:
                    pass
                else:
                    return False
            logging.getLogger('rx.subpacket.data').debug(bytes_as_hex_str(subpacket_data))

            # Get 2 binary values, possibly escaped.
            g = Zmodem.get_bin_escaped(1, 2)
            next(g)
            # crc16_val = g.send(byteval)  # use last byteval from previously
            crc16_val = None
            while crc16_val is None:
                byteval = yield
                crc16_val = g.send(byteval)
        except ValueError:
            return False

        logging.getLogger('rx.subpacket.crc').debug('{:04X}'.format(crc16_val))
        crc16_calc_val = CRC_16(subpacket_data + subpacket_type)
        if crc16_val == crc16_calc_val:
            yield subpacket_data
        else:
            logging.getLogger('rx.subpacket.crc').warning('{:04X}; calc {:04X}'.format(crc16_val, crc16_calc_val))

    @staticmethod
    def swap32(x):
        return (((x & 0x000000FF) << 24) |
                ((x & 0x0000FF00) <<  8) |
                ((x & 0x00FF0000) >>  8) |
                ((x & 0xFF000000) >> 24))

    def send_hex_header(self, header_type, header_data_flags, header_data_pos):
        header_data_pos_swap = self.swap32(header_data_pos)
        header_data = header_data_flags | header_data_pos_swap
        header_all_data = struct.pack('>BI', header_type, header_data)
        crc16_calc = CRC_16(header_all_data)
        crc16_calc_bytes = struct.pack('>H', crc16_calc)
        header_all_hex = codecs.encode(header_all_data + crc16_calc_bytes, 'hex')
        header = b'**\x18B' + header_all_hex + b'\r\n\x11'
        self.l_tx_raw.debug(bytes_as_hex_str(header))
        self.l_tx_raw.debug(bytes_as_printable_str(header))
        self.zf.write(header)

    def process_header_type(self, header_type, header_data_flags, header_data_pos):
        if header_type in self.handlers:
            handler_fn, pos_mask = self.handlers[header_type]
            handler_fn(self, header_data_flags, header_data_pos & pos_mask)

    def process_header(self, header_data):
        header_type_val, header_data_flags = struct.unpack(">BI", header_data)
        header_data_pos = self.swap32(header_data_flags)
        header_type = ZType(header_type_val)
        #logging.getLogger('rx.header.type').info('{!r}'.format(header_type))
        logging.getLogger('rx.header').info('type {!r}; flags {:08X}; pos {:08X}'.format(header_type, header_data_flags, header_data_pos))
        self.process_header_type(header_type, header_data_flags, header_data_pos)

    def process_subpacket(self, subpacket_data):
        pass

    def process_input(self):
        """Process input in self.input_queue."""
        # logging.getLogger('rx.q').debug(bytes_as_hex_str(self.input_queue))
        while self.input_queue:
            byteval = self.input_queue.popleft()
            if byteval == ZPAD:
                self.rx_state = self.RxState.WAIT_ZDLE
            elif self.rx_state == self.RxState.WAIT_HEADER_START:
                # Discard bytes until finding a header start byte.
                pass
            elif self.rx_state == self.RxState.WAIT_ZDLE:
                if byteval == ZDLE:
                    self.rx_state = self.RxState.WAIT_HEADER_TYPE
                else:
                    self.rx_state = self.RxState.WAIT_HEADER_START
            elif self.rx_state == self.RxState.WAIT_HEADER_TYPE:
                if byteval == ZHEX:
                    self.rx_state = self.RxState.GET_HEADER
                    self.get_header_gen = self.get_hex_header()
                    next(self.get_header_gen)
                elif byteval == ZBIN:
                    self.rx_state = self.RxState.GET_HEADER
                    self.get_header_gen = self.get_bin_header()
                    next(self.get_header_gen)
                else:
                    self.rx_state = self.RxState.WAIT_HEADER_START
            elif self.rx_state == self.RxState.GET_HEADER:
                try:
                    result = self.get_header_gen.send(byteval)
                    if result is not None:
                        self.rx_state = self.RxState.WAIT_HEADER_START
                        self.process_header(result)
                except StopIteration:
                    self.rx_state = self.RxState.WAIT_HEADER_START
            elif self.rx_state == self.RxState.GET_SUBPACKET:
                if self.get_subpacket_gen is None:
                    self.get_subpacket_gen = self.get_subpacket()
                    next(self.get_subpacket_gen)
                try:
                    result = self.get_subpacket_gen.send(byteval)
                    if result is not None:
                        self.rx_state = self.RxState.WAIT_HEADER_START
                        self.get_subpacket_gen = None
                        self.process_subpacket(result)
                except StopIteration:
                    self.rx_state = self.RxState.WAIT_HEADER_START
                    self.get_subpacket_gen = None

class ZmodemReceive(Zmodem):
    def __init__(self, zf, file_writer):
        super().__init__(zf)
        self.file_writer = file_writer
        self.rx_state = self.RxState.WAIT_HEADER_START

    def process(self):
        self.read_input()
        self.process_input()

    def zrqinit_handler(self, header_data_flags, header_data_pos):
        self.send_hex_header(ZType.ZRINIT, 3, 0)

    def zrinit_handler(self, header_data_flags, header_data_pos):
        pass

    def zsinit_handler(self, header_data_flags, header_data_pos):
        self.rx_state = self.RxState.GET_SUBPACKET

    def zack_handler(self, header_data_flags, header_data_pos):
        pass

    def zfile_handler(self, header_data_flags, header_data_pos):
        self.rx_state = self.RxState.GET_SUBPACKET

    def zskip_handler(self, header_data_flags, header_data_pos):
        pass

    def znak_handler(self, header_data_flags, header_data_pos):
        pass

    def zabort_handler(self, header_data_flags, header_data_pos):
        pass

    def zfin_handler(self, header_data_flags, header_data_pos):
        pass

    def zrpos_handler(self, header_data_flags, header_data_pos):
        pass

    def zdata_handler(self, header_data_flags, header_data_pos):
        self.rx_state = self.RxState.GET_SUBPACKET

    def zeof_handler(self, header_data_flags, header_data_pos):
        pass

    def zferr_handler(self, header_data_flags, header_data_pos):
        pass

    def zcrc_handler(self, header_data_flags, header_data_pos):
        pass


    handlers = {
        ZType.ZRQINIT:     ( zrqinit_handler, 0 ),
        ZType.ZRINIT:      ( zrinit_handler, 0 ),
        ZType.ZSINIT:      ( zsinit_handler, 0 ),
        ZType.ZACK:        ( zack_handler, 0 ),
        ZType.ZFILE:       ( zfile_handler, 0 ),
        ZType.ZSKIP:       ( zskip_handler, 0 ),
        ZType.ZNAK:        ( znak_handler, 0 ),
        ZType.ZABORT:      ( zabort_handler, 0 ),
        ZType.ZFIN:        ( zfin_handler, 0 ),
        ZType.ZRPOS:       ( zrpos_handler, 0 ),
        ZType.ZDATA:       ( zdata_handler, 0 ),
        ZType.ZEOF:        ( zeof_handler, 0 ),
        ZType.ZFERR:       ( zferr_handler, 0 ),
        ZType.ZCRC:        ( zcrc_handler, 0 ),
    }

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
