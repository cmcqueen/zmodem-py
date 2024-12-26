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

HEADER_TYPES = set(( ZBIN, ZHEX, ZBIN32 ))

RX_BUFFER_SIZE = 256
ZRINIT_INTERVAL_S = 2
FINAL_OO_TIMEOUT_S = 3

# Exit code
class ExitCode(IntEnum):
    NORMAL          = 0
    SERIAL_PORT     = 1
    SERVER_ABORT    = 2


# Subpacket identifiers
class ZSubpacketType(IntEnum):
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
    sys.exit(ExitCode.SERIAL_PORT)

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

    def open(self, filename, flags=None):
        self.close()
        self.f = open(filename, 'wb')
        return self.f

    def close(self):
        if self.f:
            try:
                self.f.close()
            except Exception:
                pass
            self.f = None

    def write(self, data):
        if self.f:
            return self.f.write(data)
        else:
            return None

class Zmodem:
    #l_rx_raw = logging.getLogger('zmodem.rx.raw')
    #l_tx_raw = logging.getLogger('zmodem.tx.raw')
    class HeaderDetectState(IntEnum):
        WAIT_HEADER_START   = 0
        WAIT_ZDLE           = 1
        WAIT_HEADER_TYPE    = 2

    class RxState(IntEnum):
        WAIT_HEADER         = 0
        GET_HEADER          = 1
        GET_SUBPACKET       = 2
        WAIT_FINAL_O        = 3
        WAIT_FINAL_OO       = 4

    def __init__(self, zf):
        self.zf = zf
        self.input_queue = deque()
        self.header_detect_state = self.HeaderDetectState.WAIT_HEADER_START
        self.rx_state = self.RxState.WAIT_HEADER
        self.get_subpacket_gen = None
        self.l_rx_raw = logging.getLogger('zmodem.rx.raw')
        self.l_tx_raw = logging.getLogger('zmodem.tx.raw')
        self.file_pos = 0
        self.cancel_count = 0
        self.exit_code = ExitCode.NORMAL

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
    def escape_decode(escapeval):
        if escapeval & 0x60 == 0x40:
            return escapeval ^ 0x40
        elif escapeval == 0x6C:
            return 0x7F
        elif escapeval == 0x6D:
            return 0xFF
        else:
            raise ValueError

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
                    escapeval = yield
                    try:
                        byteval = Zmodem.escape_decode(escapeval)
                    except ValueError:
                        return escapeval
                x = x * 256 + byteval
            byteval = yield result
            if byteval == ZDLE:
                escapeval = yield
                try:
                    byteval = Zmodem.escape_decode(escapeval)
                except ValueError:
                    return escapeval
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
        a valid CRC has been received. It yields tuple (subpacket_type, subpacket_data)."""
        try:
            logging.getLogger('rx.subpacket').debug('Start')
            # Get data, possibly escaped.
            g = Zmodem.get_bin_escaped(2**32)
            next(g)
            subpacket_data = bytearray()
            subpacket_type = 0xFF
            try:
                while True:
                    byteval = yield
                    result = g.send(byteval)
                    if result is not None:
                        subpacket_data.append(result)
            except StopIteration as e:
                subpacket_type = e.value
            logging.getLogger('rx.subpacket.data').debug(bytes_as_hex_str(subpacket_data))

            # Get 2 binary values, possibly escaped.
            try:
                g = Zmodem.get_bin_escaped(1, 2)
                next(g)
                crc16_val = None
                while crc16_val is None:
                    byteval = yield
                    crc16_val = g.send(byteval)
            except StopIteration as e:
                raise ValueError(e.value)
        except ValueError:
            return False

        logging.getLogger('rx.subpacket.crc').debug('{:04X}'.format(crc16_val))
        subpacket_type_byte = bytes((subpacket_type,))
        crc16_calc_val = CRC_16(subpacket_data + subpacket_type_byte)
        if crc16_val == crc16_calc_val:
            yield (subpacket_type, subpacket_data)
        else:
            logging.getLogger('rx.subpacket.crc').warning('{:04X}; calc {:04X}'.format(crc16_val, crc16_calc_val))

    @staticmethod
    def swap32(x):
        return (((x & 0x000000FF) << 24) |
                ((x & 0x0000FF00) <<  8) |
                ((x & 0x00FF0000) >>  8) |
                ((x & 0xFF000000) >> 24))

    def send_hex_header(self, header_type, header_data_flags, header_data_pos):
        logging.getLogger('tx.header').info('type {!r}; flags {:08X}; pos {:08X}'.format(header_type, header_data_flags, header_data_pos))
        header_data_pos_swap = self.swap32(header_data_pos)
        header_data = header_data_flags | header_data_pos_swap
        header_all_data = struct.pack('>BI', header_type, header_data)
        crc16_calc = CRC_16(header_all_data)
        crc16_calc_bytes = struct.pack('>H', crc16_calc)
        header_all_hex = codecs.encode(header_all_data + crc16_calc_bytes, 'hex')
        header = b'**\x18B' + header_all_hex + b'\r\n'
        # Send XON, except for ZACK, ZFIN.
        if header_type != ZType.ZACK and header_type != ZType.ZFIN:
            header += b'\x11'
        self.l_tx_raw.debug(bytes_as_hex_str(header))
        self.l_tx_raw.debug(bytes_as_printable_str(header))
        self.zf.write(header)

    def process_header_type(self, header_type, header_data_flags, header_data_pos):
        self.header_type = header_type
        if header_type in self.header_handlers:
            handler_fn, pos_mask = self.header_handlers[header_type]
            handler_fn(self, header_data_flags, header_data_pos & pos_mask)

    def process_header(self, header_data):
        header_type_val, header_data_flags = struct.unpack(">BI", header_data)
        header_data_pos = self.swap32(header_data_flags)
        header_type = ZType(header_type_val)
        #logging.getLogger('rx.header.type').info('{!r}'.format(header_type))
        logging.getLogger('rx.header').info('type {!r}; flags {:08X}; pos {:08X}'.format(header_type, header_data_flags, header_data_pos))
        self.process_header_type(header_type, header_data_flags, header_data_pos)

    def process_subpacket(self, subpacket_type, subpacket_data):
        subpacket_type_enum = ZSubpacketType(subpacket_type)
        logging.getLogger('rx.subpacket').info('type {!r}'.format(subpacket_type_enum))

        if self.header_type in self.subpacket_handlers_pre:
            handler_fn = self.subpacket_handlers_pre[self.header_type]
            logging.getLogger('rx.subpacket.process').debug('call {!r}'.format(handler_fn))
            handler_fn(self, subpacket_type, subpacket_data)

        if subpacket_type_enum == ZSubpacketType.ZCRCE:
            self.rx_state = self.RxState.WAIT_HEADER
        elif subpacket_type_enum == ZSubpacketType.ZCRCG:
            self.rx_state = self.RxState.GET_SUBPACKET
        elif subpacket_type_enum == ZSubpacketType.ZCRCQ:
            self.send_hex_header(ZType.ZACK, 0, self.file_pos)
            self.rx_state = self.RxState.GET_SUBPACKET
        elif subpacket_type_enum == ZSubpacketType.ZCRCW:
            self.send_hex_header(ZType.ZACK, 0, self.file_pos)
            self.rx_state = self.RxState.WAIT_HEADER

        if self.header_type in self.subpacket_handlers_post:
            handler_fn = self.subpacket_handlers_post[self.header_type]
            logging.getLogger('rx.subpacket.process').debug('call {!r}'.format(handler_fn))
            handler_fn(self, subpacket_type, subpacket_data)

    def detect_header(self, byteval):
        """Detect the start of a header"""
        if byteval == ZPAD:
            self.header_detect_state = self.HeaderDetectState.WAIT_ZDLE
        elif self.header_detect_state == self.HeaderDetectState.WAIT_ZDLE:
            if byteval == ZDLE:
                self.header_detect_state = self.HeaderDetectState.WAIT_HEADER_TYPE
            else:
                self.header_detect_state = self.HeaderDetectState.WAIT_HEADER_START
        elif self.header_detect_state == self.HeaderDetectState.WAIT_HEADER_TYPE:
            self.header_detect_state = self.HeaderDetectState.WAIT_HEADER_START
            if byteval in HEADER_TYPES:
                return byteval
        return None

    def process_input(self):
        """Process input in self.input_queue."""
        # logging.getLogger('rx.q').debug(bytes_as_hex_str(self.input_queue))
        while self.input_queue:
            byteval = self.input_queue.popleft()
            if byteval == CAN:
                self.cancel_count += 1
                if self.cancel_count >= 5:
                    sys.exit(ExitCode.SERVER_ABORT)
            else:
                self.cancel_count = 0

            result = self.detect_header(byteval)
            if result is not None:
                if byteval == ZHEX:
                    self.rx_state = self.RxState.GET_HEADER
                    self.get_header_gen = self.get_hex_header()
                    next(self.get_header_gen)
                elif byteval == ZBIN:
                    self.rx_state = self.RxState.GET_HEADER
                    self.get_header_gen = self.get_bin_header()
                    next(self.get_header_gen)
                else:
                    self.rx_state = self.RxState.WAIT_HEADER
            elif self.rx_state == self.RxState.GET_HEADER:
                try:
                    result = self.get_header_gen.send(byteval)
                    if result is not None:
                        self.rx_state = self.RxState.WAIT_HEADER
                        self.process_header(result)
                except StopIteration:
                    self.rx_state = self.RxState.WAIT_HEADER
            elif self.rx_state == self.RxState.GET_SUBPACKET:
                if self.get_subpacket_gen is None:
                    self.get_subpacket_gen = self.get_subpacket()
                    next(self.get_subpacket_gen)
                try:
                    result = self.get_subpacket_gen.send(byteval)
                    if result is not None:
                        logging.getLogger('rx.subpacket').debug('Got result')
                        self.rx_state = self.RxState.WAIT_HEADER
                        self.get_subpacket_gen = None
                        subpacket_type, subpacket_data = result
                        self.process_subpacket(subpacket_type, subpacket_data)
                        logging.getLogger('rx.subpacket').debug('Next state {!r}'.format(self.rx_state))
                except StopIteration:
                    logging.getLogger('rx.subpacket').debug('stop')
                    self.rx_state = self.RxState.WAIT_HEADER
                    self.get_subpacket_gen = None
            elif self.rx_state == self.RxState.WAIT_FINAL_O:
                if byteval == ord(b'O'):
                    self.rx_state = self.RxState.WAIT_FINAL_OO
                elif time.monotonic() - self.event_time >= FINAL_OO_TIMEOUT_S:
                    sys.exit(self.exit_code)
            elif self.rx_state == self.RxState.WAIT_FINAL_OO:
                if byteval == ord(b'O') or time.monotonic() - self.event_time >= FINAL_OO_TIMEOUT_S:
                    sys.exit(self.exit_code)


class ZmodemReceive(Zmodem):
    def __init__(self, zf, file_writer):
        super().__init__(zf)
        self.file_writer = file_writer
        self.do_periodic_zrinit = True
        self.event_time = 0

    def periodic_send_zrinit(self):
        if self.do_periodic_zrinit:
            now_time = time.monotonic()
            if now_time - self.event_time >= ZRINIT_INTERVAL_S:
                self.send_hex_header(ZType.ZRINIT, 0, RX_BUFFER_SIZE)
                self.event_time = now_time

    def process(self):
        self.periodic_send_zrinit()
        self.read_input()
        self.process_input()

    def zrqinit_handler(self, header_data_flags, header_data_pos):
        self.send_hex_header(ZType.ZRINIT, 0, RX_BUFFER_SIZE)

    def zsinit_handler(self, header_data_flags, header_data_pos):
        self.rx_state = self.RxState.GET_SUBPACKET

    def zfile_handler(self, header_data_flags, header_data_pos):
        self.file_pos = 0
        self.rx_state = self.RxState.GET_SUBPACKET
        self.do_periodic_zrinit = False

    def zskip_handler(self, header_data_flags, header_data_pos):
        pass

    def znak_handler(self, header_data_flags, header_data_pos):
        pass

    def zabort_handler(self, header_data_flags, header_data_pos):
        self.send_hex_header(ZType.ZFIN, 0, 0)
        self.rx_state = self.RxState.WAIT_FINAL_O
        self.event_time = time.monotonic()
        self.exit_code = ExitCode.SERVER_ABORT

    def zfin_handler(self, header_data_flags, header_data_pos):
        self.send_hex_header(ZType.ZFIN, 0, 0)
        self.rx_state = self.RxState.WAIT_FINAL_O
        self.event_time = time.monotonic()

    def zdata_handler(self, header_data_flags, header_data_pos):
        self.file_pos = header_data_pos
        self.rx_state = self.RxState.GET_SUBPACKET

    def zeof_handler(self, header_data_flags, header_data_pos):
        self.file_writer.close()
        self.send_hex_header(ZType.ZRINIT, 0, RX_BUFFER_SIZE)

    def zferr_handler(self, header_data_flags, header_data_pos):
        # Unlikely for sender to send this. Treat it like an abort.
        pass

    def zcrc_handler(self, header_data_flags, header_data_pos):
        pass

    def zfreecnt_handler(self, header_data_flags, header_data_pos):
        # Alternatively: Return actual filesystem free space.
        self.send_hex_header(ZType.ZACK, 0, 0)

    def zcommand_handler(self, header_data_flags, header_data_pos):
        # ZCOMMAND is insecure. We should not implement it. Unless we implement "safe" commands.
        self.send_hex_header(ZType.ZCOMPL, 0, 1)


    def zsinit_subpacket_pre_handler(self, subpacket_type, subpacket_data):
        pass

    def zfile_subpacket_pre_handler(self, subpacket_type, subpacket_data):
        pass

    def zdata_subpacket_pre_handler(self, subpacket_type, subpacket_data):
        self.file_writer.write(subpacket_data)
        self.file_pos += len(subpacket_data)

    def zsinit_subpacket_post_handler(self, subpacket_type, subpacket_data):
        pass

    def zfile_subpacket_post_handler(self, subpacket_type, subpacket_data):
        # Alternatively, send ZSKIP or ZFERR if the filename is bad or transfer options are unsuitable.
        self.file_writer.open('test.bin')
        self.send_hex_header(ZType.ZRPOS, 0, 0)

    def zdata_subpacket_post_handler(self, subpacket_type, subpacket_data):
        pass

    header_handlers = {
        ZType.ZRQINIT:     ( zrqinit_handler, 0 ),
        ZType.ZSINIT:      ( zsinit_handler, 0 ),
        ZType.ZFILE:       ( zfile_handler, 0 ),
        ZType.ZSKIP:       ( zskip_handler, 0 ),
        ZType.ZNAK:        ( znak_handler, 0 ),
        ZType.ZABORT:      ( zabort_handler, 0 ),
        ZType.ZFIN:        ( zfin_handler, 0 ),
        ZType.ZDATA:       ( zdata_handler, 0xFFFFFFFF ),
        ZType.ZEOF:        ( zeof_handler, 0xFFFFFFFF ),
        ZType.ZFERR:       ( zferr_handler, 0 ),
        ZType.ZCRC:        ( zcrc_handler, 0xFFFFFFFF ),
        ZType.ZFREECNT:    ( zfreecnt_handler, 0 ),
        ZType.ZCOMMAND:    ( zcommand_handler, 0 ),
    }

    subpacket_handlers_pre = {
        ZType.ZSINIT:      zsinit_subpacket_pre_handler,
        ZType.ZFILE:       zfile_subpacket_pre_handler,
        ZType.ZDATA:       zdata_subpacket_pre_handler,
    }

    subpacket_handlers_post = {
        ZType.ZSINIT:      zsinit_subpacket_post_handler,
        ZType.ZFILE:       zfile_subpacket_post_handler,
        ZType.ZDATA:       zdata_subpacket_post_handler,
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
        with serial.Serial(args.serialport, args.bitrate, timeout=0) as s:

            rz = ZmodemReceive(s, FileWriter())
            logging.getLogger('info').info('Get data')
            # Get input data
            while True:
                rz.process()
                #time.sleep(0.005)
    except KeyboardInterrupt:
        logging.getLogger('zmodem').info('Stopping')
        raise
    finally:
        rz.close()

if __name__ == '__main__':
    main()
