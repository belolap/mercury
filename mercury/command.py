__author__ = 'Gennady Kovalev <gik@bigur.ru>'
__copyright__ = '(c) 2015-2016 Business group for development management'
__licence__ = 'GPL'

__all__ = ['GetNetworkId']

import struct
import logging
import datetime


logger = logging.getLogger('root')


table = [0x0000, 0xd401, 0xa902, 0x7d03, 0x5304, 0x8705, 0xfa06, 0x2e07,
	 0xa608, 0x7209, 0x0f0a, 0xdb0b, 0xf50c, 0x210d, 0x5c0e, 0x880f,
	 0x4d10, 0x9911, 0xe412, 0x3013, 0x1e14, 0xca15, 0xb716, 0x6317,
	 0xeb18, 0x3f19, 0x421a, 0x961b, 0xb81c, 0x6c1d, 0x111e, 0xc51f,
	 0x9a20, 0x4e21, 0x3322, 0xe723, 0xc924, 0x1d25, 0x6026, 0xb427,
	 0x3c28, 0xe829, 0x952a, 0x412b, 0x6f2c, 0xbb2d, 0xc62e, 0x122f,
	 0xd730, 0x0331, 0x7e32, 0xaa33, 0x8434, 0x5035, 0x2d36, 0xf937,
	 0x7138, 0xa539, 0xd83a, 0x0c3b, 0x223c, 0xf63d, 0x8b3e, 0x5f3f,
	 0x3540, 0xe141, 0x9c42, 0x4843, 0x6644, 0xb245, 0xcf46, 0x1b47,
	 0x9348, 0x4749, 0x3a4a, 0xee4b, 0xc04c, 0x144d, 0x694e, 0xbd4f,
	 0x7850, 0xac51, 0xd152, 0x0553, 0x2b54, 0xff55, 0x8256, 0x5657,
	 0xde58, 0x0a59, 0x775a, 0xa35b, 0x8d5c, 0x595d, 0x245e, 0xf05f,
	 0xaf60, 0x7b61, 0x0662, 0xd263, 0xfc64, 0x2865, 0x5566, 0x8167,
	 0x0968, 0xdd69, 0xa06a, 0x746b, 0x5a6c, 0x8e6d, 0xf36e, 0x276f,
	 0xe270, 0x3671, 0x4b72, 0x9f73, 0xb174, 0x6575, 0x1876, 0xcc77,
	 0x4478, 0x9079, 0xed7a, 0x397b, 0x177c, 0xc37d, 0xbe7e, 0x6a7f,
	 0x6a80, 0xbe81, 0xc382, 0x1783, 0x3984, 0xed85, 0x9086, 0x4487,
	 0xcc88, 0x1889, 0x658a, 0xb18b, 0x9f8c, 0x4b8d, 0x368e, 0xe28f,
	 0x2790, 0xf391, 0x8e92, 0x5a93, 0x7494, 0xa095, 0xdd96, 0x0997,
	 0x8198, 0x5599, 0x289a, 0xfc9b, 0xd29c, 0x069d, 0x7b9e, 0xaf9f,
	 0xf0a0, 0x24a1, 0x59a2, 0x8da3, 0xa3a4, 0x77a5, 0x0aa6, 0xdea7,
	 0x56a8, 0x82a9, 0xffaa, 0x2bab, 0x05ac, 0xd1ad, 0xacae, 0x78af,
	 0xbdb0, 0x69b1, 0x14b2, 0xc0b3, 0xeeb4, 0x3ab5, 0x47b6, 0x93b7,
	 0x1bb8, 0xcfb9, 0xb2ba, 0x66bb, 0x48bc, 0x9cbd, 0xe1be, 0x35bf,
	 0x5fc0, 0x8bc1, 0xf6c2, 0x22c3, 0x0cc4, 0xd8c5, 0xa5c6, 0x71c7,
	 0xf9c8, 0x2dc9, 0x50ca, 0x84cb, 0xaacc, 0x7ecd, 0x03ce, 0xd7cf,
	 0x12d0, 0xc6d1, 0xbbd2, 0x6fd3, 0x41d4, 0x95d5, 0xe8d6, 0x3cd7,
	 0xb4d8, 0x60d9, 0x1dda, 0xc9db, 0xe7dc, 0x33dd, 0x4ede, 0x9adf,
	 0xc5e0, 0x11e1, 0x6ce2, 0xb8e3, 0x96e4, 0x42e5, 0x3fe6, 0xebe7,
	 0x63e8, 0xb7e9, 0xcaea, 0x1eeb, 0x30ec, 0xe4ed, 0x99ee, 0x4def,
	 0x88f0, 0x5cf1, 0x21f2, 0xf5f3, 0xdbf4, 0x0ff5, 0x72f6, 0xa6f7,
	 0x2ef8, 0xfaf9, 0x87fa, 0x53fb, 0x7dfc, 0xa9fd, 0xd4fe, 0x00ff]


class CommandError(Exception):
    pass


class Command(object):

    def __init__(self):
        self._source = None
        self._destination = None
        self._response_code = None
        self._response_data = None

    def __crc24(self, octets):
        poly = 0x01864cfb
        crc = 0x00b704ce
        for octet in octets:
            crc ^= (ord(octet) << 16)
            for i in xrange(8):
                crc <<= 1
                if crc & 0x1000000: crc ^= poly
        return crc & 0xffffff

    def __checksum(self, octets):
        s = 0
        for octet in octets:
            s += ord(octet)
        s -= 1
        return s & 0xff

    def _dump(self, data):
        if data is None:
            return 'None'
        return ' '.join([hex(ord(x))[2:].zfill(2) for x in data])

    @property
    def source(self):
        assert self._source is not None, 'please setup source address'
        return self._source

    @source.setter
    def source(self, value):
        self._source = value

    @property
    def destination(self):
        assert self._destination is not None, 'please setup dest address'
        return self._destination

    @destination.setter
    def destination(self, value):
        self._destination = value

    @property
    def _request_code(self):
        raise NotImplementedError('inherit required')

    @property
    def _request_data(self):
        raise NotImplementedError('inherit required')

    @property
    def _request_payload(self):
        return struct.pack('<B{}s'.format(
            len(self._request_data)), self._request_code, self._request_data)

    @property
    def _request_length(self):
        return struct.pack('<B', len(self._request_payload))

    @property
    def _request_crc(self):
        octets = struct.pack('<HHs', self.source, self.destination,
                             self._request_length)
        return struct.pack('<I', self.__crc24(octets))[:-1]

    @property
    def _request_checksum(self):
        return struct.pack('<B', self.__checksum(self._request_payload))

    @property
    def request(self):
        octets = struct.pack('<3sHHs{}ss'.format(len(self._request_payload)),
                             self._request_crc,
                             self.source,
                             self.destination,
                             self._request_length,
                             self._request_payload,
                             self._request_checksum)
        return octets

    # Parse response
    def parse_response(self, crc, src, dst, length, code, data, checksum):

        # Check CRC24
        octets = struct.pack('<HHB', src, dst, length)
        if struct.unpack('<I', crc + '\x00')[0] != self.__crc24(octets):
            raise CommandError('incorrect crc in response')

        # Check checksum
        octets = struct.pack('<B{}s'.format(length), code, data)
        if checksum != self.__checksum(octets):
            raise CommandError('incorrect checksum in response')

        # Check address
        if self.destination != 0x2fff and self.destination != src:
            raise CommandError('incorrect destination in response: %s' % hex(src))

        # Save source & destination
        self.source = dst
        self.destination = src

        # Load response
        try:
            self._response_code = code
            self._response_data = data
        except Exception as e:
            raise CommandError('error in response %s' % format(e))

    @property
    def result(self):
        raise NotImplementedError('inherit required')


# ------------------------------------------------------------------------------
class GetNetworkID(Command):

    _request_code = 0x86
    _request_data = ''

    @property
    def result(self):
        assert self._response_code == 0x86, \
                    'incorrect response code (%s)' % hex(self._response_code)
        assert len(self._response_data) == 2, 'incorrect address length'
        return struct.unpack('<H', self._response_data)[0]


# ------------------------------------------------------------------------------
class GetConfig(Command):

    _request_code = 0x80
    _request_data = ''

    _modes = ['Normal', 'MasterSR', 'SlaveSRT', 'SlaveSR']

    @property
    def result(self):
        assert self._response_code == 0x80, \
                    'incorrect response code (%s)' % hex(self._response_code)
        assert len(self._response_data) == 3, 'incorrect address length'
        counters, config = struct.unpack('<HB', self._response_data)

        result = {}
        result['counters'] = counters
        result['config'] = {}
        result['config']['transparent_mode'] = bool(config & 1)
        result['config']['zero_threshold'] = bool(config & 2)
        result['config']['mode'] = self._modes[(config & 252) >> 2]
        result['config']['dst'] = bool(config & 16)
        result['config']['plc_disabled'] = bool(config & 32)

        return result


# ------------------------------------------------------------------------------
class SetConfig(GetConfig):

    _request_code = 0x00

    def __init__(self, config):
        assert set(config.keys()) == {'counters', 'config'}
        assert set(config['config'].keys()) == {'transparent_mode',
                                                'zero_threshold',
                                                'mode',
                                                'dst',
                                                'plc_disabled'}
        self._config = config
        super(SetConfig, self).__init__()

    @property
    def _request_data(self):
        counters = self._config['counters']
        config = 0
        config |= self._config['config']['transparent_mode'] and 0b00000001
        config |= self._config['config']['zero_threshold']   and 0b00000010
        idx = self._modes.index(self._config['config']['mode'])
        config |= idx << 2
        config |= self._config['config']['dst']              and 0b00010000
        config |= self._config['config']['plc_disabled']     and 0b00100000
        return struct.pack('<HB', counters, config)


# ------------------------------------------------------------------------------
class GetLastPacket(Command):

    _request_code = 0x82

    def __init__(self, counter):
        self._counter = counter
        super(GetLastPacket, self).__init__()

    def _restore_value(self, base, inc, cc):
        if table[inc] == (cc * 0x100 + inc):
            return base + inc

    @property
    def _request_data(self):
        return struct.pack('<H', self._counter)

    @property
    def result(self):
        assert self._response_code == 0x82, \
                    'incorrect response code (%s)' % hex(self._response_code)
        if len(self._response_data) == 0:
            return
        assert len(self._response_data) == 13, 'incorrect response length'

        addr, dtype, base, inc, cc, level, m, h, d, month, year = \
                            struct.unpack('<HBHBBBBBBBB', self._response_data)

        result = {}
        result['level'] = level
        result['type']  = dtype

        try:
            dt = datetime.datetime(2000 + year, month + 1, d + 1, h, m)
        except ValueError, e:
            dt = None
        result['date']  = dt

        result['value'] = self._restore_value(base, inc, cc)

        return result


# ------------------------------------------------------------------------------
class GetHistory(Command):

    _request_code = 0x85

    def __init__(self, counter):
        self._counter = counter
        super(GetHistory, self).__init__()

    @property
    def _request_data(self):
        return struct.pack('<H', self._counter)

    def _restore_value(self, base, inc, cc):
        if table[inc] == (cc * 0x100 + inc):
            return base + inc

    @property
    def result(self):
        assert self._response_code == 0x85, \
                    'incorrect response code (%s)' % hex(self._response_code)
        octets = self._response_data
        if len(octets) == 0:
            return
        assert len(octets) > 2, 'incorrect response length'

        addr, = struct.unpack('<H', octets[0:2])
        assert addr == self._counter, ('response for another counter '
                                       '%s' % self._counter)

        octets = octets[2:]
        assert len(octets) % 11 == 0, 'incorrect response length'

        records = []
        for i in range(0, len(octets) / 11):
            dtype, base, inc, cc, level, m, h, d, month, year = \
                                    struct.unpack('<BHBBBBBBBB', octets[0:11])
            octets = octets[11:]
            value = self._restore_value(base, inc, cc)
            try:
                dt = datetime.datetime(2000 + year, month + 1, d + 1, h, m)
            except ValueError, e:
                dt = None
            else:
                records.append({'level': level, 'type': dtype, 'date': dt,
                                'value': value})

        return records
