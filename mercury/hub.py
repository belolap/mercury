__author__ = 'Gennady Kovalev <gik@bigur.ru>'
__copyright__ = '(c) 2015-2016 Business group of development management'
__licence__ = 'GPL'

import struct
import logging

from . import serial
from . import command


logger = logging.getLogger('energo.hub')


class OperationalError(Exception):
    pass


class Hub(object):

    def __init__(self, device, address):
        self._device = device

        self._source = 0xffff
        self._destination = address

        self._serial = serial.Serial(device)

    def execute(self, cmd):
        cmd.source = self._source
        cmd.destination = self._destination
        if not self._serial.is_open():
            try:
                self._serial.open()
                self._serial.configure()
            except serial.SerialError as e:
                raise OperationalError(e)

        self._serial.flush()

        try:
            octets = cmd.request
            logger.debug('Send: {}'.format(cmd._dump(octets)))
            self._serial.write(octets)
        except serial.SerialError as e:
            raise OperationalError(e)

        try:
            tries = 5
            recieved = False
            while not recieved and tries:
                tries -= 1
                octets = self._serial.read(8)
                if len(octets) == 0:
                    raise OperationalError('no response from device '
                                           '%s' % hex(self._destination))
                elif len(octets) < 8:
                    logger.debug('Recv: {}'.format(cmd._dump(octets)))
                    raise OperationalError('response too short in stage 1')
                elif len(octets) > 8:
                    raise OperationalError('response too long in stage 1')
                crc, src, dst, length = struct.unpack('<3sHHB', octets[:8])
                response = octets

                octets = self._serial.read(length + 1)
                if len(octets) < (length + 1):
                    raise OperationalError('response too short in stage 2')
                elif len(octets) > (length + 1):
                    raise OperationalError('response too long in stage 2')
                data = ''
                if length == 1:
                    code, checksum = struct.unpack('<BB', octets)
                elif length > 1:
                    code, data, checksum = struct.unpack(
                            '<B{}sB'.format(length - 1), octets)
                else:
                    raise OperationalError('incorrect response length')
                response += octets

                logger.debug('Recv: {}'.format(cmd._dump(response)))
                if (cmd.destination == 0x2fff and  \
                    src > 0x2f00 and src < 0x2fff):
                        self._destination = src

                if src == self._destination:
                    cmd.parse_response(crc, src, dst, length, code, data,
                                       checksum)
                    recieved = True

                else:
                    logger.debug('Recieve from another source '
                                 '({}), next try'.format(hex(src)))

            if not recieved and not tries:
                raise OperationalError('Recieve tries limit reached')

        except (serial.SerialError, command.CommandError) as e:
            raise OperationalError(e)

        return cmd.result



'''
import struct


from struct import pack, unpack
from logging import getLogger

#from energo.serial import Serial, SerialError
#from energo.commands import (GetNetworkID, GetConfig, GetLastPacket, GetHistory)






    def _send(self, command):

    def get_network_id(self):
        return self._send(GetNetworkID(self._source, self._address))

    def get_config(self):
        cmd = self._send(GetConfig(self._source, self._address))
        if cmd.destination != self._address:
            self._address = cmd.destination

        return cmd

    def get_last_packet(self, counter):
        return self._send(GetLastPacket(self._source, self._address, counter))

    def get_history(self, counter):
        return  self._send(GetHistory(self._source, self._address, counter))
'''
