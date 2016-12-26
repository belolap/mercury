__author__ = 'Gennady Kovalev <gik@bigur.ru>'
__copyright__ = '(c) 2015-2016 Business group for development management'
__licence__ = 'GPL'

import os
import time
import errno
import select
import termios
import logging


logger = logging.getLogger('energo.serial')


class SerialError(Exception):
    pass


class Serial(object):

    __timeout__ = 8
    __baudrate__ = termios.B38400

    def __init__(self, device):
        self._device = device
        self._fh = None
        self._is_open = False

    def __del__(self):
        self.close()

    def _dump_bin(self, octet):
        s = bin(octet)[2:].zfill(32)
        parts = []
        parts.append(s[0:8])
        parts.append(s[8:16])
        parts.append(s[16:24])
        parts.append(s[24:])
        return ' '.join(parts)

    def _dump_hex(self, data):
        if data is None:
            return 'None'
        res = []
        for x in data:
            if isinstance(x, str):
                x = ord(x)
            res.append(hex(x)[2:].zfill(2))
        return ' '.join(res)

    def open(self):
        if not self._is_open:
            try:
                self._fh = os.open(self._device,
                                   os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
            except Exception as e:
                raise SerialError('can\'t open port: {}'.format(e))
            self._is_open = True

    def is_open(self):
        return self._is_open

    def configure(self):
        logger.debug('Configure serial port')
        if not self._is_open:
            raise SerialError('port is not open')

        try:
            orig_attrs = termios.tcgetattr(self._fh)
            iflag, oflag, cflag, lflag, ispeed, ospeed, cc = orig_attrs
        except termios.error, e:
            raise SerialError('can\'t configure port: {}'.format(e))

        # Speed
        ispeed = ospeed = self.__baudrate__


        # Set iflag
        logger.debug('......')
        logger.debug('...... &~  BRKINT: {}'.format(self._dump_bin(termios.BRKINT)))
        logger.debug('...... &~   ICRNL: {}'.format(self._dump_bin(termios.ICRNL)))
        logger.debug('...... &~   INPCK: {}'.format(self._dump_bin(termios.INPCK)))
        logger.debug('...... &~  ISTRIP: {}'.format(self._dump_bin(termios.ISTRIP)))
        logger.debug('...... &~    IXON: {}'.format(self._dump_bin(termios.IXON)))
        iflag &= ~(termios.BRKINT|termios.ICRNL|termios.INPCK|termios.ISTRIP|termios.IXON)
        logger.debug('......             -----------------------------------')
        logger.debug('......      iflag: {}'.format(self._dump_bin(iflag)))

        # Set oflag
        logger.debug('......')
        logger.debug('...... &~   OPOST: {}'.format(self._dump_bin(termios.OPOST)))
        oflag &= ~(termios.OPOST)
        logger.debug('......             -----------------------------------')
        logger.debug('......      oflag: {}'.format(self._dump_bin(oflag)))

        # Set cflag
        logger.debug('...... |      CS8: {}'.format(self._dump_bin(termios.CS8)))
        cflag |= termios.CS8
        logger.debug('......             -----------------------------------')
        logger.debug('......      cflag: {}'.format(self._dump_bin(cflag)))

        # Set lflag
        logger.debug('......')
        logger.debug('...... &~    ECHO: {}'.format(self._dump_bin(termios.ECHO)))
        logger.debug('...... &~  ICANON: {}'.format(self._dump_bin(termios.ICANON)))
        logger.debug('...... &~  IEXTEN: {}'.format(self._dump_bin(termios.IEXTEN)))
        logger.debug('...... &~    ISIG: {}'.format(self._dump_bin(termios.ISIG)))
        lflag &= ~(termios.ECHO|termios.ICANON|termios.IEXTEN|termios.ISIG)
        logger.debug('......             -----------------------------------')
        logger.debug('......      lflag: {}'.format(self._dump_bin(lflag)))

        # Setup CC
        cc[termios.VMIN] = 1
        cc[termios.VTIME] = self.__timeout__

        if [iflag, oflag, cflag, lflag, ispeed, ospeed, cc] != orig_attrs:
            termios.tcsetattr(self._fh, termios.TCSANOW, \
                              [iflag, oflag, cflag, lflag, ispeed, ospeed, cc])
        logger.debug('......')

    def write(self, octets):
        if not self._is_open:
            raise SerialError('port is not open')

        timeout = time.time() + self.__timeout__

        l = len(octets)
        remained = octets
        while l > 0:
            try:
                n = os.write(self._fh, remained)
                timeleft = timeout - time.time()
                if timeleft < 0:
                    raise SerialError('write timeout')
                _, ready, _ = select.select([], [self._fh], [], timeleft)
                if not ready:
                    raise SerialError('write timeout')
                remained = remained[n:]
                l = l - n
            except OSError as e:
                if e.errno != errno.EAGAIN:
                    raise SerialError('write failed: {}'.format(e))
        return len(octets)

    def read(self, size=1):
        if not self._is_open:
            raise SerialError('port is not open')
        recieved = bytearray()
        while len(recieved) < size:
            ready,_,_ = select.select([self._fh],[],[], self.__timeout__)
            if not ready:
                break
            buf = os.read(self._fh, size-len(recieved))
            if not buf:
                raise SerialError('no data from port')
            recieved.extend(buf)
        return bytes(recieved)

    def flush(self):
        if not self._is_open:
            raise SerialError('port is not open')
        termios.tcflush(self._fh, termios.TCIOFLUSH)

    def close(self):
        if self._is_open:
            try:
                os.close(self._fh)
            except:
                pass
        self._is_open = False
