"""Library to handle connection with Nexbang Gateway"""
# coding=utf-8
import socket
import json
import random
import logging
#import platform
import struct
from collections import defaultdict
#from threading import Thread
import uuid
import asyncio

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from zlib import crc32

_LOGGER = logging.getLogger(__name__)

UDP_LISTEN_PORT = 43708
CMD_DISCOVER_GW = 0x0100

SOCKET_BUFSIZE = 1024
LP_HEAD_DEC = 26724
LP_KEYTYPE_PK_DEC = 28779
LP_KEYTYPE_DK_DEC = 25707
NEXBANG_HEAD_LENGTH = 50


def gen_new_serial():
    """Generate a serial num"""
    return random.randrange(1, 10000, 1)

def _validate_data(data):
    if data is None or "data" not in data:
        _LOGGER.error('No data in response from hub %s', data)
        return False
    if 'error' in data['data']:
        _LOGGER.error('Got error element in data %s', data['data'])
        return False
    return True

def nexbang_pack(head, length, keyType, crc, sessiondId, cmd, serial):
    """Nexbang protocol"""
    #serial = gen_new_serial()
    #print("serialnum=", serial)
    byte_data = struct.pack("!HHHI32sIi", head, length, keyType, crc, sessiondId, serial, cmd)
    return byte_data


def nexbang_unpack(indata):
    head_data = struct.unpack("!HHHI32sIi", indata[0:NEXBANG_HEAD_LENGTH])
    # head_len = struct.calcsize("!HHHI32sIi")
    payload_len = len(indata) - NEXBANG_HEAD_LENGTH
    #print("payload_len:", payload_len)
    return payload_len, head_data



def gen_uuid():
    tempstr = str(uuid.uuid1())
    #print(tempstr)
    result = tempstr[0:8] + tempstr[9:13]+tempstr[14:18]+tempstr[19:23]+tempstr[24:36]
    #print (result)
    return result.encode("utf-8")

def send_request_message(transport,aesagen,smessage,rqcmd,keytype,sessionId,serial):
    if sessionId == None:
        sessionId=gen_uuid()

    aes_message=aesagen.cbc_encrypt(smessage)
    rescrc32=crc32(aes_message)
    #print("CRC32={:x}".format(rescrc32))
    if serial == None:
        serial = gen_new_serial()

    request_head =  nexbang_pack( LP_HEAD_DEC,
                                len(aes_message),
                                keytype,
                                rescrc32,
                                sessionId,
                                rqcmd,
                                serial
                              )
    send_data = request_head + aes_message
    #print("send_data:{:d} bytes-->{!r}".format(len(send_data),send_data))
    try:
        transport.write(send_data)
    except Exception as exc:
        print('The coroutine raised an exception: {!r}'.format(exc))
        return transport.close()
    else:
        return

def request_dk(transport,pkaesagen):
    REQUEST_KEY_CMD=0x0101
    sendmesg = '{"source":"homeassistant","softwareVer":"1.0","sysVer":"Linux","hardwareVer":"raspi","language":"english"}'

    return send_request_message(transport,pkaesagen,sendmesg,REQUEST_KEY_CMD, LP_KEYTYPE_PK_DEC,None,None)


class AESCrypto(object):

    def __init__(self, key, iv):
        self.AES_CBC_KEY = key
        self.AES_CBC_IV = iv

    @staticmethod
    def pkcs7_padding(data):
        if not isinstance(data, bytes):
            data = data.encode()

        padder = padding.PKCS7(128).padder()

        padded_data = padder.update(data) + padder.finalize()

        return padded_data

    @staticmethod
    def pkcs7_unpadding(padded_data):
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data)

        try:
            uppadded_data = data + unpadder.finalize()
        except ValueError:
            raise Exception('无效的加密信息!')
        else:
            return uppadded_data

    def cbc_encrypt(self, data):
        if not isinstance(data, bytes):
            data = data.encode()

        cipher = Cipher(algorithms.AES(self.AES_CBC_KEY),
                        modes.CBC(self.AES_CBC_IV),
                        backend=default_backend())
        encryptor = cipher.encryptor()

        padded_data = encryptor.update(self.pkcs7_padding(data))

        return padded_data

    def cbc_decrypt(self, data):
        if not isinstance(data, bytes):
            data = data.encode()

        cipher = Cipher(algorithms.AES(self.AES_CBC_KEY),
                        modes.CBC(self.AES_CBC_IV),
                        backend=default_backend())
        decryptor = cipher.decryptor()

        uppaded_data = self.pkcs7_unpadding(decryptor.update(data))

        uppaded_data = uppaded_data.decode()
        return uppaded_data


class NexbangAesKey(object):
    """AES kkey"""
    def __init__(self,key):
        #self.dkey = key
        self.aesAgen = AESCrypto(key.encode(), key.encode())


class NexbangClientProtocol(asyncio.Protocol):
    def __init__(self, loop, exc_calbak, ipaddr, listenport):
        self.aespkey = None
        self.aesdkey = None
        self.gatewayId = None
        self.transport = None
        self.sessionId = None
        self.calbak_fun = defaultdict(list)
        self.loop = loop
        self.serNo = None

        self.exc_calbak = exc_calbak #exc_calbak is equal to hass.async_add_job
        self.ipaddr = ipaddr
        self.listenport = listenport
        self.deviceslist = defaultdict(list)

    def connection_made(self, transport):
        self.aespkey = NexbangAesKey("khGed59B63nx6E8J").aesAgen
        self.transport = transport
        request_dk(transport, self.aespkey)
        print('connection establish')

    def connection_lost(self,exc):
        print('The server closed the connection, try to reconnect...')
        self.exc_calbak(self.reconnect())

    async def reconnect(self):
        self.transport, _= await self.loop.create_connection(lambda: self, self.ipaddr,self.listenport)

    def request_deviceslist(self):
        REQUEST_CMD = 0x0109
        sendmesg = json.dumps({"gatewayId": self.gatewayId})
        return send_request_message(self.transport,self.aesdkey,sendmesg,REQUEST_CMD,LP_KEYTYPE_DK_DEC,self.sessionId,None)

    def data_received(self,indata):
        CMD_REQUEST_KEY_RESP = 0x8101
        #print('Data received: {!r}'.format(data))
        jsonlen,headmesg =  nexbang_unpack(indata)
        #print(headmesg)
        payload = indata[ NEXBANG_HEAD_LENGTH: NEXBANG_HEAD_LENGTH + jsonlen]
        caculcrc = crc32(payload)
        keytpye = headmesg[2]
        recrc = headmesg[3]
        self.sessionId = headmesg[4]
        self.serNo = headmesg[5]
        reccmd = headmesg[6]
        if recrc != caculcrc:
            print ("CRC error!")
            return
        print("cmd={:02x},CRC:{:x},serialNO={:d}".format(reccmd,recrc,self.serNo))
        if keytpye ==  LP_KEYTYPE_PK_DEC:
            decdatata = self.aespkey.cbc_decrypt(payload)
        else:
            decdatata = self.aesdkey.cbc_decrypt(payload)
        _LOGGER.info("recv payload:{!r}".format(decdatata))
        resp = json.loads(decdatata)
        #print("dkey:{!r}".format(resp["key"]))
        if reccmd == CMD_REQUEST_KEY_RESP:
            self.aesdkey = NexbangAesKey(resp["key"]).aesAgen
            self.gatewayId = resp["gatewayId"]
            print("gatewayId:{!r}".format(self.gatewayId))
            return self.request_deviceslist()
            #No need to send heartbeat
            #return  self.exc_calbak(self.hub_send_heartbeat())#triger heartbeat cycle here
        else:
            self.process_cmd(reccmd,resp)

    def add_and_check(self,type,device):
        devicelist = self.deviceslist[type]
        for k in range(len(devicelist)):
            if device["deviceId"] in devicelist[k]["deviceId"]:
                print('Found {!r}'.format(device["deviceId"]))
                return
        self.deviceslist[type].append(device)

    def parse_devicelist(self,payloadata):
        if payloadata["status"] != 0:
            print ("gateway return error!!")
            return False
        else:
            device_types = {
                'sensor': ['10006E', '10006F'],
                'binary_sensor': ['100050', '10003Z', '10003M','10005O'],
                'switch': ['10002A', '100025'],
                'light': ['100053'],
                'doorlock':['10005R'],
                'cover': ['10009Q']}
            devices= payloadata["device_list"]
            for device in devices:
                proudId = device["deviceId"][0:6]
                #print("productId:{!r}".format(proudId))
                for devtype in device_types:
                    #print("devtype:{!r},device_types:{!r}".format(devtype,device_types[devtype]))
                    if proudId in device_types[devtype]:
                        self.add_and_check(devtype,device)
                        #print (self.deviceslist)
        return True

    #TODO:Need to fix
    async def hub_send_heartbeat(self):
        REQUEST_CMD = 0x010a
        smessage=json.dumps({"gatewayId":self.gatewayId})
        send_request_message(self.transport,self.aesdkey, smessage, REQUEST_CMD, LP_KEYTYPE_DK_DEC, self.sessionId)
        r = await asyncio.sleep(30)#heartbeat cycle is 30 second
        return self.exc_calbak(self.hub_send_heartbeat())

    def hub_send_permitjoin(self):
        REQUEST_CMD=0x0103
        smessage = json.dumps({"gatewayId": self.gatewayId,"type":"open"})
        return send_request_message(self.transport, self.aesdkey, smessage, REQUEST_CMD, LP_KEYTYPE_DK_DEC, self.sessionId,None)

    def write_to_hub(self,REQUEST_CMD,jsondata):
        _LOGGER.info(json.loads(jsondata))
        return send_request_message(self.transport, self.aesdkey, jsondata, REQUEST_CMD, LP_KEYTYPE_DK_DEC,self.sessionId,None)

    def default_responde(self):
        RESPONDE_CMD=0x8000
        smessage = json.dumps({"status":0})
        return send_request_message(self.transport, self.aesdkey, smessage, RESPONDE_CMD, LP_KEYTYPE_DK_DEC,self.sessionId, self.serNo)

    def process_cmd(self, icmd, jsonpayload):
        CMD_REQUEST_DEVICELIST_RESP = 0x8109
        CMD_ATTRIBUTE_RESP = 0x8108
        if icmd == CMD_REQUEST_DEVICELIST_RESP:
            self.parse_devicelist(jsonpayload)
        elif icmd == CMD_ATTRIBUTE_RESP:
            self.default_responde()
            did = jsonpayload["deviceId"]
            if self.calbak_fun[did] is not None:
                print("++++++++++++++++++")
                self.calbak_fun[did](jsonpayload)
        return




class PyNexbangHub(object):
    """PyNexbang."""

    def __init__(self, callback_func, interface,loop):

        self.callback_func = callback_func

        self._interface = interface

        self.loop = loop
        self.gateways = defaultdict(list)


    async def initial_session(self, sessionclass,ipaddr, listenport):
        transport, protocol = await self.loop.create_connection(lambda: sessionclass, ipaddr, listenport)

    def discover_gateways(self, interface):
        """Discover gateways using broadcast"""
        _socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        _socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _socket.settimeout(5.0)
        if interface != 'any':
            _socket.bind((interface, 0))
        sessid = "abcdef123456".encode("utf-8")
        payload = '{"gatewayId":"whois"}'.encode("utf-8")
        serial = gen_new_serial()
        udp_proto = nexbang_pack(LP_HEAD_DEC,
                                 len(payload),
                                 LP_KEYTYPE_PK_DEC,
                                 0,
                                 sessid,
                                 CMD_DISCOVER_GW,
                                 serial
                                 )
        send_data = udp_proto + payload
        # print(send_data)

        try:
            _socket.sendto(send_data,
                           ("255.255.255.255", UDP_LISTEN_PORT))
            _LOGGER.info("send to multicast_address success!")
            while True:
                data, ip_add = _socket.recvfrom(1024)
                if len(data) is None:
                    continue
                print(data)
                jsonlen, _ = nexbang_unpack(data)
                resp = json.loads(data[NEXBANG_HEAD_LENGTH:NEXBANG_HEAD_LENGTH + jsonlen].decode())

                if resp["status"] != 0:
                    _LOGGER.error("Response faile!")
                    continue

                port = resp["port"]

                self.gateways[resp["gatewayId"]] = NexbangClientProtocol(self.loop, self.callback_func, ip_add[0], port),ip_add[0], port

                _LOGGER.info('Nexbang Gateway %s found at IP %s tcp port:%d', resp["gatewayId"], ip_add[0], port)
                #_socket.close()
                #return resp["gatewayId"]
        except socket.timeout:
            _LOGGER.info("Gateway discovery finished in 5 seconds")
            _socket.close()

if __name__ == '__main__':
    print('Hello Nexgo!')
