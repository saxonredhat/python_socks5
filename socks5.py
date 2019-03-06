import logging
import select
import socket
import struct
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler

logging.basicConfig(level=logging.DEBUG)
SOCKS_VERSION = 5
PROXY_PORT=6666


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
	pass


class SocksProxy(StreamRequestHandler):
	username = 'username'
	password = 'password'

	def handle(self):
		logging.info(u'接收来自SOCK5的客户端连接 %s:%s' % self.client_address)

		# greeting header
		# read and unpack 2 bytes from a client
		header = self.connection.recv(2)
		version, nmethods = struct.unpack("!BB", header)

		# socks 5
		assert version == SOCKS_VERSION
		assert nmethods > 0

		# get available methods
		methods = self.get_available_methods(nmethods)

		# accept only USERNAME/PASSWORD auth
		if 2 not in set(methods):
			# close connection
			self.server.close_request(self.request)
			return

		# send welcome message
		self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, 2))

		if not self.verify_credentials():
			return

		# request
		version, cmd, _, address_type = struct.unpack("!BBBB", self.connection.recv(4))
		assert version == SOCKS_VERSION
		logging.info(u'版本:%s,命令:%s,_:%s,地址类型:%s' % (version, cmd, _, address_type))

		if address_type == 1:  # IPv4
			address = socket.inet_ntoa(self.connection.recv(4))
		elif address_type == 3:  # Domain name
			
			domain_length = self.connection.recv(1)[0]
			logging.info(u'收到需要代理访问的域名的长度 %s' % domain_length)
			#domain_length = ord(self.connection.recv(1)[0])
			address = self.connection.recv(domain_length)
			logging.info(u'收到需要代理访问的域名 %s' % address)

		port = struct.unpack('!H', self.connection.recv(2))[0]

		# reply
		try:
			logging.info('cmd:%s' % cmd)	
			if cmd == 1:  # CONNECT
				remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				logging.info(u'地址:%s,端口:%s' % (address, port))	
				remote.connect((address, port))
				bind_address = remote.getsockname()
				logging.info(u'绑定的地址:%s' % bind_address[0])
				logging.info(u'连接到 %s %s' % (address, port))
			else:
				self.server.close_request(self.request)

			addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
			port = bind_address[1]
			sock5_address_type=1
			reply = struct.pack("!BBBBIH", SOCKS_VERSION, 0, 0, sock5_address_type,addr, port)
			logging.info(u'地址:%s,端口:%s,应答:%s' % (addr,port,reply))

		except Exception as err:
			logging.error(err)
			# return connection refused error
			reply = self.generate_failed_reply(sock5_address_type, 5)

		self.connection.sendall(reply)

		# establish data exchange
		if reply[1] == 0 and cmd == 1:
			logging.info(u'准备进入数据交互阶段')
			self.exchange_loop(self.connection, remote)

		self.server.close_request(self.request)

	def get_available_methods(self, n):
		methods = []
		for i in range(n):
			methods.append(ord(self.connection.recv(1)))
		return methods

	def verify_credentials(self):
		version = ord(self.connection.recv(1))
		assert version == 1

		username_len = ord(self.connection.recv(1))
		username = self.connection.recv(username_len).decode('utf-8')

		password_len = ord(self.connection.recv(1))
		password = self.connection.recv(password_len).decode('utf-8')

		if username == self.username and password == self.password:
			logging.info(u'认证成功')
			# success, status = 0
			response = struct.pack("!BB", version, 0)
			self.connection.sendall(response)
			return True

		# failure, status != 0
		response = struct.pack("!BB", version, 0xFF)
		self.connection.sendall(response)
		self.server.close_request(self.request)
		return False

	def generate_failed_reply(self, address_type, error_number):
		return struct.pack("!BBBBIH", SOCKS_VERSION, error_number, 0, address_type, 0, 0)

	def exchange_loop(self, client, remote):
		logging.info(u'进入数据交互')

		while True:

			logging.info(u'远程SOCK5客户端: %s,远程服务器: %s' % (client,remote))
			# wait until client or remote is available for read
			r, w, e = select.select([client, remote], [], [client, remote])
			logging.info(u'读:%s,写:%s,异常:%s' % (r, w, e))
			for ss in r:
				print(u"远程节点信息:::: %s,%s"% ss.getpeername())

			if client in r:
				data = client.recv(4096)
				logging.info('		client data: %s' % data)
				if remote.send(data) <= 0:
					break

			if remote in r:
				data = remote.recv(4096)
				logging.info('		remote data: %s' % data)
				if client.send(data) <= 0:
					break


if __name__ == '__main__':
	logging.info(u'启动代理服务:%s' % PROXY_PORT) 
	with ThreadingTCPServer(('0.0.0.0',PROXY_PORT), SocksProxy) as server:
		server.serve_forever()
