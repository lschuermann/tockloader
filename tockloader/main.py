#!/usr/bin/env python3

import argparse
import binascii
import struct
import sys
import time

import crcmod
import serial
import serial.tools.list_ports
import serial.tools.miniterm


################################################################################
## Global Bootloader Constants
################################################################################

# "This was chosen as it is infrequent in .bin files" - immesys
ESCAPE_CHAR = 0xFC

# Commands from this tool to the bootloader.
# The "X" commands are for external flash.
COMMAND_PING               = 0x01
COMMAND_INFO               = 0x03
COMMAND_ID                 = 0x04
COMMAND_RESET              = 0x05
COMMAND_ERASE_PAGE         = 0x06
COMMAND_WRITE_PAGE         = 0x07
COMMAND_XEBLOCK            = 0x08
COMMAND_XWPAGE             = 0x09
COMMAND_CRCRX              = 0x10
COMMAND_READ_RANGE         = 0x11
COMMAND_XRRANGE            = 0x12
COMMAND_SATTR              = 0x13
COMMAND_GATTR              = 0x14
COMMAND_CRC_INTERNAL_FLASH = 0x15
COMMAND_CRCEF              = 0x16
COMMAND_XEPAGE             = 0x17
COMMAND_XFINIT             = 0x18
COMMAND_CLKOUT             = 0x19
COMMAND_WUSER              = 0x20

# Responses from the bootloader.
RESPONSE_OVERFLOW           = 0x10
RESPONSE_PONG               = 0x11
RESPONSE_BADADDR            = 0x12
RESPONSE_INTERROR           = 0x13
RESPONSE_BADARGS            = 0x14
RESPONSE_OK                 = 0x15
RESPONSE_UNKNOWN            = 0x16
RESPONSE_XFTIMEOUT          = 0x17
RESPONSE_XFEPE              = 0x18
RESPONSE_CRCRX              = 0x19
RESPONSE_READ_RANGE         = 0x20
RESPONSE_XRRANGE            = 0x21
RESPONSE_GATTR              = 0x22
RESPONSE_CRC_INTERNAL_FLASH = 0x23
RESPONSE_CRCXF              = 0x24
RESPONSE_INFO               = 0x25

# Tell the bootloader to reset its buffer to handle a new command.
SYNC_MESSAGE = bytes([0x00, ESCAPE_CHAR, COMMAND_RESET])


################################################################################
## Main Bootloader Interface
################################################################################

class TockLoader:
	# Open the serial port to the chip/bootloader
	def open (self, port):

		# Check to see if the serial port was specified or we should find
		# one to use
		if port == None:
			print('No serial port specified. Discovering attached serial devices...')
			# Start by looking for one with "tock" in the description
			ports = list(serial.tools.list_ports.grep('tock'))
			if len(ports) > 0:
				# Use the first one
				print('Using "{}"'.format(ports[0]))
				port = ports[0][0]
			else:
				# Just find any port and use the first one
				ports = list(serial.tools.list_ports.comports())
				if len(ports) == 0:
					print('No serial ports found. Is the board connected?')
					return False

				print('Found {} serial port(s).'.format(len(ports)))
				print('Using "{}"'.format(ports[0]))
				port = ports[0][0]

		# Open the actual serial port
		self.sp = serial.Serial()
		self.sp.port = port
		self.sp.baudrate = 115200
		self.sp.parity=serial.PARITY_NONE
		self.sp.stopbits=1
		self.sp.xonxoff=0
		self.sp.rtscts=0
		self.sp.timeout=0.5
		# Try to set initial conditions, but not all platforms support them.
		# https://github.com/pyserial/pyserial/issues/124#issuecomment-227235402
		self.sp.dtr = 0
		self.sp.rts = 0
		self.sp.open()

		return True


	# Tell the bootloader to save the binary blob to an address in internal
	# flash.
	#
	# This will pad the binary as needed, so don't worry about the binary being
	# a certain length.
	#
	# Returns False if there is an error.
	def flash_binary (self, binary, address):
		# Enter bootloader mode to get things started
		entered = self._enter_bootloader_mode();
		if not entered:
			return False

		# Make sure the binary is a multiple of 512 bytes by padding 0xFFs
		if len(binary) % 512 != 0:
			remaining = 512 - (len(binary) % 512)
			binary += bytes([0xFF]*remaining)

		# Time the programming operation
		then = time.time()

		flashed = self._flash_binary(address, binary)
		if not flashed:
			return False

		# And check the CRC
		crc_passed = self._check_crc(address, binary)
		if not crc_passed:
			return False

		# How long did that take
		now = time.time()
		print('Wrote {} bytes in {:0.3f} seconds'.format(len(binary), now-then))

		# All done, now run the application
		self._exit_bootloader_mode()

		return True

	# Run miniterm for receiving data from the board.
	def run_terminal (self):
		# Use trusty miniterm
		miniterm = serial.tools.miniterm.Miniterm(
			self.sp,
			echo=False,
			eol='crlf',
			filters=['default'])

		# Ctrl+c to exit.
		miniterm.exit_character = serial.tools.miniterm.unichr(0x03)
		miniterm.set_rx_encoding('UTF-8')
		miniterm.set_tx_encoding('UTF-8')

		miniterm.start()
		try:
			miniterm.join(True)
		except KeyboardInterrupt:
			pass
		miniterm.join()
		miniterm.close()


	# Query the chip's flash to determine which apps are installed.
	def list_apps (self, address, verbose):
		# Enter bootloader mode to get things started
		entered = self._enter_bootloader_mode();
		if not entered:
			return False

		# Keep track of which app this is
		app_index = 0
		start_address = address

		# Read the first range of bytes from the application section of flash
		# to get the Tock Binary Format header.
		while (True):
			header_length = 76 # Version 1
			flash = self._read_range(start_address, header_length)

			# Get all the fields from the header
			tbfh = self._parse_tbf_header(flash)

			if tbfh['version'] == 1:

				# Get name if possible
				name = self._get_app_name(start_address + tbfh['package_name_offset'], tbfh['package_name_size'])

				print('[App {}]'.format(app_index))
				print('  Name:                  {}'.format(name))
				print('  Flash Start Address:   {:#010x}'.format(start_address))
				print('  Flash End Address:     {:#010x}'.format(start_address+tbfh['total_size']-1))

				if verbose:
					print('  Flash End Address:     {:#010x}'.format(start_address+tbfh['total_size']-1))
					print('  Entry Address:         {:#010x}'.format(start_address+tbfh['entry_offset']))
					print('  Relocate Data Address: {:#010x} (length: {} bytes)'.format(start_address+tbfh['rel_data_offset'], tbfh['rel_data_size']))
					print('  Text Address:          {:#010x} (length: {} bytes)'.format(start_address+tbfh['text_offset'], tbfh['text_size']))
					print('  GOT Address:           {:#010x} (length: {} bytes)'.format(start_address+tbfh['got_offset'], tbfh['got_size']))
					print('  Data Address:          {:#010x} (length: {} bytes)'.format(start_address+tbfh['data_offset'], tbfh['data_size']))
					print('  BSS Memory Address:    {:#010x} (length: {} bytes)'.format(start_address+tbfh['bss_mem_offset'], tbfh['bss_mem_size']))
					print('  Minimum Stack Size:    {} bytes'.format(tbfh['min_stack_len']))
					print('  Minimum Heap Size:     {} bytes'.format(tbfh['min_app_heap_len']))
					print('  Minimum Grant Size:    {} bytes'.format(tbfh['min_kernel_heap_len']))
					print('  Checksum:              {:#010x}'.format(tbfh['checksum']))

				# Increment to next app and check there
				start_address += tbfh['total_size']
				app_index += 1
			elif tbfh['version'] == 0xffffffff or tbfh['version'] == 0:
				if app_index == 0:
					print('No apps currently flashed.')
				break
			else:
				print('Found Tock Binary Format header version {}'.format(tbfh['version']))
				print('This version of tockloader does not know how to parse that.')
				break

			print('')

		# Done
		self._exit_bootloader_mode()
		return True


	# Inspect the given binary and find one that matches that's already programmed,
	# then replace it on the chip. address is the starting address to search
	# for apps.
	def replace_binary (self, binary, address):
		# Enter bootloader mode to get things started
		entered = self._enter_bootloader_mode();
		if not entered:
			return False

		# Make sure the binary is a multiple of 512 bytes by padding 0xFFs
		if len(binary) % 512 != 0:
			remaining = 512 - (len(binary) % 512)
			binary += bytes([0xFF]*remaining)

		# Get the application name and properties to match it with
		tbfh = self._parse_tbf_header(binary)

		# Need its name to match to existing apps
		name_binary = binary[tbfh['package_name_offset']:tbfh['package_name_offset']+tbfh['package_name_size']];
		new_name = name_binary.decode('utf-8')

		# Time the programming operation
		then = time.time()

		# Find the matching app and make sure there is enough space
		start_address = address

		while (True):
			header_length = 76 # Version 1
			flash = self._read_range(start_address, header_length)

			# Get all the fields from the header
			atbfh = self._parse_tbf_header(flash)

			if atbfh['version'] == 1:
				# Get the name out of the app
				name = self._get_app_name(start_address+atbfh['package_name_offset'], atbfh['package_name_size'])

				# Check that the name matches the app we are trying to flash
				if name == new_name:
					# Now check that the app is the same size
					if atbfh['total_size'] == tbfh['total_size']:
						# Great we can just overwrite it!
						print('Found matching binary at address {:#010x}'.format(start_address))
						print('Replacing the binary...')
						flashed = self._flash_binary(start_address, binary)
						if not flashed:
							return False

						# And check the CRC
						crc_passed = self._check_crc(start_address, binary)
						if not crc_passed:
							return False

						break

					else:
						print('Replacement app ({} bytes) is not the same size as the existing app ({} bytes)'.format(atbfh['total_size'], tbfh['total_size']))
						print('Cannot replace this app.')
						print('In the future, we could move apps so they all can fit.')
						print('But that future isn\'t today')
						return False

				start_address += atbfh['total_size']

			else:
				# At the end of valid apps
				# We did not find a matching app.
				print('No app named "{}" found on the board.'.format(new_name))
				print('Cannot replace.')
				return False

		# How long did it take?
		now = time.time()
		print('Wrote {} bytes in {:0.3f} seconds'.format(len(binary), now-then))

		# Done
		self._exit_bootloader_mode()
		return True


	############################
	## Internal Helper Functions
	############################

	# Reset the chip and assert the bootloader select pin to enter bootloader
	# mode.
	def _toggle_bootloader_entry (self):
		# Reset the SAM4L
		self.sp.dtr = 1
		# Set RTS to make the SAM4L go into bootloader mode
		self.sp.rts = 1
		# Wait for the reset to take effect
		time.sleep(0.1)
		# Let the SAM4L startup
		self.sp.dtr = 0
		# Wait for 500 ms to make sure the bootloader enters bootloader mode
		time.sleep(0.5)
		# The select line can go back high
		self.sp.rts = 0

	# Reset the chip and assert the bootloader select pin to enter bootloader
	# mode.
	def _enter_bootloader_mode (self):
		self._toggle_bootloader_entry()

		# Make sure the bootloader is actually active and we can talk to it.
		alive = self._ping_bootloader_and_wait_for_response()
		if not alive:
			print('Error connecting to bootloader. No "pong" received.')
			print('Things that could be wrong:')
			print('  - The bootloader is not flashed on the chip')
			print('  - The DTR/RTS lines are not working')
			print('  - The serial port being used is incorrect')
			print('  - The bootloader API has changed')
			print('  - There is a bug in this script')
			return False
		return True

	# Reset the chip to exit bootloader mode
	def _exit_bootloader_mode (self):
		# Reset the SAM4L
		self.sp.dtr = 1
		# Make sure this line is de-asserted (high)
		self.sp.rts = 0
		# Let the reset take effect
		time.sleep(0.1)
		# Let the SAM4L startup
		self.sp.dtr = 0

	# Returns True if the device is there and responding, False otherwise
	def _ping_bootloader_and_wait_for_response (self):
		for i in range(30):
			# Try to ping the SAM4L to ensure it is in bootloader mode
			ping_pkt = bytes([0xFC, 0x01])
			self.sp.write(ping_pkt)

			ret = self.sp.read(2)

			if len(ret) == 2 and ret[1] == RESPONSE_PONG:
				return True
		return False

	# Setup a command to send to the bootloader and handle the response.
	def _issue_command (self, command, message, sync, response_len, response_code):
		if sync:
			self.sp.write(SYNC_MESSAGE)
			time.sleep(0.0001)

		# Generate the message to send to the bootloader
		pkt = message + bytes([ESCAPE_CHAR, command])
		self.sp.write(pkt)

		# Response has a two byte header, then response_len bytes
		ret = self.sp.read(2 + response_len)
		if len(ret) < 2:
			print('Error: No response after issuing command')
			return (False, bytes())

		if ret[0] != ESCAPE_CHAR:
			print('Error: Invalid response from bootloader (no escape character)')
			return (False, ret[0:2])
		if ret[1] != response_code:
			print('Error: Expected return type {:x}, got return {:x}'.format(response_code, ret[1]))
			return (False, ret[0:2])
		if len(ret) != 2 + response_len:
			print('Error: Incorrect number of bytes received')
			return (False, ret[0:2])

		return (True, ret[2:])

	# Write pages until a binary has been flashed. binary must have a length that
	# is a multiple of 512.
	def _flash_binary (self, address, binary):
		# Loop through the binary 512 bytes at a time until it has been flashed
		# to the chip.
		for i in range(len(binary) // 512):
			# First we write the sync string to make sure the bootloader is ready
			# to receive this page of the binary.
			self.sp.write(SYNC_MESSAGE)
			time.sleep(0.0001)

			# Now create the packet that we send to the bootloader. First four
			# bytes are the address of the page.
			pkt = struct.pack('<I', address + (i*512))

			# Next are the 512 bytes that go into the page.
			pkt += binary[i*512: (i+1)*512]

			# Escape any bytes that need to be escaped
			pkt = pkt.replace(bytes([ESCAPE_CHAR]), bytes([ESCAPE_CHAR, ESCAPE_CHAR]))

			# Add the ending escape that ends the packet and the command byte
			pkt += bytes([ESCAPE_CHAR, COMMAND_WRITE_PAGE])

			# Send this page to the bootloader
			self.sp.write(pkt)

			# We expect a two byte response
			ret = self.sp.read(2)

			# Check that we get the RESPONSE_OK return code
			if ret[0] != ESCAPE_CHAR:
				print('Error: Invalid response from bootloader when flashing page')
				return False

			if ret[1] != RESPONSE_OK:
				print('Error: Error when flashing page')
				if ret[1] == RESPONSE_BADADDR:
					print('Error: RESPONSE_BADADDR: Invalid address for page to write (address: 0x{:X}'.format(address + (i*512)))
				elif ret[1] == RESPONSE_INTERROR:
					print('Error: RESPONSE_INTERROR: Internal error when writing flash')
				elif ret[1] == RESPONSE_BADARGS:
					print('Error: RESPONSE_BADARGS: Invalid length for flash page write')
				else:
					print('Error: 0x{:X}'.format(ret[1]))
				return False

		return True

	# Read a specific range of flash.
	def _read_range (self, address, length):
		message = struct.pack('<IH', address, length)
		success, flash = self._issue_command(COMMAND_READ_RANGE, message, True, length, RESPONSE_READ_RANGE)

		if not success:
			print('Error: Could not read flash')
		return flash

	# Get the bootloader to compute a CRC
	def _get_crc_internal_flash (self, address, length):
		message = struct.pack('<II', address, length)
		success, crc = self._issue_command(COMMAND_CRC_INTERNAL_FLASH, message, True, 4, RESPONSE_CRC_INTERNAL_FLASH)

		if not success:
			if crc[1] == RESPONSE_BADADDR:
				print('Error: RESPONSE_BADADDR: Invalid address for CRC (address: 0x{:X})'.format(address))
			elif crc[1] == RESPONSE_BADARGS:
				print('Error: RESPONSE_BADARGS: Invalid length for CRC check')
			else:
				print('Error: 0x{:X}'.format(crc[1]))
			return bytes()

		return crc

	# Compares the CRC of the local binary to the one calculated by the bootloader
	def _check_crc (self, address, binary):
		# Check the CRC
		crc_data = self._get_crc_internal_flash(address, len(binary))

		# Now interpret the returned bytes as the CRC
		crc_bootloader = struct.unpack("<I", crc_data[0:4])[0]

		# Calculate the CRC locally
		crc_function = crcmod.mkCrcFun(0x104c11db7, initCrc=0, xorOut=0xFFFFFFFF)
		crc_loader = crc_function(binary, 0)

		if crc_bootloader != crc_loader:
			print('Error: CRC check failed. Expected: 0x{:04x}, Got: 0x{:04x}'.format(crc_loader, crc_bootloader))
			return False
		else:
			print('CRC check passed. Binaries successfully loaded.')
			return True

	# Retrieve bytes from the board and interpret them as a string
	def _get_app_name (self, address, length):
		if length == 0:
			return ''

		name_memory = self._read_range(address, length)
		return name_memory.decode('utf-8')

	# Parses a buffer into the Tock Binary Format header fields
	def _parse_tbf_header (self, buffer):
		out = {}

		# Read first word to get the TBF version
		out['version'] = struct.unpack('<I', buffer[0:4])[0]

		if out['version'] == 1:
			tbf_header = struct.unpack('<IIIIIIIIIIIIIIIIII', buffer[4:76])
			out['total_size'] = tbf_header[0]
			out['entry_offset'] = tbf_header[1]
			out['rel_data_offset'] = tbf_header[2]
			out['rel_data_size'] = tbf_header[3]
			out['text_offset'] = tbf_header[4]
			out['text_size'] = tbf_header[5]
			out['got_offset'] = tbf_header[6]
			out['got_size'] = tbf_header[7]
			out['data_offset'] = tbf_header[8]
			out['data_size'] = tbf_header[9]
			out['bss_mem_offset'] = tbf_header[10]
			out['bss_mem_size'] = tbf_header[11]
			out['min_stack_len'] = tbf_header[12]
			out['min_app_heap_len'] = tbf_header[13]
			out['min_kernel_heap_len'] = tbf_header[14]
			out['package_name_offset'] = tbf_header[15]
			out['package_name_size'] = tbf_header[16]
			out['checksum'] = tbf_header[17]

		return out


################################################################################
## Command Functions
################################################################################

def command_flash (args):
	# Load in all binaries
	binary = bytes([])
	for binary_filename in args.binary:
		try:
			with open(binary_filename, 'rb') as f:
				binary += f.read()
		except Exception as e:
			print('Error opening and reading "{}"'.format(binary_filename))
			sys.exit(1)

	# Temporary: append 0x00s to signal the end of valid applications
	binary += bytes([0]*8)

	# Flash the binary to the chip
	tock_loader = TockLoader()
	success = tock_loader.open(port=args.port)
	if not success:
		print('Could not open the serial port. Make sure the board is plugged in.')
		sys.exit(1)
	success = tock_loader.flash_binary(binary, args.address)
	if not success:
		print('Could not flash the binaries.')
		sys.exit(1)


def command_listen (args):
	tock_loader = TockLoader()
	success = tock_loader.open(port=args.port)
	if not success:
		print('Could not open the serial port. Make sure the board is plugged in.')
		sys.exit(1)
	tock_loader.run_terminal()


def command_list (args):
	tock_loader = TockLoader()
	success = tock_loader.open(port=args.port)
	if not success:
		print('Could not open the serial port. Make sure the board is plugged in.')
		sys.exit(1)
	tock_loader.list_apps(args.address, args.verbose)


def command_replace (args):
	# Load in all binaries
	binary = bytes([])
	try:
		with open(args.binary[0], 'rb') as f:
			binary += f.read()
	except Exception as e:
		print('Error opening and reading "{}"'.format(args.binary[0]))
		sys.exit(1)

	# Flash the binary to the chip
	tock_loader = TockLoader()
	success = tock_loader.open(port=args.port)
	if not success:
		print('Could not open the serial port. Make sure the board is plugged in.')
		sys.exit(1)
	success = tock_loader.replace_binary(binary, args.address)
	if not success:
		print('Could not replace the binary.')
		sys.exit(1)

################################################################################
## Setup and parse command line arguments
################################################################################

def main ():
	# Setup command line arguments
	parser = argparse.ArgumentParser()

	# All commands need a serial port to talk to the board
	parser.add_argument('--port', '-p',
		help='The serial port to use')

	# Support multiple commands for this tool
	subparser = parser.add_subparsers(
		title='Commands')

	flash = subparser.add_parser('flash',
		help='Flash binaries to the chip')
	flash.set_defaults(func=command_flash)
	flash.add_argument('binary',
		help='The binary file or files to flash to the chip',
		nargs='+')
	flash.add_argument('--address', '-a',
		help='Address to flash the binary at',
		type=lambda x: int(x, 0),
		default=0x30000)

	listen = subparser.add_parser('listen',
		help='Open a terminal to receive UART data')
	listen.set_defaults(func=command_listen)

	listcmd = subparser.add_parser('list',
		help='List the apps installed on the board')
	listcmd.set_defaults(func=command_list)
	listcmd.add_argument('--address', '-a',
		help='Address to flash the binary at',
		type=lambda x: int(x, 0),
		default=0x30000)
	listcmd.add_argument('--verbose', '-v',
		help='Print more information',
		action='store_true')

	replace = subparser.add_parser('replace',
		help='Replace an already flashed app with this binary')
	replace.set_defaults(func=command_replace)
	replace.add_argument('binary',
		help='The binary file to use as the replacement',
		nargs=1)
	replace.add_argument('--address', '-a',
		help='Address where apps are placed',
		type=lambda x: int(x, 0),
		default=0x30000)

	args = parser.parse_args()
	if hasattr(args, 'func'):
		args.func(args)
	else:
		print('Missing Command. Run with --help to see supported commands.')
		sys.exit(1)


if __name__ == "__main__":
    main()
