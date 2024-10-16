import argparse
import serial
import time

"""
run by using: py serial_console.py -D COM4
Note: You will likely need to specify a different serial port than COM4

you will first need to build and flash the c program.
"""

parser = argparse.ArgumentParser("Simple python serial console.")
parser.add_argument("-dst", "-D", dest="port_dest", type=str, nargs=1, help="Destination serial port")
args = parser.parse_args()


DEVICE_PROMPT = "> "

def is_ready(line):
	return len(line) > len("SYNC // FIRMWARE READY") and "SYNC // FIRMWARE READY" in line

def is_complete(line):
	return line == ""

def query_device_v2(ser, inputError = False):
	in_line = ""
	listening = False
	if not inputError:
		while not listening:
			next = ser.read(size=1).decode("utf-8", errors="replace")
			if next:
				in_line += next
				if DEVICE_PROMPT in in_line:
					time.sleep(0.05)
					print(DEVICE_PROMPT, end="")
					listening = True
				elif next == "\n":
					if in_line != "\n": # sometimes it just wants to print just the new line character, this is just to fix that
						print(in_line[:-1])
					in_line = ""
	else:
		print(DEVICE_PROMPT, end="")
	cmd = input()

	if len(cmd) > 127:
		print(f"The input length cannot be longer that 127 characters, your input is {len(cmd)} characters long.")
		return query_device_v2(ser, True)
	elif len(cmd) == 0:
		return query_device_v2(ser, True)
	if (cmd == "exit"):
		return True
	ser.write((cmd + "\n").encode("ascii"))
	return False


def sync_device(ser):
	# Little block to dump any pre-existing input on the serial port.  This may
	#  (depending on when/how console script is run) include boot dump info for
	#  device which is not of any great interest to us right now.  Keep scrapping
	#  input until 200ms go by with no further input.
	ser.reset_input_buffer()
	time.sleep(0.2)
	while ser.in_waiting > 0:
		ser.reset_input_buffer()
		time.sleep(0.2)

	print(f"Reboot device to synchronize.")
	while True:
		line = ser.readline().decode("utf-8", errors="replace")
		if is_ready(line):
			print(f"\nSYNC // FIRMWARE READY")
			return
		else:
			print(".", end="", flush=True)




com = serial.Serial(port=args.port_dest[0], baudrate=115200, timeout=10, write_timeout=10)
if not com.is_open:
	print(f"Failed to connect to serial port {args.port_dest[0]}")
else:
	print(f"Console connected on serial port {args.port_dest[0]}")

sync_device(com)
complete = False
while not complete:
	complete = query_device_v2(com)


