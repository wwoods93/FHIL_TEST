import pyvisa


# Create a resource manager using the Python backend
rm = pyvisa.ResourceManager()
# List available instruments
print(rm.list_resources())
# Open a specific instrument resource (replace with your device details)
inst = rm.open_resource('TCPIP::192.168.1.102::INSTR')
# Send a command to the instrument
response = inst.query("*IDN?")
print(response)

inst.write('MEAS:VOLT:DC?\n')
voltage = inst.read()
print(f"Voltage: {voltage}")
inst.close()