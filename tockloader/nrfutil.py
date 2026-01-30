"""
Interface for boards using nrfutil.
"""

import logging
import os
import subprocess
import tempfile

from .board_interface import BoardInterface
from .exceptions import TockLoaderException


class NrfUtil(BoardInterface):
    def __init__(self, args):
        # Must call the generic init first.
        super().__init__(args)

        # Check for nrfutil
        try:
            # Prevent output to stdout/stderr unless debug?
            subprocess.check_call(
                ["nrfutil", "--version"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            raise TockLoaderException("nrfutil not found. Please install nrfutil.")
        except subprocess.CalledProcessError:
            raise TockLoaderException("Error running nrfutil.")

        # Check for device subcommand
        try:
            subprocess.check_call(
                ["nrfutil", "device", "--help"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError:
            raise TockLoaderException(
                "nrfutil device subcommand not found. Please run 'nrfutil install device'."
            )

    def _run_nrfutil(self, args):
        cmd = ["nrfutil"] + args
        logging.debug("Running: {}".format(" ".join(cmd)))
        try:
            subprocess.check_call(
                cmd, stdout=subprocess.DEVNULL if not self.args.debug else None
            )
        except subprocess.CalledProcessError as e:
            raise TockLoaderException(
                "nrfutil command failed: {}".format(" ".join(cmd))
            )

    def open_link_to_board(self):
        # Check if a device is connected
        if not self.attached_board_exists():
            raise TockLoaderException("No nRF device attached.")

    def flash_binary(self, address, binary, pad=False):
        """
        Write using nrfutil.
        """
        # Convert to hex
        hex_content = self._bytes_to_intel_hex(address, binary)

        # Create temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".hex", delete=False) as tmp:
            tmp.write(hex_content)
            tmp_path = tmp.name

        try:
            self._run_nrfutil(["device", "program", "--firmware", tmp_path])
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def read_range(self, address, length):
        """
        Read using nrfutil.
        """
        tmp_path = None
        try:
            # Temp file for output
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp_path = tmp.name

            # Using 'device memory read' based on online docs
            self._run_nrfutil(
                [
                    "device",
                    "memory",
                    "read",
                    "--address",
                    f"{address:#x}",
                    "--length",
                    str(length),
                    "--output-file",
                    tmp_path,
                ]
            )

            with open(tmp_path, "rb") as f:
                return f.read()
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.remove(tmp_path)

    def clear_bytes(self, address):
        """
        Clear bytes by writing 0xFFs.
        """
        logging.debug("Clearing bytes starting at {:#0x}".format(address))

        binary = bytes([0xFF] * 8)
        self.flash_binary(address, binary)

    def attached_board_exists(self):
        """
        Check if an nRF device is attached.
        """
        try:
            # list devices and check output
            output = subprocess.check_output(["nrfutil", "device", "list", "--json"], stderr=subprocess.DEVNULL)
            # If output contains something valid, we assume yes.
            # But checking content is better. For now, if command succeeds, assume yes?
            # No, command succeeds even if no devices.
            # We need to parse JSON.
            # However, imports are restricted? No, I can import json.
            import json
            devices = json.loads(output)
            # Depends on JSON structure. Usually a list or dict with list.
            if isinstance(devices, list):
                return len(devices) > 0
            elif isinstance(devices, dict):
                 # Maybe "devices": [...]
                 if "devices" in devices:
                     return len(devices["devices"]) > 0

            # If we can't parse or empty, assume False
            return False
        except:
            return False

    def _bytes_to_intel_hex(self, address, binary):
        """
        Convert bytes to Intel HEX format string.
        """
        out = ""
        offset = 0
        upper_address_set = None

        while offset < len(binary):
            # Calculate current absolute address
            curr_address = address + offset

            # Check if we need to set the extended linear address (upper 16 bits)
            upper_address = (curr_address >> 16) & 0xFFFF
            if upper_address != upper_address_set:
                # Emit Extended Linear Address Record (Type 04)
                # :02000004UUUUCC
                record = bytes(
                    [
                        0x02,
                        0x00,
                        0x00,
                        0x04,
                        (upper_address >> 8) & 0xFF,
                        upper_address & 0xFF,
                    ]
                )
                checksum = (-(sum(record) & 0xFF)) & 0xFF
                out += ":{:02X}{:04X}{:02X}{:04X}{:02X}\n".format(
                    2, 0, 4, upper_address, checksum
                )
                upper_address_set = upper_address

            # Data Record (Type 00)
            length = min(16, len(binary) - offset)

            # Ensure we don't cross a 64KB boundary in a single record
            lower_address = curr_address & 0xFFFF
            if lower_address + length > 0x10000:
                length = 0x10000 - lower_address

            data_chunk = binary[offset : offset + length]

            # :LLAAAATT[DD...]CC
            header = bytes(
                [length, (lower_address >> 8) & 0xFF, lower_address & 0xFF, 0x00]
            )
            checksum_input = header + data_chunk
            checksum = (-(sum(checksum_input) & 0xFF)) & 0xFF

            data_str = "".join(["{:02X}".format(b) for b in data_chunk])
            out += ":{:02X}{:04X}{:02X}{}{:02X}\n".format(
                length, lower_address, 0, data_str, checksum
            )

            offset += length

        # End of File Record (Type 01)
        out += ":00000001FF\n"
        return out
