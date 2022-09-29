"""https://stackoverflow.com/a/58241294/6235116"""

import pefile  # type: ignore
from datetime import datetime
import logging


def get_portable_executable_info(file_path: str) -> dict:
    """
    Return a dictionary with ProductVersion and other params of portable executable.

    The Portable Executable (PE) format is a file format for executables, object code, DLLs and others used in 32-bit
    and 64-bit versions of Windows operating systems. For non PE files this error is raised:
    pefile.PEFormatError: 'DOS Header magic not found.'
    We can use it to provide the info about the tested build to the pytest report.
    """
    decoded_dict: dict = {}  # To avoid "Local variable 'pe' might be referenced before assignment" alert.
    try:
        pe = pefile.PE(file_path)  # type - class 'pefile.PE'
    except FileNotFoundError as error:
        logging.error(f"Check the provided file path: {error}. An empty dict is returned.")
        return decoded_dict
    except pefile.PEFormatError as error:
        logging.error(f"The provided file is not Portable Executable: {error}. An empty dict is returned.")
        return decoded_dict

    file_info: list = pe.FileInfo  # In my case: List of lists. len==1.
    # The nested list contains 2 elements of class 'pefile.Structure': VarFileInfo and StringFileInfo

    for structure in file_info[0]:
        if not hasattr(structure, 'StringTable'):
            logging.debug("This entry doesn't contain attribute StringTable.")
            continue

        string_table: list = structure.StringTable  # In my case:len==1. Contains 1 element of class 'pefile.Structure'
        logging.debug("This entry CONTAINS attribute StringTable.")
        encoded_dict: dict = string_table[0].entries
        decoded_dict = dict((key.decode(), value.decode()) for key, value in encoded_dict.items())

    # Add modification time from FILE_HEADER
    time_date_stamp = pe.FILE_HEADER.TimeDateStamp
    modification_time = str(datetime.fromtimestamp(time_date_stamp))
    decoded_dict["Modification_time"] = modification_time
    return decoded_dict


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
