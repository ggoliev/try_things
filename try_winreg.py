import winreg
import logging
from re import search


def registry_open_key(registry_path: str) -> winreg.HKEYType | False:
    """
    Opens specified in registry_path key for winreg operations.

    :param registry_path: str. Any format of the path to the registry, like Computer\HKEY_CURRENT_USER\Software\Folder
    :return: a PyHKEY key, open for winreg operations or False if key cannot be open
    """

    # extract registry folder name from the full path: HKEY_CURRENT_USER etc.
    hkey_folder: str = search(r"HKEY[^\\]*", registry_path)[0]  # type: ignore
    logging.debug(f"The registry folder is {hkey_folder=}")

    # find the folder name in the provided path
    path_to_sub_key: str = search(f"(?<={hkey_folder}\\\).*", registry_path)[0]  # type: ignore
    logging.debug(f"The sub path is {path_to_sub_key=}")

    # Need to use the getattr, because hkey is string, so I can't get access to winreg."HKEY_CURRENT_USER."
    hkey_constant: int = getattr(winreg, hkey_folder)  # = winreg.HKEY_CURRENT_USER (for example)
    logging.debug(f"{hkey_constant=} for {hkey_folder}")

    opened_key = False  # To avoid "Local variable might be referenced before assignment" alert.
    try:
        opened_key = winreg.OpenKeyEx(hkey_constant, path_to_sub_key, access=winreg.KEY_WRITE)
        logging.debug(f"Successfully opened: {registry_path}")
    except FileNotFoundError as error:
        logging.error(f"Check the provided registry path: {error}")
    except WindowsError as error:  # The same as PermissionError
        logging.error(f"Run the script as admin: {error}")

    return opened_key


def registry_create_value(registry_path: str, value_type: str, value_name: str, value_data: str, ) -> bool:
    """
    Creates value with provided name, type (REG_SZ etc) and data.

    :param registry_path: str.
    :param value_type: str. REG_SZ for String Value, REG_BINARY for Binary Value etc.
    :param value_name: str.
    :param value_data: str.
    :return: True if the value was created, False otherwise.
    """

    # Checking that value_type parameter has the right format.
    value_type_int = 0  # To avoid "Local variable might be referenced before assignment" alert.
    try:
        value_type_int: int = getattr(winreg, value_type)
        logging.debug("Value_type successfully checked")
    except AttributeError as error:
        logging.error(f"Check the provided value_type parameter: {error}")

    key_is_ready = registry_open_key(registry_path)
    if not key_is_ready:
        logging.error("Key is not open")
        return False
    else:
        logging.debug(f"Ready to work with the key {registry_path}")
        # Creating a new value_name and value_data
        winreg.SetValueEx(key_is_ready, value_name, 0, value_type_int, value_data)
        logging.debug(f"{value_name} was created")
        return True


def registry_delete_value(registry_path: str, value_name: str) -> bool:
    """
    Removes a named value from a registry key.

    :param registry_path: str
    :param value_name: str
    :return: True if the value was removed, False otherwise
    """

    key_is_ready = registry_open_key(registry_path)
    if not key_is_ready:
        logging.error("Key is not open")
        return False
    else:
        logging.debug(f"Ready to work with the key {registry_path}")
        try:
            winreg.DeleteValue(key_is_ready, value_name)
            logging.debug(f"Key {value_name} deleted")
            return True
        except FileNotFoundError as error:
            logging.error(f"Check the provided value_name parameter: {error}")
            return False


def registry_create_key():
    """
    ToDo
    :return:
    """

    pass


def registry_delete_key():
    """
    ToDo
    :return:
    """

    pass


my_path1 = r"Computer\HKEY_CURRENT_USER\Software\Zscaler\GG"
my_path2 = r"Computer\HKEY_LOCAL_MACHINE\Software\Zscaler Inc."

registry_delete_value(my_path1, "GG_name")


if __name__ == '__main__':
    FORMAT = "%(funcName)s %(levelname)s: %(message)s"
    logging.basicConfig(format=FORMAT, level=logging.DEBUG)
