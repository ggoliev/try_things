import winreg
import logging
from re import search

FORMAT = "%(funcName)s %(levelname)s: %(message)s"
logging.basicConfig(format = FORMAT, level=logging.DEBUG)


def registry_names_extract(registry_path: str) -> tuple:
    """
    Extracts from the provided registry path the name of HKEY_folder and rest of the path.

    :param registry_path: str. Any format of the path to the registry, like Computer\HKEY_CURRENT_USER\Software\Folder
    :return: Tuple with 2 strings: HKEY_folder and the path that goes after HKEY_folder
    """

    # extract registry folder name from the full path: HKEY_CURRENT_USER etc.
    hkey_folder: str = search(r"HKEY[^\\]*", registry_path)[0]  # type: ignore
    logging.debug(f"The registry folder is {hkey_folder=}")

    # find the folder name in the provided path
    path_to_sub_key: str = search(f"(?<={hkey_folder}\\\).*", registry_path)[0]  # type: ignore
    logging.debug(f"The path is {path_to_sub_key=}")

    return hkey_folder, path_to_sub_key


def registry_open_key(registry_path: str) -> winreg.HKEYType | bool:
    """
    Opens provided key by path for winreg operations.

    :param registry_path:
    :return: a PyHKEY key, open for winreg operations or False if key cannot be open
    """

    # extract registry folder name from the full path: HKEY_CURRENT_USER etc.
    hkey_folder: str = search(r"HKEY[^\\]*", registry_path)[0]  # type: ignore
    logging.debug(f"The registry folder is {hkey_folder=}")

    # find the folder name in the provided path
    path_to_sub_key: str = search(f"(?<={hkey_folder}\\\).*", registry_path)[0]  # type: ignore
    logging.debug(f"The path is {path_to_sub_key=}")

    # Need to use the getattr, because hkey is string, so I can't get access to winreg."HKEY_CURRENT_USER."
    hkey_constant: int = getattr(winreg, hkey_folder)  # = winreg.HKEY_CURRENT_USER (for example)
    logging.debug(f"{hkey_constant=} for {hkey_folder}")

    opened_key = False  # To avoid "Local variable might be referenced before assignment" alert.
    try:
        opened_key = winreg.OpenKeyEx(hkey_constant, path_to_sub_key, access=winreg.KEY_WRITE)
        logging.debug(f"Successfully opened: {registry_path}")
    except FileNotFoundError as error:
        logging.error(f"Check the provided registry path: {error}")

    return opened_key


def registry_create_key(registry_path: str, new_key_name: str) -> bool:
    """
    Creates a key (folder) in the provided registry key.

    :param registry_path: Where do you want to kreate key
    :param new_key_name:
    :return: True if the key was created, False otherwise.
    """

    hkey: str = registry_names_extract(registry_path)[0]
    path_to_sub_key: str = registry_names_extract(registry_path)[1]

    # Need to use the getattr, because hkey is string, so I can't get access to winreg."HKEY_CURRENT_USER."
    hkey_constant: int = getattr(winreg, hkey)  # = winreg.HKEY_CURRENT_USER (for example)
    logging.debug(f"{hkey_constant=}")

    opened_key = 0  # To avoid "Local variable might be referenced before assignment" alert.
    try:
        opened_key = winreg.OpenKeyEx(hkey_constant, path_to_sub_key)
        logging.debug(f"Successfully opened: {registry_path}")
    except FileNotFoundError as error:
        logging.error(f"Check the provided registry path: {error}")

    try:
        # Creating a new key (folder)
        new_key = winreg.CreateKey(opened_key, new_key_name)
        logging.debug(f"{new_key} is created")

        # Note If hkey is not closed using this method (or via hkey.Close()), it is closed when the hkey object is
        # destroyed by Python. Do we need to close it explicitly?
        winreg.CloseKey(new_key)
        logging.debug("Closing new_key was successful!")

        return True
    except WindowsError as e:
        logging.error(f"run as admin: {e}")
        return False


def registry_create_value(registry_path: str, value_type: str, value_name: str, value_data: str, ) -> bool:
    """
    Creates value with provide name, type (REG_SZ etc) and data.

    :param registry_path: str.
    :param value_type: str. REG_SZ for String Value, REG_BINARY for Binary Value etc.
    :param value_name: str.
    :param value_data: str.
    :return: True if the value was created, False otherwise.
    """
    hkey: str = registry_names_extract(registry_path)[0]
    path_to_sub_key: str = registry_names_extract(registry_path)[1]

    # Need to use the getattr, because hkey is string, so I can't get access to winreg."HKEY_CURRENT_USER."
    hkey_constant: int = getattr(winreg, hkey)  # = winreg.HKEY_CURRENT_USER (for example)
    logging.debug(f"{hkey_constant=}")

    # Open the specified key with write access
    opened_key = 0  # To avoid "Local variable might be referenced before assignment" alert.
    try:
        opened_key = winreg.OpenKeyEx(hkey_constant, path_to_sub_key, access=winreg.KEY_WRITE)
        logging.debug(f"Successfully opened: {registry_path}")
    except FileNotFoundError as error:
        logging.error(f"Check the provided registry path: {error}")

    # Checking that value_type parameter has the right format.
    value_type_int = 0
    try:
        value_type_int: int = getattr(winreg, value_type)
        logging.debug("Value_type successfully checked")
    except AttributeError as error:
        logging.error(f"Check the value_type parameter: {error}")

    # Creating a new value_name and value_data
    winreg.SetValueEx(opened_key, value_name, 0, value_type_int, value_data)
    logging.debug(f"{value_name} was created")
    return True


def registry_delete_key(registry_path: str):
    key_is_ready = registry_open_key(registry_path)
    if not key_is_ready:
        logging.error("Key is not open")
        return False
    else:
        logging.debug("Ready to work with the key")


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
        try:
            logging.debug(f"Ready to work with the key {registry_path}")
            winreg.DeleteValue(key_is_ready, value_name)
            logging.debug("Key is deleted")
            return True
        except FileNotFoundError as error:
            logging.error(f"Check the provided value_name: {error}")
            return False


my_path1 = r"Computer\HKEY_CURRENT_USER\Software\Zscaler\GG"
my_path2 = r"Computer\HKEY_LOCAL_MACHINE\Software\Zscaler Inc."

registry_delete_value(my_path1, "GG_name")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
