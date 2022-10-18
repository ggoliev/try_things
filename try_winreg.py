import winreg
import logging
from re import search
from try_admin import is_running_as_admin


def registry_open_key(registry_path: str) -> winreg.HKEYType | None:
    """
    Opens specified in registry_path key for winreg operations.

    HKEY_CURRENT_USER folder can be open with the regular running, others (like HKEY_LOCAL_MACHINE) - should be run
    as admin.

    :param registry_path: str. Any format of the path to the registry, like Computer\HKEY_CURRENT_USER\Software\Folder
    :return: a PyHKEY key, open for winreg operations or None if key cannot be open
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

    try:
        opened_key = winreg.OpenKeyEx(hkey_constant, path_to_sub_key, access=winreg.KEY_WRITE)
        logging.info(f"Successfully opened: {registry_path}")
        return opened_key  # <-- we can return it immediately

    except FileNotFoundError as error:
        logging.error(f"Check the provided registry path: {error}")
    except PermissionError as error:  # The same as  WindowsError
        logging.error(f"Can't open {hkey_folder} without admin privileges: {error}")
    # Here is end of function; if function ends with nothing, it implicitly returns `None`


def registry_create_value(registry_path: str, value_type: str, value_name: str, value_data: str, ) -> bool:
    """
    Creates value with provided name, type (REG_SZ etc) and data.

    :param registry_path: str.
    :param value_type: str. REG_SZ for String Value, REG_BINARY for Binary Value etc.
    :param value_name: str.
    :param value_data: str.
    :return: True if the value was created, False otherwise.
    """

    key_is_ready = registry_open_key(registry_path)
    if not key_is_ready:
        logging.error("Key is not open. Stop the function.")
        return False
    logging.debug(f"Ready to work with the key {registry_path}.")

    value_type_int = getattr(winreg, value_type, 0)
    try:
        winreg.SetValueEx(key_is_ready, value_name, 0, value_type_int, value_data)
        logging.info(f"{value_name} with type {value_type} and {value_data} was created.")
        return True
    except TypeError as error:
        logging.error(f"Most likely you need to check the value_type parameter: {error}")
        # Zero provided as __type: int -> "Objects of type 'str' can not be used as binary registry values"
        return False
    except PermissionError as error:
        if not is_running_as_admin():  # This flow is for HKEY_CURRENT_USER only. Another folders will fail on open_key.
            logging.error(f"{error}. Try to run as admin. But in case of Anti-tampering you will fail again.")
            return False
        logging.error(f"The script was run as admin, but still '{error}'. So the Anti-tampering is working!")
        return False


def registry_delete_value(registry_path: str, value_name: str) -> bool:
    """
    Removes a named value from a registry key.

    :param registry_path: str
    :param value_name: str
    :return: True if the value was removed, False otherwise
    """

    key_is_ready = registry_open_key(registry_path)
    if not key_is_ready:
        logging.error("Key is not open. Stop the function.")
        return False
    logging.debug(f"Ready to work with the key {registry_path}")

    try:
        winreg.DeleteValue(key_is_ready, value_name)
        logging.info(f"Key {value_name} deleted")
        return True
    except FileNotFoundError as error:
        logging.error(f"Check the provided value_name parameter: {error}")
        return False
    except PermissionError as error:
        if not is_running_as_admin():  # This flow is for HKEY_CURRENT_USER only. Another folders will fail on open_key.
            logging.error(f"{error}. Try to run as admin. But in case of Anti-tampering you will fail again.")
            return False
        logging.error(f"The script was run as admin, but still '{error}'. So the Anti-tampering is working!")
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


if __name__ == '__main__':
    FORMAT = "%(funcName)s %(levelname)s: %(message)s"
    logging.basicConfig(format=FORMAT, level=logging.DEBUG)
