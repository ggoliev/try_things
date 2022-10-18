import os
import ctypes
import logging


def is_admin() -> bool:
    """
    Checks if the script was run by admin or regular user

    :return: True if run by admin, None if not
    :rtype:
    """

    class UnknownOs(Exception):
        pass
    os_name: str = os.name
    logging.debug(f"OS name is {os_name}")
    if os_name == "nt":
        run_as_admin: int = ctypes.windll.shell32.IsUserAnAdmin()
        # returns 1 if admin, 0 if regular user
        logging.debug(f"{run_as_admin=}")
        return bool(run_as_admin)
    elif os_name == "posix":
        uid: int = os.getuid()
        # returns 0 if admin, 501 (or another number) if regular user
        logging.debug(f"{uid=}")
        return uid == 0
    else:
        raise UnknownOs(f"Unrecognised {os_name=}")


if __name__ == '__main__':
    FORMAT = "%(funcName)s %(levelname)s: %(message)s"
    logging.basicConfig(format=FORMAT, level=logging.DEBUG)
