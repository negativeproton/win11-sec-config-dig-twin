__author__ = "negativeproton"
__description__ = "This file is part of a project to monitor (some) essential security configurations of Windows 11"
__licence__ = "unlicensed"
__version__ = "1.0.0"

"""
    # Usage example:
    # Specify the registry key path and value name.
    registry_key_path = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    value_name = "EnableMulticast"

    # Read the registry value.
    value = read_registry_key(registry_key_path, value_name)

    if value is not None:
        print(f"Value of '{value_name}' in '{registry_key_path}': {value}")
    else:
        print("Registry key or value not found.")
"""

import winreg


def read_registry_key(key_path, value_name):
    """
    Read out and return the value of a given parameter (and its path)
    @param key_path: path to the parameter (key) in the Windows registry
    @param value_name: name of the parameter
    @return: value of the parameter
    @rtype: str
    """
    key = None
    try:
        # Open the registry key.
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)

        # Read the registry value.
        value, _ = winreg.QueryValueEx(key, value_name)

        return value

    except FileNotFoundError:
        print(f'Please note that the registry key "{value_name}" does not exist in {key_path}.\n')
    except Exception as e:
        print(f"An error occurred: {e}")

    finally:
        # Always close the registry key.
        if key is not None:
            winreg.CloseKey(key)

