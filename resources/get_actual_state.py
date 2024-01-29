__author__ = "negativeproton"
__description__ = "This file is part of a project to monitor (some) essential security configurations of Windows 11"
__licence__ = "unlicensed"
__version__ = "1.0.0"

import os
import subprocess
import sys


class PlatformError(Exception):
    message = 'Error: Execution has to happen on a Windows 11 computer.'
    pass


try:
    if os.name != 'nt':
        raise PlatformError
except PlatformError:
    print(PlatformError.message)
    sys.exit(1)  # Terminate with error code.

from resources import readregistry

SECEDIT_OUTPUT_FILE_NAME = 'actual-state.inf'
SUBDIR_NAME = 'resources'
MPCOMPUTERSTATUS_IMPORTANT_PARAMETERS: list[str] = ["AntispywareEnabled", "AMServiceEnabled", "AntivirusEnabled",
                                                    "BehaviorMonitorEnabled", "IsTamperProtected",
                                                    "RealTimeProtectionEnabled"]
FIREWALLSTATUS_IMPORTANT_PARAMETERS: list[str] = ["Enabled", "NotifyOnListen", "LogFileName", "LogMaxSizeKilobytes",
                                                  "LogAllowed", "LogBlocked"]
FILTER_OUT = ['Microsoft', 'Python']


def main():
    refresh_secedit_output()

    mp_parameter_and_value_dic = extract_parameters_and_values('Get-MpComputerStatus',
                                                               MPCOMPUTERSTATUS_IMPORTANT_PARAMETERS)
    fw_parameter_and_value_dic = extract_parameters_and_values('Get-NetFirewallProfile -Name Domain',
                                                               FIREWALLSTATUS_IMPORTANT_PARAMETERS)

    # Get parameters from registry.
    # Define the paths with the key names.
    regpath_regkey_dict: dict[str, str] = {r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient": "EnableMulticast"}
    regpath_regkey_dict[r"SYSTEM\CurrentControlSet\Services\WinHTTPAutoProxySvc"] = "Start"

    regkey_regvalue_dict: dict[str, str] = {}

    for key in regpath_regkey_dict.keys():
        # Read the registry value
        registry_key_path = key
        value_name = regpath_regkey_dict[key]
        value = readregistry.read_registry_key(registry_key_path, value_name)

        if value is not None:
            regkey_regvalue_dict[value_name] = value

    # installed programs.
    installed_programs_powershell_output = get_installed_programs()
    installed_programs_name_version_dict: dict[str, str] = extract_installed_programs(
        installed_programs_powershell_output)

    # Open the file in 'utf-16-le' encoding for writing, since the export from secedit uses that encoding.
    # Write out to the file.
    with open(SUBDIR_NAME + '/' + SECEDIT_OUTPUT_FILE_NAME, 'a', encoding='utf-16-le') as file:
        # Write '{parameter} = {value}' to the file
        file.write("[Firewall]\n")
        for key in fw_parameter_and_value_dic.keys():
            file.write(f"{key} = {fw_parameter_and_value_dic[key]}\n")
        file.write("[Anti-Malware]\n")
        for key in mp_parameter_and_value_dic.keys():
            file.write(f"{key} = {mp_parameter_and_value_dic[key]}\n")
        file.write("[custom registry value extraction]\n")
        for key in regkey_regvalue_dict.keys():
            file.write(f"{key} = {regkey_regvalue_dict[key]}\n")
        file.write("[installed program (= program version)]\n")
        for key in installed_programs_name_version_dict.keys():
            file.write(f"{key} = {installed_programs_name_version_dict[key]}\n")


def get_installed_programs() -> str:
    """
    Read in Uninstall from registry via running a powershell command to get a str of installed software (with version)
    @return: the output of the powershell command
    @rtype: str
    """
    cmd = r'Get-ItemProperty -Path ‘HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*’ | Select-Object DisplayName, DisplayVersion, Publisher | ConvertTo-Csv -NoTypeInformation'
    result = subprocess.run(['powershell', cmd], capture_output=True, text=True)
    result = result.stdout
    return result


def extract_installed_programs(result) -> dict[str, str]:
    """
    Read in the result of get_installed_programs(), omit lines using the blacklist FILTER_OUT,
    then extract software name and its corresponding version
    @param result: the output of the powershell command to read Uninstall from registry
    @return: software name (as key) and the installed version (as value)
    @rtype: dict
    """
    result_list = result.split("\n")
    result_list.pop(0)

    extract = []
    for e in result_list:
        blocked = False
        if e == ',,':
            continue
        if e == '':
            continue
        for blocked_word in FILTER_OUT:
            if blocked_word.lower() in e.lower():
                blocked = True
        if not blocked:
            extract.append(e)

    sw_name_version_dict = {}
    for e in extract:
        line_list = e.split(',')
        software_name = line_list[0].replace('"', '')
        software_version = line_list[1].replace('"', '')
        sw_name_version_dict[software_name] = software_version
    return sw_name_version_dict


def extract_parameters_and_values(ps_command, parameter_list) -> dict[str, str]:
    """
    Execute the given ps command and process the command output to get and return the parameter values
    @param ps_command: powershell command to run in order to get system information
    @param parameter_list: list of parameters that are to be extracted
    @return: parameters (as keys) with their corresponding values (as values)
    @rtype: dict
    """
    dic = {}
    result = subprocess.run(['powershell', ps_command], capture_output=True, text=True)
    output = result.stdout
    del result
    # example output:
    # "AntivirusEnabled        : True"
    output_list = output.split('\n')
    for line in output_list:
        if ':' not in line:
            continue
        list_of_parameter_and_value = line.split(':')
        parameter = list_of_parameter_and_value[0].strip('\t').strip()
        value = list_of_parameter_and_value[1].strip('\t').strip()
        if parameter in parameter_list:
            dic[parameter] = value
    return dic


def refresh_secedit_output():
    """
    Delete the existing file that contains secedit output (export of security configuration database).
    Generate and save a new, up-to-date one in its place.
    @return: void
    @rtype: void
    """
    # Overwrite a file with that name without prompting.
    cmd = fr"del {SUBDIR_NAME}\{SECEDIT_OUTPUT_FILE_NAME}"
    os.system(cmd)
    print('Status of secedit execution:')
    # Write current state in a file in a subdirectory.
    # Outputs important information to stdout/stderr.
    os.system(f'secedit /export /cfg {SUBDIR_NAME}/{SECEDIT_OUTPUT_FILE_NAME}')
    print()


if __name__ == "__main__":
    main()
