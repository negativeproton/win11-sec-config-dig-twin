__author__ = "negativeproton"
__description__ = "This file is part of a project to monitor (some) essential security configurations of Windows 11"
__licence__ = "unlicensed"
__version__ = "1.0.0"

import string
import sys

from resources import get_actual_state

get_actual_state.main()


# Name of the file containing the output from secedit /export /cfg actual-state.inf.
ACTUAL_STATE_FILE_NAME = 'actual-state.inf'
SUBDIR_NAME = 'resources'
# Name of the file containing the name of the parameters, followed by an '=', followed by the values.
# One parameter-value pair per line.
# Example: MinimumPasswordLength = 14
TARGET_STATE_FILE_NAME = 'target-state.txt'


def main():
    actual_state = read_in_actual_state_file()
    target_state = read_in_target_state_file()

    # Process configuration parameters.
    actual_dict = fill_dict(actual_state)
    target_dict = fill_dict(target_state)

    list_compliant_parameters, counter_non_compliant_configurations, list_unknown_parameters = compare_target_and_actual_state(
        target_dict, actual_dict)

    output_compliant(list_compliant_parameters)

    output_unknown(list_unknown_parameters)

    output_statistics(target_dict, counter_non_compliant_configurations, list_compliant_parameters,
                      list_unknown_parameters)

    # Process installed programs.
    actual_dict_programs = fill_dict(actual_state, process_programs=True)
    target_dict_programs = fill_dict(target_state, process_programs=True)

    list_compliant_programs, counter_non_compliant_programs, list_unknown_programs = compare_target_and_actual_state(
        target_dict_programs, actual_dict_programs, process_programs=True)

    output_compliant(list_compliant_programs, topic='programs')

    output_unknown(list_unknown_programs, topic='programs')

    output_statistics(target_dict_programs, counter_non_compliant_programs, list_compliant_programs,
                      list_unknown_programs, topic='programs')


def compare_target_and_actual_state(target_dict, actual_dict, process_programs=False):
    """
    Compare the values of two given dictionaries using the same key, print out the non-compliant (not equal),
    count them, add compliant and unknown to a list
    @param target_dict: dictionary containing the target state
    @param actual_dict: dictionary containing the actual state
    @param process_programs: Bool variable; Are parameters getting processed? If not then programs get processed.
    @return: list of compliant programs/parameters, counter for the number of non-compliant programs/parameters, list of unknown programs/parameters
    @rtype: list, int, list
    """
    # Create a list to save the compliant values.
    list_compliant = []
    # Create a counter to count the non-compliant configurations or programs.
    counter_non_compliant = 0
    # Create a list for parameters/programs defined in the target state, that aren't in the actual state.
    list_unknown = []

    # Identify and output the non-compliant configurations/programs.
    # Save the compliant configurations/programs to the list_compliant list.
    if process_programs:
        print()
        print('The following are all non-compliant programs:')
    else:
        print('The following are all non-compliant configurations:')
    for key in target_dict.keys():
        if key not in actual_dict.keys():
            list_unknown.append(f'{key}')
        elif actual_dict[key] != target_dict[key]:
            if process_programs:
                print(
                    f'The actual version of program "{key}" is "{actual_dict[key]}", but the target version is "{target_dict[key]}"!'.replace('""','"'))
            else:
                print(
                    f'The actual configuration for "{key}" is "{actual_dict[key]}", but the target is "{target_dict[key]}"!'.replace('""','"'))
            counter_non_compliant += 1
        else:
            if process_programs:
                list_compliant.append(f'"{key}" installed in the version: "{actual_dict[key]}"'.replace('""','"'))
            else:
                list_compliant.append(f'"{key}" configured with the value: "{actual_dict[key]}"'.replace('""','"'))

    return list_compliant, counter_non_compliant, list_unknown


def output_compliant(list_compliant, topic='configurations'):
    """
    Output the given list containing complaint parameters/programs
    @param list_compliant: list of complaint parameters/programs
    @param topic: current context of function call (is it for parameters or programs)
    @return: void
    @rtype: void
    """
    print()
    if len(list_compliant) >= 1:
        print(f'The following are all compliant {topic}:')
        for e in list_compliant:
            print(e)
    elif len(list_compliant) == 0:
        print(f'There are no compliant {topic}.')
    else:
        print(f"There has been an error regarding the list of compliant {topic}. Please check both state files.")


def output_statistics(target_dict, counter_non_compliant_configurations, list_compliant,
                      list_unknown, topic='target configuration parameters'):
    """
    At the end of each round, output number and percentage of non-compliant, compliant and unknown parameter/programs
    @param target_dict: dictionary for the target state
    @param counter_non_compliant_configurations: counter for non-compliant parameters
    @param list_compliant: list for compliant parameters
    @param list_unknown: list for unknown parameters
    @param topic: string about current context (parameters or programs)
    @return: void
    @rtype: void
    """
    print()
    print(f'{len(target_dict)} {topic} were found in {TARGET_STATE_FILE_NAME}.')
    print(
        f'{counter_non_compliant_configurations} of those, {round(counter_non_compliant_configurations / len(target_dict) * 100, 1)}%, are non-compliant with the actual state (found in {ACTUAL_STATE_FILE_NAME}).')
    print(
        f'Meanwhile {len(list_compliant)} of them, {round(len(list_compliant) / len(target_dict) * 100, 1)}%, are compliant with the actual state.')
    print(
        f'{len(list_unknown)} of them, {round(len(list_unknown) / len(target_dict) * 100, 1)}%, are defined in {TARGET_STATE_FILE_NAME}, but do not appear in the actual state.')


def fill_dict(state_list, process_programs=False):
    """
    Take in a state in form of a list of strings, extract name (of parameter or program) for keys
    and parameter value/version for values
    @param state_list: list with state, e.g. target or actual
    @param process_programs: bool for current context
    @return: extracted parameters/programs (as key) and parameter value/version (as value)
    @rtype: dict
    """
    working_dict = {}
    reached_installed_programs = False
    for line in state_list:
        if not process_programs:
            if 'installed program' in line:
                # After a string containing this line installed programs are listed in target and actual state file.
                break
        else:
            if 'installed program' in line:
                reached_installed_programs = True
            if not reached_installed_programs:
                continue

        if line.count('=') != 1:
            continue
        if line.strip()[0] not in string.ascii_letters + string.digits:
            continue
        entry = line.split('=')
        working_dict[entry[0].strip()] = entry[1].strip()
    return working_dict


def read_in_actual_state_file():
    """
    Read in the actual state by opening the file named like the value of ACTUAL_STATE_FILE_NAME in a subdir of the
    working dir called the value of SUBDIR_NAME, every line as a string in one list.
    Get each line as a separate string in a python list.
    Output of secedit command, e.g. a file called actual-state.inf, should be Little-endian UTF-16 Unicode encoded
    @return: iterable with each line as an element of type str
    @rtype: list
    """
    try:
        with open(SUBDIR_NAME + '/' + ACTUAL_STATE_FILE_NAME, 'rb') as file:
            actual_state = file.read().decode('utf-16-le').splitlines()
    except FileNotFoundError:
        print(f"Error: A file named {ACTUAL_STATE_FILE_NAME} couldn't be found in a subdirectory called {SUBDIR_NAME}.")
        sys.exit(1)
    except UnicodeDecodeError:
        print(f"Error: {ACTUAL_STATE_FILE_NAME} in folder {SUBDIR_NAME} isn't encoded in Little-endian UTF-16 Unicode.")
        sys.exit(1)

    assert type(actual_state) == list, "actual_state is not of the right data type."
    return actual_state


def read_in_target_state_file():
    """
    Read in the target state by opening the file named like the value of TARGET_STATE_FILE_NAME in the current
    working dir, every line as a string in one list.
    Get each line as a separate string in a python list.
    @return: iterable with each line as an element of type str
    @rtype: list
    """
    try:
        with open(TARGET_STATE_FILE_NAME, 'r') as file:
            target_state = file.read().splitlines()
    except FileNotFoundError:
        print(f"Error: A file named {TARGET_STATE_FILE_NAME} couldn't be found in the current working directory.")
        sys.exit(1)

    assert type(target_state) == list, "target_state is not of the right data type."
    return target_state


def output_unknown(list_unknown, topic='configurations'):
    """
    Output the given list containing parameters/programs that appear in target state but not in actual state
    @param list_unknown: list of unknown parameters/programs
    @param topic: current context of function call (is it for parameters or programs)
    @return: void
    @rtype: void
    """
    print()
    if len(list_unknown) >= 1:
        print(f'Target {topic} that do not appear in the actual state are:')
        for e in list_unknown:
            print(e)
    elif len(list_unknown) == 0:
        print(f'All target {topic} were found in the actual state.')
    else:
        print(f"There has been an error regarding the list of unknown target {topic}. Please check both state files.")


if __name__ == "__main__":
    main()

