#!/usr/bin/env python3

# Copyright: FossID AB 2022

import builtins
import json
import logging
import argparse
import random
import os
import subprocess
from argparse import RawTextHelpFormatter
import sys
import traceback

# Import the new API structure
from api import WorkbenchAPI

# from dotenv import load_dotenv
logger = logging.getLogger("log")


# Keep backward compatibility by creating an alias
Workbench = WorkbenchAPI


class CliWrapper:
    """
    A class to interact with the FossID CLI.

    Attributes:
        cli_path (string): Path to the executable file "fossid"
        config_path (string): Path to the configuration file "fossid.conf"
        timeout (int): timeout for CLI expressed in seconds
    """

    # __parameters (dictionary): Dictionary of parameters passed to 'fossid-cli'
    __parameters = {}

    def __init__(self, cli_path, config_path, timeout="120"):
        self.cli_path = cli_path
        self.config_path = config_path
        self.timeout = timeout

    # Executes  fossid-cli --version
    # Returns string
    def get_version(self):
        """
        Get CLI version

        Args:
            self

        Returns:
            str
        """
        args = ["timeout", self.timeout, self.cli_path, "--version"]
        try:
            result = subprocess.check_output(args, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            return "Calledprocerr: " + str(e.cmd) + " " + str(e.returncode) + " " + str(e.output)
        # pylint: disable-next=broad-except
        except Exception as e:
            return "Error: " + str(e)

        return result

    def blind_scan(self, path, run_dependency_analysis):
        """
        Call fossid-cli on a given path in order to generate hashes of the files from that path

        Args:
            run_dependency_analysis (bool): whether to run dependency analysis or not
            path (str): path of the code to be scanned

        Returns:
            str: path to temporary .fossid file containing generated hashes
        """
        temporary_file_path = "/tmp/blind_scan_result_" + self.randstring(8) + ".fossid"
        # Create temporary file, make it empty if already exists
        # pylint: disable-next=consider-using-with,unspecified-encoding
        open(temporary_file_path, "w").close()
        my_cmd = f"timeout {self.timeout} {self.cli_path} --local --enable-sha1=1 "

        if run_dependency_analysis:
            my_cmd += " --dependency-analysis=1 "

        my_cmd += f" {path} > {temporary_file_path}"

        try:
            # pylint: disable-next=unspecified-encoding
            with open(temporary_file_path, "w") as outfile:
                subprocess.check_output(my_cmd, shell=True, stderr=outfile)
            # result = subprocess.check_output(args, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            print("Calledprocerr: " + str(e.cmd) + " " + str(e.returncode) + " " + str(e.output))
            print(traceback.format_exc())
            sys.exit()
        # pylint: disable-next=broad-except
        except Exception as e:
            print("Error: " + str(e))
            print(traceback.format_exc())
            sys.exit()

        return temporary_file_path

    @staticmethod
    def randstring(length=10):
        """
        Generate a random string of a given length

        Parameters:
            length (int): Length of the generated string

        Returns:
            str
        """
        valid_letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        return "".join((random.choice(valid_letters) for i in range(0, length)))


def parse_cmdline_args():
    """
    Parses command line arguments for the script.

    Returns:
        argparse.Namespace: An object containing the parsed command line arguments.
    """

    # Define a custom type function which will verify for empty string
    def non_empty_string(s):
        if not s.strip():
            raise argparse.ArgumentTypeError("Argument cannot be empty or just whitespace.")
        return s

    parser = argparse.ArgumentParser(
        add_help=False,
        description="Run FossID Workbench Agent",
        formatter_class=RawTextHelpFormatter,
    )
    required = parser.add_argument_group("required arguments")
    optional = parser.add_argument_group("optional arguments")

    # Add back help
    optional.add_argument(
        "-h",
        "--help",
        action="help",
        default=argparse.SUPPRESS,
        help="show this help message and exit",
    )

    required.add_argument(
        "--api_url",
        help="URL of the Workbench API instance, Ex:  https://myserver.com/api.php",
        type=non_empty_string,
        required=True,
    )
    required.add_argument(
        "--api_user",
        help="Workbench user that will make API calls",
        type=non_empty_string,
        required=True,
    )
    required.add_argument(
        "--api_token",
        help="Workbench user API token (Not the same with user password!!!)",
        type=non_empty_string,
        required=True,
    )
    required.add_argument(
        "--project_code",
        help="Name of the project inside Workbench where the scan will be created.\n"
        "If the project doesn't exist, it will be created",
        type=non_empty_string,
        required=True,
    )
    required.add_argument(
        "--scan_code",
        help="The scan code user when creating the scan in Workbench. It can be based on some env var,\n"
        "for example:  ${BUILD_NUMBER}",
        type=non_empty_string,
        required=True,
    )
    optional.add_argument(
        "--limit",
        help="Limits CLI results to N most significant matches (default: 10)",
        type=int,
        default=10,
    )
    optional.add_argument(
        "--sensitivity",
        help="Sets snippet sensitivity to a minimum of N lines (default: 10)",
        type=int,
        default=10,
    )
    optional.add_argument(
        "--recursively_extract_archives",
        help="Recursively extract nested archives. Default false.",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--jar_file_extraction",
        help="Control default behavior related to extracting jar files. Default false.",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--blind_scan",
        help="Call CLI and generate file hashes. Upload hashes and initiate blind scan.",
        action="store_true",
        default=False,
    )

    optional.add_argument(
        "--run_dependency_analysis",
        help="Initiate dependency analysis after finishing scanning for matches in KB.",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--run_only_dependency_analysis",
        help="Scan only for dependencies, no results from KB.",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--auto_identification_detect_declaration",
        help="Automatically detect license declaration inside files. This argument expects no value, not passing\n"
        "this argument is equivalent to assigning false.",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--auto_identification_detect_copyright",
        help="Automatically detect copyright statements inside files. This argument expects no value, not passing\n"
        "this argument is equivalent to assigning false.",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--auto_identification_resolve_pending_ids",
        help="Automatically resolve pending identifications. This argument expects no value, not passing\n"
        "this argument is equivalent to assigning false.",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--delta_only",
        help="""Scan only delta (newly added files from last scan).""",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--reuse_identifications",
        help="If present, try to use an existing identification depending on parameter 'identification_reuse_type'.",
        action="store_true",
        default=False,
        required=False,
    )
    optional.add_argument(
        "--identification_reuse_type",
        help="Based on reuse type last identification found will be used for files with the same hash.",
        choices=["any", "only_me", "specific_project", "specific_scan"],
        default="any",
        type=str,
        required=False,
    )
    optional.add_argument(
        "--specific_code",
        help="The scan code used when creating the scan in Workbench. It can be based on some env var,\n"
        "for example:  ${BUILD_NUMBER}",
        type=str,
        required=False,
    )
    optional.add_argument(
        "--no_advanced_match_scoring",
        help="Disable advanced match scoring which by default is enabled.",
        dest="advanced_match_scoring",
        action="store_false",
    )
    optional.add_argument(
        "--match_filtering_threshold",
        help="Minimum length, in characters, of the snippet to be considered valid after applying match filtering.\n"
        "Set to 0 to disable intelligent match filtering for current scan.",
        type=int,
        default=-1,
    )
    optional.add_argument(
        "--target_path",
        help="The path on the Workbench server where the code to be scanned is stored.\n"
        "No upload is done in this scenario.",
        type=str,
        required=False,
    )
    optional.add_argument(
        "--chunked_upload",
        help="For files bigger than 8 MB (which is default post_max_size in php.ini) uploading will be done using\n"
        "the header Transfer-encoding: chunked with chunks of 5MB.",
        action="store_true",
        default=False,
        required=False,
    )
    required.add_argument(
        "--scan_number_of_tries",
        help="""Number of calls to 'check_status' till declaring the scan failed from the point of view of the agent""",
        type=int,
        default=960,  # This means 8 hours when --scan_wait_time has default value 30 seconds
        required=False,
    )
    required.add_argument(
        "--scan_wait_time",
        help="Time interval between calling 'check_status', expressed in seconds (default 30 seconds)",
        type=int,
        default=30,
        required=False,
    )
    required.add_argument(
        "--path",
        help="Path of the directory where the files to be scanned reside",
        type=str,
        required=True,
    )

    optional.add_argument(
        "--log",
        help="specify logging level. Allowed values: DEBUG, INFO, WARNING, ERROR",
        default="ERROR",
    )

    optional.add_argument(
        "--path-result",
        help="Save results to specified path",
        type=str,
        required=False,
    )

    optional.add_argument(
        "--get_scan_identified_components",
        help="By default at the end of scanning the list of licenses identified will be retrieved.\n"
        "When passing this parameter the agent will return the list of identified components instead.\n"
        "This argument expects no value, not passing this argument is equivalent to assigning false.",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--scans_get_policy_warnings_counter",
        help="By default at the end of scanning the list of licenses identified will be retrieved.\n"
        "When passing this parameter the agent will return information about policy warnings found in this scan\n"
        "based on policy rules set at Project level.\n"
        "This argument expects no value, not passing this argument is equivalent to assigning false.",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--projects_get_policy_warnings_info",
        help="By default at the end of scanning the list of licenses identified will be retrieved.\n"
        "When passing this parameter the agent will return information about policy warnings for project,\n"
        "including the warnings counter.\n"
        "This argument expects no value, not passing this argument is equivalent to assigning false.",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--scans_get_results",
        help="By default at the end of scanning the list of licenses identified will be retrieved.\n"
        "When passing this parameter the agent will return information about policy warnings found in this scan\n"
        "based on policy rules set at Project level.\n"
        "This argument expects no value, not passing this argument is equivalent to assigning false.",
        action="store_true",
        default=False,
    )

    args = parser.parse_args()
    return args


def save_results(params, results):
    """
    Saves the scanning results to a specified path.

    Parameters:
        params (argparse.Namespace): Parsed command line parameters.
        results (dict): The scan results to be saved.
    """
    if params.path_result:
        if os.path.isdir(params.path_result):
            fname = os.path.join(params.path_result, "wb_results.json")
            try:
                with open(fname, "w") as file:
                    file.write(json.dumps(results, indent=4))
                    print(f"Results saved to: {fname}")
            except builtins.Exception:
                logger.debug(f"Error trying to write results to {fname}")
                print(f"Error trying to write results to {fname}")
        elif os.path.isfile(params.path_result):
            fname = params.path_result
            _folder = os.path.dirname(params.path_result)
            _fname = os.path.basename(params.path_result)
            if _fname:
                if not _fname.endswith(".json"):
                    try:
                        extension = _fname.split(".")[-1]
                        _fname = _fname.replace(extension, "json")
                    except (TypeError, IndexError):
                        _fname = f"{_fname.replace('.', '_')}.json"
            else:
                _fname = "wb_results.json"
            try:
                os.makedirs(_folder, exist_ok=True)
                try:
                    with open(fname, "w") as file:
                        file.write(json.dumps(results, indent=4))
                        print(f"Results saved to: {fname}")
                except builtins.Exception:
                    logger.debug(f"Error trying to write results to {fname}")
            except PermissionError:
                logger.debug(f"Error trying to create folder: {_folder}")
        else:
            logger.debug(f"Folder or file does not exist: {params.path_result}")
            try:
                fname = params.path_result
                if fname.endswith(".json"):
                    _folder = os.path.dirname(fname)
                else:
                    if "." in fname:
                        _folder = os.path.dirname(fname)
                    else:
                        _folder = fname
                    fname = os.path.join(_folder, "wb_results.json")
                try:
                    os.makedirs(_folder, exist_ok=True)
                    try:
                        with open(fname, "w") as file:
                            file.write(json.dumps(results, indent=4))
                        print(f"Results saved to: {fname}")
                    except builtins.Exception:
                        logger.debug(f"Error trying to write results to {fname}")
                except builtins.Exception:
                    logger.debug(f"Error trying to create folder: {_folder}")
            except builtins.Exception:
                logger.debug(f"Error trying to create report: {params.path_result}")


def main():
    # Retrieve parameters from command line
    params = parse_cmdline_args()
    logger.setLevel(params.log)
    f_handler = logging.FileHandler("log-agent.txt")
    logger.addHandler(f_handler)

    # Display parsed parameters
    print("Parsed parameters: ")
    for k, v in params.__dict__.items():
        print("{} = {}".format(k, v))

    if params.blind_scan:
        cli_wrapper = CliWrapper("/usr/bin/fossid-cli", "/etc/fossid.conf")
        # Display fossid-cli version just to validate the path to CLI
        print(cli_wrapper.get_version())

        # Run scan and save .fossid file as temporary file
        blind_scan_result_path = cli_wrapper.blind_scan(params.path, params.run_dependency_analysis)
        print(
            "Temporary file containing hashes generated at path: {}".format(blind_scan_result_path)
        )

    # Create Project if it doesn't exist
    workbench = Workbench(params.api_url, params.api_user, params.api_token)
    if not workbench.check_if_project_exists(params.project_code):
        workbench.create_project(params.project_code)
    # Create scan if it doesn't exist
    scan_exists = workbench.check_if_scan_exists(params.scan_code)
    if not scan_exists:
        print(f"Scan with code {params.scan_code} does not exist. Calling API to create it...")
        workbench.create_webapp_scan(params.scan_code, params.project_code, params.target_path)
    else:
        print(f"Scan with code {params.scan_code} already exists. Proceeding to upload...")
    # Handle blind scan differently from regular scan
    if params.blind_scan:
        # Upload temporary file with blind scan hashes
        print("Parsed path: ", params.path)
        workbench.upload_files(params.scan_code, blind_scan_result_path)

        # delete .fossid file containing hashes (after upload to scan)
        if os.path.isfile(blind_scan_result_path):
            os.remove(blind_scan_result_path)
        else:
            print("Can not delete the file {} as it doesn't exists".format(blind_scan_result_path))
    # Handle normal scanning (directly uploading files at given path instead of generating hashes with CLI)
    # There is no file upload when scanning from target path
    elif not params.target_path:
        if not os.path.isdir(params.path):
            # The given path is an actual file path. Only this file will be uploaded
            print("Uploading file indicated in --path parameter: {}".format(params.path))
            workbench.upload_files(params.scan_code, params.path, params.chunked_upload)
        else:
            # Get all files found at given path (including in subdirectories). Exclude directories
            print(
                "Uploading files found in directory indicated in --path parameter: {}".format(
                    params.path
                )
            )
            counter_files = 0
            for root, directories, filenames in os.walk(params.path):
                for filename in filenames:
                    if not os.path.isdir(os.path.join(root, filename)):
                        counter_files = counter_files + 1
                        workbench.upload_files(
                            params.scan_code, os.path.join(root, filename), params.chunked_upload
                        )
            print("A total of {} files uploaded".format(counter_files))
        print("Calling API scans->extracting_archives")
        workbench.extract_archives(
            params.scan_code,
            params.recursively_extract_archives,
            params.jar_file_extraction,
        )

    # If --run_only_dependency_analysis parameter is true ONLY run dependency analysis, no KB scanning
    if params.run_only_dependency_analysis:
        workbench.assert_dependency_analysis_can_start(params.scan_code)
        print("Starting dependency analysis for scan: {}".format(params.scan_code))
        workbench.start_dependency_analysis(params.scan_code)
        # Check if finished based on: scan_number_of_tries X scan_wait_time until throwing an error
        workbench.wait_for_scan_to_finish(
            "DEPENDENCY_ANALYSIS",
            params.scan_code,
            params.scan_number_of_tries,
            params.scan_wait_time,
        )
    # Run scan
    else:
        workbench.run_scan(
            params.scan_code,
            params.limit,
            params.sensitivity,
            params.auto_identification_detect_declaration,
            params.auto_identification_detect_copyright,
            params.auto_identification_resolve_pending_ids,
            params.delta_only,
            params.reuse_identifications,
            params.identification_reuse_type,
            params.specific_code,
            params.advanced_match_scoring,
            params.match_filtering_threshold,
        )
        # Check if finished based on: scan_number_of_tries X scan_wait_time until throwing an error
        workbench.wait_for_scan_to_finish(
            "SCAN", params.scan_code, params.scan_number_of_tries, params.scan_wait_time
        )

    # If --run_dependency_analysis parameter is true run also dependency analysis
    if params.run_dependency_analysis:
        workbench.assert_dependency_analysis_can_start(params.scan_code)
        print("Starting dependency analysis for scan: {}".format(params.scan_code))
        workbench.start_dependency_analysis(params.scan_code)
        # Check if finished based on: scan_number_of_tries X scan_wait_time until throwing an error
        workbench.wait_for_scan_to_finish(
            "DEPENDENCY_ANALYSIS",
            params.scan_code,
            params.scan_number_of_tries,
            params.scan_wait_time,
        )

    # When scan finished retrieve licenses list by default of if parameter --get_scan_identified_components is True call
    # scans -> get_scan_identified_components
    if params.get_scan_identified_components:
        print("Identified components: ")
        identified_components = workbench.get_scan_identified_components(params.scan_code)
        print(json.dumps(identified_components))
        save_results(params=params, results=identified_components)
        sys.exit(0)

        # projects ->  get_policy_warnings_info
    elif params.scans_get_policy_warnings_counter:
        if params.project_code is None or params.project_code == "":
            print(
                "Parameter project_code missing!\n"
                "In order for the scans->get_policy_warnings_counter to be called a project code is required."
            )
            sys.exit(1)
        print(f"Scan: {params.scan_code} policy warnings info: ")
        info_policy = workbench.scans_get_policy_warnings_counter(params.scan_code)
        print(json.dumps(info_policy))
        save_results(params=params, results=info_policy)
        sys.exit(0)
    # When scan finished retrieve project policy warnings info
    # projects ->  get_policy_warnings_info
    elif params.projects_get_policy_warnings_info:
        if params.project_code is None or params.project_code == "":
            print(
                "Parameter project_code missing!\n"
                "In order for the projects->get_policy_warnings_info to be called a project code is required."
            )
            sys.exit(1)
        print(f"Project {params.project_code} policy warnings info: ")
        info_policy = workbench.projects_get_policy_warnings_info(params.project_code)
        print(json.dumps(info_policy))
        save_results(params=params, results=info_policy)
        sys.exit(0)
    # When scan finished retrieve project policy warnings info
    # projects ->  get_policy_warnings_info
    elif params.scans_get_results:

        print(f"Scan {params.scan_code} results: ")
        results = workbench.get_results(params.scan_code)
        print(json.dumps(results))
        save_results(params=params, results=results)
        sys.exit(0)
    else:
        print("Identified licenses: ")
        identified_licenses = workbench.get_scan_identified_licenses(params.scan_code)
        print(json.dumps(identified_licenses))
        save_results(params=params, results=identified_licenses)


main()
