# Workbench-Agent

## Overview

The **Workbench-Agent** is a Python script used for integrating with **FossID Workbench** in CI/CD pipelines. It leverages the
Workbench API in order to upload code, scan code and retrieve various types of results.

There are various scenarios for integrating the Workbench into a CI/CD pipeline, each with its own pros and cons. Those 
scenarios are presented in the Workbench documentation.

At this moment the Workbench-Agent supports two scenarios: 

- Upload code directly to Workbench

- Generate hashes locally using **fossid-cli** and upload those to Workbench (also known as a blind scan). 

### 1. Upload code directly to Workbench 

WB-Agent Calls Workbench API and creates project and scan (or uses already existing one with given project/scan code)

Uploads files from given path via Workbench API. Extract archives API actions is also called to expand any uploaded archive.

Initiates scan, usually with auto id and delta scan enabled

Checks status in a loop. Use also a max limit of time to stop on malfunctioning scans.

When scan finishes can return various type of results: list of all licenses identified, list of all components found, 
policy warnings at scan or project level. Also saves results to a file specified by parameter --path-result PATH_RESULT

Below are some pros and cons compared with other integration scenarios:

#### Pros:
- local file content is available when inspecting the files in Workbench

- no need to manually expand .war/.jar files, this is handled in the Workbench

#### Cons:
- much larger files to be uploaded to the Workbench resulting in possibly longer execution time of the pipeline.

 

### 2. Generate hashes using fossid-cli and upload those to Workbench (blind scan)

Requires fossid-cli for generating file signatures using the --local flag. Usually WB-Agent is distributed in a container
image containing also fossid-cli and Shinobi License Extractor. This image can be easily pulled in CI/CD pipelines from
a container repository.

Saves file signatures on a temporary file with .fossid extension

Calls Workbench API and create project and scan (or use already existing one with give project/scan code)

Uploads .fossid file via Workbench API

Initiates scan, usually with auto id and delta scan enabled

Checks status in a loop. Use also a max limit of time to stop on malfunctioning scans.

When scan finishes can return various type of results: list of all licenses identified, list of all components found, 
policy warnings at scan or project level. Also saves results to a file specified by parameter --path-result PATH_RESULT

Below are some pros and cons compared with other integration scenarios:

##### Pros:

- no need to make code available to Workbench avoiding large files being uploaded

- easy setup

#### Cons:

- the scanned files (local files) will not be available for comparison with matches in Workbench UI.


## Installation

Copy the file "workbench-agent.py" file to a server with Python installed and with access to a Workbench API.
Install dependencies:

```bash
pip install -r requirements.txt
```


## Usage
Example:
```bash
    python3 workbench-agent.py --api_url=https://myserver.com/api.php \
      --api_user=my_user  \
      --api_token=xxxxxxxxx \
      --project_code=prod \
      --scan_code=${BUILD_NUMBER} \
      --limit=10 \
      --sensitivity=10 \
      --auto_identification_detect_declaration  \
      --auto_identification_detect_copyright  \
      --delta_only \
      --scan_number_of_tries=100 \
      --scan_wait_time=30 \
      --path='/some/path/to/files/to/be/scanned'
      --path-result='/tmp/fossid_result.json'

      

```
Detailed parameters description:
```bash
 python3 workbench-agent.py --help
usage:  python3 workbench-agent.py [-h] --api_url API_URL --api_user API_USER --api_token API_TOKEN --project_code PROJECT_CODE --scan_code SCAN_CODE [--limit LIMIT]
                          [--sensitivity SENSITIVITY] [--auto_identification_detect_declaration] [--auto_identification_detect_copyright]
                          [--auto_identification_resolve_pending_ids] [--delta_only] [--reuse_identifications]
                          [--identification_reuse_type {any,only_me,specific_project,specific_scan}] [--specific_code SPECIFIC_CODE]
                          [--scan_number_of_tries SCAN_NUMBER_OF_TRIES] [--scan_wait_time SCAN_WAIT_TIME] --path PATH [--log LOG] [--get_scan_identified_components]

Run FossID Workbench Agent

required arguments:
  --api_url API_URL     URL of the Workbench API instance, Ex:  https://myserver.com/api.php
  --api_user API_USER   Workbench user that will make API calls
  --api_token API_TOKEN
                        Workbench user API token (Not the same with user password!!!)
  --project_code PROJECT_CODE
                        Name of the project inside Workbench where the scan will be created.
                        If the project doesnt exist, it will be created
  --scan_code SCAN_CODE
                        The scan code used when creating the scan in Workbench. It can be based on some env var,
                        for example:  ${BUILD_NUMBER}
  --scan_number_of_tries SCAN_NUMBER_OF_TRIES
                        Number of calls to "check_status" till declaring the scan failed from the point of view of the agent.
  --scan_wait_time SCAN_WAIT_TIME
                        Time interval between calling "check_status", expressed in seconds (default 30 seconds)
  --path PATH           Path of the directory where the files to be scanned reside

optional arguments:
  -h, --help            show this help message and exit
  --limit LIMIT         Limits CLI results to N most significant matches (default: 10)
  --sensitivity SENSITIVITY
                        Sets snippet sensitivity to a minimum of N lines (default: 10)
  --auto_identification_detect_declaration
                        Automatically detect license declaration inside files. This argument expects no value, not passing
                        this argument is equivalent to assigning false.
  --auto_identification_detect_copyright
                        Automatically detect copyright statements inside files. This argument expects no value, not passing
                        this argument is equivalent to assigning false.
  --auto_identification_resolve_pending_ids
                        Automatically resolve pending identifications. This argument expects no value, not passing
                        this argument is equivalent to assigning false.
  --delta_only          Scan only delta (newly added files from last scan).
  --run_dependency_analysis
                        Initiate dependency analysis after finishing scanning for matches in KB.
  --run_only_dependency_analysis
                        Scan only for dependencies, no results from KB.
  --reuse_identifications
                        If present, try to use an existing identification depending on parameter "identification_reuse_type".
  --identification_reuse_type {any,only_me,specific_project,specific_scan}
                        Based on reuse type last identification found will be used for files with the same hash.
  --specific_code SPECIFIC_CODE
                        The scan code user when creating the scan in Workbench. It can be based on some env var,
                        for example:  ${BUILD_NUMBER}
  --log LOG             specify logging level. Allowed values: DEBUG, INFO, WARNING, ERROR
  --path-result PATH_RESULT
                        Save results to specified path

  --get_scan_identified_components 
                        By default at the end of scanning the list of licenses identified will be retrieved.
                        When passing this parameter the agent will return the list of identified components instead.
                        This argument expects no value, not passing this argument is equivalent to assigning false.
  --scans_get_policy_warnings_counter
                        By default at the end of scanning the list of licenses identified will be retrieved.
                        When passing this parameter the agent will return information about policy warnings found in this scan
                        based on policy rules set at Project level.
                        This argument expects no value, not passing this argument is equivalent to assigning false.

  --projects_get_policy_warnings_info
                        By default at the end of scanning the list of licenses identified will be retrieved.
                        When passing this parameter the agent will return information about policy warnings for project,
                        including the warnings counter.
                        This argument expects no value, not passing this argument is equivalent to assigning false.


```


## Contributing

Thank you for considering contributing to FossID Workbench-Agent. Easiest way to contribute is by reporting bugs or by
sending improvement suggestions. The FossID Support Portal is the preferred channel for sending those, but you can use
the Issues in GitHub repository is an alternative channel.

Pull requests are also welcomed. Please note that the Workbench-Agent is licensed under MIT license.
The submission of your contribution implies that you agree with MIT licensing terms.

## Development

We make efforts to comply with PEP8 Style guide (https://peps.python.org/pep-0008/)
Run this command for checking code style issues:
```bash
    pycodestyle workbench-agent.py 
```
Using 'black' auto-formatter various problems can be fixed with this command:
```bash
    black workbench-agent.py
```
Linting

Run pylint in order reveal possible issues:
```bash
    pylint workbench-agent.py
```
