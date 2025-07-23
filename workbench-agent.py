#!/usr/bin/env python3

# Copyright: FossID AB 2022

import sys
from workbench_agent.main import main  # Import the main function from the package

# Keep backward compatibility by creating an alias
from workbench_agent.api import WorkbenchAPI
Workbench = WorkbenchAPI


if __name__ == "__main__":
    sys.exit(main())  # Call the main function and exit with its code
