from typing import Dict, List, Optional, Union, Any, Tuple
import logging
import time
import argparse
from ..projects_api import ProjectsAPI
from ..scans_api import ScansAPI
from ...exceptions import (
    WorkbenchAgentError,
    ApiError,
    NetworkError,
    ConfigurationError,
    ValidationError,
    ProjectNotFoundError,
    ScanNotFoundError,
    ProjectExistsError,
    ScanExistsError
)

# Assume logger is configured in main.py
logger = logging.getLogger("workbench-agent")


class ResolveWorkbenchProjectScan(ProjectsAPI, ScansAPI):
    """
    Workbench API Scan Target Resolution Operations - handles resolving project names to codes
    and scan names to codes/IDs, with optional creation functionality.
    
    Inherits from both ProjectsAPI and ScansAPI to access list methods.
    """

    def resolve_project(self, project_name: str, create_if_missing: bool = False) -> str:
        """Find a project by name, optionally creating it if not found."""
        # Look for existing project
        projects = self.list_projects()
        project = next((p for p in projects if p.get("project_name") == project_name), None)
        
        if project:
            return project["project_code"]
            
        # Create if requested
        if create_if_missing:
            print(f"Creating project '{project_name}'...")
            try:
                self.create_project(project_name)
                return project_name  # Use project_name as project_code
            except ProjectExistsError:
                # Handle race condition
                projects = self.list_projects()
                project = next((p for p in projects if p.get("project_name") == project_name), None)
                if project:
                    return project["project_code"]
                raise ApiError(f"Failed to resolve project '{project_name}' after creation conflict")
                
        raise ProjectNotFoundError(f"Project '{project_name}' not found")

    def resolve_scan(self, scan_name: str, project_name: Optional[str], create_if_missing: bool, params: argparse.Namespace, import_from_report: bool = False) -> Tuple[str, int]:
        """Find a scan by name, optionally creating it if not found."""
        if project_name:
            # Look in specific project
            project_code = self.resolve_project(project_name, create_if_missing)
            scan_list = self.get_project_scans(project_code)
            
            # Look for exact match only
            scan = next((s for s in scan_list if s.get('name') == scan_name), None)
            if scan:
                return scan['code'], int(scan['id'])
                
            # Create if requested
            if create_if_missing:
                print(f"Creating scan '{scan_name}' in project '{project_name}'...")
                git_params = self._get_git_params(params)
                scan_id = self.create_webapp_scan(
                    scan_code=scan_name,  # Use scan_name as scan_code
                    project_code=project_code,
                    **git_params
                )
                time.sleep(2)  # Brief wait for creation to process
                
                # Get the newly created scan
                scan_list = self.get_project_scans(project_code)
                scan = next((s for s in scan_list if s.get('name') == scan_name), None)
                if scan:
                    return scan['code'], int(scan['id'])
                raise ApiError(f"Failed to retrieve newly created scan '{scan_name}'")
                
            raise ScanNotFoundError(f"Scan '{scan_name}' not found in project '{project_name}'")
            
        else:
            # Global search
            if create_if_missing:
                raise ConfigurationError("Cannot create a scan without specifying a project")
                
            scan_list = self.list_scans()
            found = [s for s in scan_list if s.get('name') == scan_name]
            
            if len(found) == 1:
                scan = found[0]
                return scan['code'], int(scan['id'])
            elif len(found) > 1:
                projects = sorted(set(s.get('project_code', 'Unknown') for s in found))
                raise ValidationError(f"Multiple scans found with name '{scan_name}' in projects: {', '.join(projects)}")
                
            raise ScanNotFoundError(f"Scan '{scan_name}' not found in any project")

    def prepare_project_and_scan(self, project_identifier: str, scan_identifier: str, params: argparse.Namespace = None) -> Tuple[str, int]:
        """
        Ensures project exists and creates scan if needed.
        Supports both legacy code-based approach and new name-based approach with automatic resolution.
        
        Args:
            project_identifier: Project code/name to use
            scan_identifier: Scan code/name to use  
            params: Optional command line parameters for name resolution
            
        Returns:
            Tuple of (project_code, scan_id)
        """
        # Determine if we're using names vs codes based on explicit flag
        use_name_resolution = params and getattr(params, 'use_name_resolution', False)
        
        if use_name_resolution:
            logger.info(f"Using name-based resolution for project and scan...")
            
            # Get names from params
            project_name = getattr(params, 'project_name', project_identifier)
            scan_name = getattr(params, 'scan_name', scan_identifier)
            
            logger.info(f"Resolving project name '{project_name}' and scan name '{scan_name}'...")
            
            # Resolve project (auto-create if missing)
            try:
                resolved_project_code = self.resolve_project(project_name, create_if_missing=True)
                logger.info(f"Project '{project_name}' resolved to code '{resolved_project_code}'")
            except Exception as e:
                logger.error(f"Failed to resolve project '{project_name}': {e}")
                raise
            
            # Resolve scan (auto-create if missing)
            try:
                resolved_scan_code, scan_id = self.resolve_scan(
                    scan_name=scan_name,
                    project_name=project_name,
                    create_if_missing=True,
                    params=params
                )
                logger.info(f"Scan '{scan_name}' resolved to code '{resolved_scan_code}' with ID {scan_id}")
                return resolved_project_code, scan_id
            except Exception as e:
                logger.error(f"Failed to resolve scan '{scan_name}': {e}")
                raise
                
        else:
            # Legacy code-based approach
            logger.info(f"Using legacy code-based approach for project '{project_identifier}' and scan '{scan_identifier}'...")
            
            # Check if project exists, create if needed
            if not self.check_if_project_exists(project_identifier):
                logger.info(f"Project '{project_identifier}' does not exist. Creating...")
                self.create_project(project_identifier)
                logger.info(f"Project '{project_identifier}' created successfully.")
            else:
                logger.info(f"Project '{project_identifier}' already exists.")

            # Create scan if it doesn't exist
            scan_exists = self.check_if_scan_exists(scan_identifier)
            if not scan_exists:
                logger.info(f"Scan '{scan_identifier}' does not exist. Creating...")
                scan_id = self.create_webapp_scan(
                    scan_code=scan_identifier,
                    project_code=project_identifier
                )
                logger.info(f"Created scan with ID: {scan_id}")
            else:
                logger.info(f"Scan '{scan_identifier}' already exists.")
                # For existing scans, we don't need the scan_id for our workflows
                scan_id = None

            return project_identifier, scan_id

    def _get_git_params(self, params: argparse.Namespace) -> Dict[str, Any]:
        """Get git parameters if this is a git scan."""
        # For now, the workbench-agent doesn't support git-specific scans like the CLI
        # This is a placeholder for future git scan support
        return {} 