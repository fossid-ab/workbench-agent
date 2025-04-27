# --- Builder Stage ---
# Use a builder stage with development tools (pip, setuptools, etc.)
FROM cgr.dev/chainguard/python:latest-dev AS builder

# Set the working directory
WORKDIR /app

# Copy the files required for installation
# - pyproject.toml defines the package and dependencies
# - src/ contains the actual package code
COPY pyproject.toml .
COPY src/ ./src/

# Install the workbench-agent package itself and its dependencies
# using the pyproject.toml file.
# Install into the user scheme (--user) which is typically /home/nonroot/.local
# This makes it easier to copy the installed files to the final stage.
# Use --no-cache-dir to ensure fresh downloads if needed.
RUN pip install . --user --no-cache-dir

# --- Final Runtime Stage ---
# Use a minimal runtime image
FROM cgr.dev/chainguard/python:latest

# Set the working directory
WORKDIR /app

# Copy the installed package and dependencies from the builder stage's
# user installation directory to the same location in the final stage.
COPY --from=builder /home/nonroot/.local /home/nonroot/.local

# Add the user's local bin directory (where pip installs scripts with --user)
# to the system's PATH environment variable.
# This ensures the installed 'workbench-agent' command can be found and executed.
ENV PATH="/home/nonroot/.local/bin:${PATH}"

# Set the entrypoint to the installed command 'workbench-agent'.
# When the container starts, it will execute this command.
# Arguments passed to `docker run` will be appended to this entrypoint.
ENTRYPOINT [ "workbench-agent" ]