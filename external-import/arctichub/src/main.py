import traceback

from arctichub import ConnectorArctichub, ConnectorSettings
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    """
    Entry point of the script.

    - traceback.print_exc(): Prints the traceback of the exception to stderr,
      which is very useful for debugging purposes.
    - exit(1): Terminates the program signalling an error to the OS.
    """
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
        connector = ConnectorArctichub(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
