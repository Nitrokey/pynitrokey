import contextlib
import logging


@contextlib.contextmanager
def suppress_logs(logger: logging.Logger = None, highest_level=logging.CRITICAL, execute=True):
    """Context manager to temporarily disable logs.
    see https://stackoverflow.com/questions/2266646/how-to-disable-logging-on-the-standard-error-stream

    # Arguments
        logger (logging.Logger): #logging.Logger object to disable. Defaults
            to the root logger.

    # Usage
        ```python
           with suppress_logs():
               pass
        ```
    """
    if not execute:
        yield
        return

    previous_level = logging.root.manager.disable
    if logger is None:
        logger = logging.getLogger()
    try:
        logger.disabled = True
        logging.disable(highest_level)
        yield
    finally:
        logger.disabled = False
        logging.disable(previous_level)
