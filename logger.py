from logging import getLogger, INFO, basicConfig


class Logger:
    """Custom logger class"""

    def __init__(self, logger_name: str):
        self.logger = getLogger(logger_name)
        self.log_file_mode = LoggerArguments.WRITE_MODE
        self.log_level = INFO
        basicConfig(filename=LoggerArguments.LOG_FILE_PATH, filemode=self.log_file_mode,
                    format=LoggerArguments.LOG_FILE_FORMAT, level=self.log_level,
                    datefmt=LoggerArguments.LOG_DATE_FORMAT)


class LoggerArguments:
    # log file
    LOG_FILE_PATH = "pcap_parser.log"
    LOG_FILE_FORMAT = "[%(asctime)s] - [%(name)s] - [%(levelname)s] --- %(message)s"
    LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
    WRITE_MODE = 'w'


class LoggerError(Exception):
    pass
