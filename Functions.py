from json import dump
from os import path, listdir
from logger import Logger
from typing import Optional, Any


class Functions:
    def __init__(self):
        self.logger = Logger(self.__class__.__name__)

    def create_json_file(self, file_path: str, data: Any, indent: Optional[int] = 4) -> None:
        """
        This function creates a JSON file.
        :param file_path: The path to the new created JSON file.
        :param data: The data to be dumped into the JSON file.
        :param indent: For the JSON file indentation level.
        :return: None
        """
        try:
            with open(file_path, FunctionsArguments.WRITE_MODE) as json_file:
                dump(data, json_file, indent=indent)
            self.logger.logger.info(f"Created '{file_path}' successfully.")

        except Exception as err:
            self.logger.logger.error(err)
            raise FunctionsError(f"Failed to create a JSON file, Error: {err}")

    def choose_file(self, dir_path: str) -> str:
        """
        This function returns the wanted file from dir_path and validates if the file is a .pcap file.
        :param dir_path: The path to the pcap files directory.
        :return: The wanted .pcap file.
        """
        try:
            # show all the files in dir_name directory
            files = listdir(dir_path)
            for index, file in enumerate(files, start=1):
                print(f"{index} - {file}")

            # choose the wanted file
            selected_index = int(input("Please Enter the index number of the file: "))
            if 1 <= selected_index <= len(files):
                selected_file = files[selected_index - 1]

                # validate the selected_file is a .pcap file
                if self.validate_pcap_file(selected_file):
                    return f"{dir_path}/{selected_file}"
                else:
                    self.logger.logger.error(f"'{selected_file}' is not a .pcap file.")
                    print(f"'{selected_file}' is not a .pcap file.")
                    raise FunctionsError

            else:
                self.logger.logger.error("Invalid index. Please choose a valid index.")
                print("Invalid index. Please choose a valid index.")
                raise FunctionsError

        except Exception as err:
            self.logger.logger.error(err)
            raise FunctionsError(f"Error while choosing a file.")

    def validate_pcap_file(self, file_path: str) -> bool:
        """
        This function validates if file_path is a .pcap file.
        :param file_path: The path to the .pcap file.
        :return: True if file_path is a .pcap file, False otherwise.
        """
        _, file_extension = path.splitext(file_path)
        return file_extension in ['.pcap', '.pcapng']


class FunctionsArguments:

    WRITE_MODE = 'w'
    PCAP_SUFFIX = ".pcap"


class FunctionsError(Exception):
    pass
