from sys import exit
from pcap_parser import PcapParser, ParserArguments
from Functions import Functions


def main():
    try:
        functions = Functions()
        args = ParserArguments()

        pcap_file = functions.choose_file(args.PCAP_FILE_ROOT_DIR)
        parsing = PcapParser(pcap_file)
        parsing.run()

    except Exception as err:
        print(err)
        exit()


if __name__ == "__main__":
    main()
