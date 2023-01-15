import lief
import os
from textwrap import indent


def main():
    binary = lief.parse("/Users/richard/prj/mkw/tools/4199_60831/mwcceppc.exe")

    print("Header:")
    print(indent(str(binary.header), "\t"))

    print("DOS Header:")
    print(indent(str(binary.dos_header), "\t"))

    print("Optional Header")
    print(indent(str(binary.optional_header), "\t"))

    print("Imports:")
    for lib in binary.imports:
        print(f"\t- {lib.name}")

    print("Sections:")
    for section in binary.sections:
        print(f"\t- {section.name}")

    print("Dumping text...")
    dump_text(binary)


def dump_text(binary):
    section = binary.get_section(".text")
    print("\tpaddr: %# 10x" % (section.offset))
    vaddr = binary.optional_header.imagebase + section.virtual_address
    print("\tvaddr: %# 10x" % (vaddr))
    print("\tsize:  %# 10x" % (section.size))
    print("\tWriting to ./out/text.raw")
    os.makedirs("./out", exist_ok=True)
    with open("./out/text.raw", "wb") as text_raw_file:
        text_raw_file.write(section.content)


if __name__ == "__main__":
    main()
