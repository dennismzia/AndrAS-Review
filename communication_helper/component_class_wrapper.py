from typing import *
from common.execute_command import execute, Timeout
import os

CURRENT_DIRECTORY = os.path.dirname(os.path.realpath(__file__))

class Link:
    def __init__(self, apk_loc: str, class_file: str, output_file: str, out_loc: str = "tmp"):
        self.aloc = apk_loc
        self.oloc = out_loc
        self.cfile = class_file
        self.ofile = output_file
        self.link: Set[Tuple[str, str]] = set()
        assert (os.path.exists(self.aloc))
        assert (os.path.exists(self.oloc))
        assert (os.path.exists(self.cfile))
    
    def retrieveInfo(self, timeout = 10000) -> bool:

        cmd = "java -jar" + " " + \
            CURRENT_DIRECTORY + "/tools/component-class-link.jar" + " " + \
            self.aloc + " " + \
            self.oloc + " " + \
            self.cfile + " " + \
            self.ofile
        print(cmd) 
        try:
            execute(cmd)
        except Timeout:
            print(f"[*] Timed out ({timeout} secs)")
            return False

        # assert (os.path.exists(self.ofile))
        return True

    def analyze(self, keepFile = False):
        if not os.path.exists(self.ofile):
            print("File not found, run retrieveInfo first!")
            return

        f = open(self.ofile, "r")
        for line in f.readlines():
            if len(line) > 3:
                # u is always component, v is always class defined in given file!
                u, v = line.strip().split(" - ")
                self.link.add((u, v))
        f.close()
        if not keepFile:
            os.remove(self.ofile)
        

def exportComponentClassLink(apk_path="../app/app-debug.apk"):
    print(apk_path)
    print("Current " + CURRENT_DIRECTORY)
    a = Link(apk_path, CURRENT_DIRECTORY + "/tmp/source_classes.txt", "links.txt", CURRENT_DIRECTORY + "/tmp")
    print(a)
    # Use can set `timeout` here
    a.retrieveInfo()
    print("Here")
    # delete temporary link file or not with `keepFile``
    a.analyze()
    print("There")
    return a.link

# Example code
if __name__ == "__main__":
    # argument: apk path -> source classes path -> temporary link file -> tmp folder for Argus output
    a = Link("./app/app-debug.apk", "tmp/source_classes.txt", "links.txt", "../tmp")
    # Use can set `timeout` here
    a.retrieveInfo()
    # delete temporary link file or not with `keepFile``
    a.analyze()
    print(a.link) # Same format as ICCEX