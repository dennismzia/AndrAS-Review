from typing import *
import subprocess as sp
import os

CURRENT_DIRECTORY = os.path.dirname(os.path.realpath(__file__))

class URLExtractor:
    def __init__(self, apk_loc: str, out_loc: str = "/tmp"):
        self.aloc = apk_loc
        self.oloc = out_loc
        self.link: Set[Tuple[str, str]] = set()
        assert (os.path.exists(self.aloc))
        assert (os.path.exists(self.oloc))
    
    # Type = full | partial (full url or analyzed url in code!)
    # Full url -> faster
    def get(self, type: str = "full", timeout = 700):
        jar_location = CURRENT_DIRECTORY + "/tools/urlExtractor.jar"
        assert (os.path.exists(jar_location))
        assert((type == "full") or (type == "partial"))
        params = [
            "java",
            "-jar",
            jar_location, 
            type,
            self.aloc,
            self.oloc
        ]

        output = []

        try:
            process = sp.Popen(params, stdout=sp.PIPE, stderr=sp.PIPE)
            output, _ = process.communicate(timeout = timeout)
            output = output.decode().split('\n')

            output = output[output.index("BEGIN")+1: output.index("END")]
        except sp.TimeoutExpired:
            print(f"[*] {type} timed out ({timeout} secs)")
            return []
        return output

if __name__ == "__main__":
    u = URLExtractor("./app/app-debug.apk")
    # get("full") or get("partial")
    for i in u.get(): print(i)
