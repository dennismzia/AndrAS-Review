from typing import *
import subprocess as sp
import os
from common.execute_command import execute, Timeout

import graphviz

CURRENT_DIRECTORY = os.path.dirname(os.path.realpath(__file__))
ANDROID_JAR = CURRENT_DIRECTORY + "/tools/android.jar"
#ICC_EXTRACTOR = CURRENT_DIRECTORY + "/tools/ICC-EXtractor.jar"
ICC_EXTRACTOR = CURRENT_DIRECTORY + "/ICCEX/out/artifacts/ICC_EXtractor_jar/ICC-EXtractor.jar"
#SOOT_EXTRACTOR = CURRENT_DIRECTORY + "/tools/soot_analyst.jar"
SOOT_EXTRACTOR = CURRENT_DIRECTORY + "/Soot_ICCEX/out/artifacts/analyst_jar/analyst.jar"


class ICCEX:
    def __init__(self, apk_loc: str, out_loc: str = "tmp"):
        self.aloc = apk_loc
        self.oloc = out_loc
        self.link: Set[Tuple[str, str]] = set()
        assert (os.path.exists(self.aloc))
        assert (os.path.exists(self.oloc))
    
    # Type == ArgusOld || ArgusNew || Soot
    def retrieveInfo(self, type: str = "ArgusNew", timeout = 10000, analyzeLib = True) -> bool:
        params = []

        if type == "ArgusOld":
            jar_location = ICC_EXTRACTOR
            assert (os.path.exists(jar_location))
            params = [
                "java",
                "-jar",
                jar_location, 
                "v1",
                self.aloc,
                self.oloc,
                "nolib" if not analyzeLib else ""
            ]
        elif type == "ArgusNew":
            jar_location = ICC_EXTRACTOR
            assert (os.path.exists(jar_location))
            params = [
                "java",
                "-jar",
                jar_location, 
                "v2",
                self.aloc,
                self.oloc,
                "nolib" if not analyzeLib else ""
            ]
        elif type == "Soot":
            jar_location = SOOT_EXTRACTOR
            assert (os.path.exists(jar_location))
            params = [
                "java",
                "-jar",
                jar_location,
                self.aloc,
                ANDROID_JAR
            ]

        try:
            command = ' '.join(params)
            # process = sp.Popen(params, stdout=sp.PIPE, stderr=sp.PIPE)
            # output, _ = process.communicate(timeout = timeout)
            # output = output.decode().split('\n')
            #output = execute(cmd=command, timeout=timeout).decode().split('\n')
            output = execute(cmd=command).decode().split('\n')

            self.analyzeOutput(output[output.index("BEGIN")+1: output.index("END")])
        except Timeout:
            print(f"[*] {type} timed out ({timeout} secs)")
            return False
        return True
    def analyzeOutput(self, output: Sequence[str]):
        #print("[*] Analyze output from ICCEX")
        self.link = set(
            map(lambda e: tuple(
                map(lambda t: t.split('$')[0], e.split(" - "))
            ), output)
        )
        # print(self.link)
    
    def makeGraph(self):
        # assert (self.link != set()) # in case only 1 activity !
        f = graphviz.Digraph('ICC', filename='icc.gv')
        f.attr(rankdir='TD', size='8,5')
        f.attr('node', shape='component')
        with f.subgraph(name='cluster_icc') as c:
            for u,v in self.link:
                c.node(u)
                c.node(v)
                f.edge(u, v)
        f.view()
        

def exportICC(apk_path="../app/app-debug.apk", type="ArgusLite"):
    local_type = type
    if type == "ArgusLite":
        local_type = "ArgusNew"
    elif type == "Argus":
        local_type = "ArgusOld"
    elif type == "Soot":
        local_type = "Soot"
    a = ICCEX(apk_path)
    a.retrieveInfo(local_type)
    return a.link

# Example code
if __name__ == "__main__":
    a = ICCEX("../app/app-debug.apk")
    # Type == ArgusOld || ArgusNew || Soot
    # Use argusnew for better performance
    a.retrieveInfo("ArgusNew", analyzeLib=False)
    a.makeGraph()