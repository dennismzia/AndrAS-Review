from typing import *
import subprocess as sp
from common.execute_command import execute, Timeout
import os

CURRENT_DIRECTORY = os.path.dirname(os.path.realpath(__file__))
ANDROID_JAR = CURRENT_DIRECTORY + "/tools"

class ICCBot:
    def __init__(self, apk_loc: str, out_loc: str = "tmp"):
        self.aloc = apk_loc
        self.oloc = out_loc
        self.link: Set[Tuple[str, str]] = set()
        assert (os.path.exists(self.aloc))
        assert (os.path.exists(self.oloc))
    
    def retrieveInfo(self, timeout = 10000, analyzeLib = True):
    
        jar_location = CURRENT_DIRECTORY + "/tools/ICCBot.jar"
        # print("Jar location: ",  jar_location)
        assert (os.path.exists(jar_location))

        filename = os.path.basename(self.aloc)
        dirpath = self.aloc[:-len(filename)]

        params = [
            "java",
            "-jar",
            jar_location, 
            "-androidJar",
            ANDROID_JAR,
            "-path",
            dirpath,
            "-name",
            filename,
            "-outputDir",
            self.oloc,
            "-config",
            CURRENT_DIRECTORY + "/tools/config.json",
            "-client",
            "MainClient",
            "-time",
            str(timeout // 60),
            "-noLibCode" if not analyzeLib else "",
            "-noFragment"
        ]

        #print(' '.join(params))

        execute(' '.join(params))

    def getInfoAfterRun(self):
        filename_without_ext = '.'.join(os.path.basename(self.aloc).split('.')[:-1])
        path = self.oloc + "/" + \
            filename_without_ext + "/CTGResult/" + \
            filename_without_ext + "_CTG.txt"
        
        # print(path)
        link = set()

        if (os.path.exists(path)):

            f = open(path, "r")

            for line in f.readlines():
                if len(line) > 4:
                    u,v = line.strip().split(' -> ')
                    link.add((u, v))

            f.close()

            return link
        else:
            return None

def exportICCBot(apk_path="app/app-debug.apk"):
    b = ICCBot(apk_path)
    # print("Path: " + apk_path)
    b.retrieveInfo(analyzeLib = False)
    result = b.getInfoAfterRun()
    if result == None:
        print("Run fail (maybe timed out)")
        exit(1)
    else:
        return result

if __name__ == "__main__":
    b = ICCBot("./app/app-debug.apk")
    b.retrieveInfo()
    result = b.getInfoAfterRun()
    if result == None:
        print("Run fail (maybe timed out)")
    else:
        for x in result:
            print(x)