# AndrAS: An automated threat modeling tool for Android applications

## Setup
* You have to install Java and set JAVA_HOME path. You should use the python version `3.7`
* Setup
```
virtualenv venv-andras
source venv-andras/bin/activate
pip install r requirements.txt
```

## Run
```
cp <filename.apk> Test/<filename.apk>

python analyze.py -a <filename.apk> -d Test -i None

```
The output files are in the Test folder.

Example:

```
python analyze.py -a Diva.apk -d Test -i None
```

### Usage
```
python analyze.py -h 

usage: analyze.py [-h] [-a APK] [-d DIR] [-i {Argus,ArgusLite,Soot,ICCBot,None}]
                  [-l {True,False}]

AndrAS: Automated Attack Surface Analysis for Android Applications

optional arguments:
  -h, --help            show this help message and exit
  -a APK, --apk APK     Path to the APK file
  -d DIR, --dir DIR     Path to the directory containing the APK file
  -i {Argus,ArgusLite,Soot,ICCBot}, --icc {Argus,ArgusLite,Soot,ICCBot,None}
                        Mode for ICC analysis
  -l {True,False}, --library {True,False}
                        Enable library analysis
```
