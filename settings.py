import os

# Android 3P Tools
JADX_BINARY = ''
BACKSMALI_BINARY = ''
VD2SVG_BINARY = ''
BATIK_BINARY = ''
APKTOOL_BINARY = ''
ADB_BINARY = ''

# iOS 3P Tools
JTOOL_BINARY = ''
CLASSDUMP_BINARY = ''
CLASSDUMP_SWIFT_BINARY = ''

# COMMON
JAVA_DIRECTORY = ''
VBOXMANAGE_BINARY = ''
PYTHON3_PATH = ''
JADX_TIMEOUT = int(os.getenv('JADX_TIMEOUT', 1800))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ==========ANDROID SKIP CLASSES==========================
    # Common third party classes/paths that will be skipped
    # during static analysis
SKIP_CLASS_PATH = {
    'com/google/', 'androidx', 'okhttp2/', 'okhttp3/',
    'com/android/', 'com/squareup', 'okhttp/'
    'android/content/', 'com/twitter/', 'twitter4j/',
    'android/support/', 'org/apache/', 'oauth/signpost',
    'android/arch', 'org/chromium/', 'com/facebook',
    'org/spongycastle', 'org/bouncycastle',
    'com/amazon/identity/', 'io/fabric/sdk',
    'com/instabug', 'com/crashlytics/android',
    'kotlinx/', 'kotlin/', 'retrofit2/',
    # adding
    'retrofit2/', 'io/flutter/', 'io/realm/', 'io/didomi/', 
}

# Format
LOCAL_APP = "Local App"
NO_PERMISSION = "No Permission"
DATA_STORAGE_SHAPE = "cylinder"
DATA_STORAGE_COLOR = "lightblue"
CONNECTION_SHAPE = "rectangle"
CONNECTION_COLOR = "lightgreen"
PERSONAL_SHAPE = "rectangle"
PERSONAL_COLOR = "darkorchid1"
REST_API_SHAPE = "rectangle"
REST_API_COLOR = "gold1"
PERMISSION_SHAPE = "hexagon"
PERMISSION_COLOR = "lightcoral"
COMPONENT_SHAPE = "ellipse"
EXTERNAL_ENTITY_SHAPE = "rectangle"
EXTERNAL_ENTITY_COLOR = "gray"