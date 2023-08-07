"""Common Utils."""
import ntpath
import platform
import os
import shutil
import settings as settings
from common.permission_map import PERMISSION_ZONE
from urllib.parse import urlparse
import logging
import requests

logger = logging.getLogger(__name__)
def upstream_proxy(flaw_type):
    """Set upstream Proxy if needed."""
    if settings.UPSTREAM_PROXY_ENABLED:
        if not settings.UPSTREAM_PROXY_USERNAME:
            proxy_port = str(settings.UPSTREAM_PROXY_PORT)
            proxy_host = '{}://{}:{}'.format(
                settings.UPSTREAM_PROXY_TYPE,
                settings.UPSTREAM_PROXY_IP,
                proxy_port)
            proxies = {flaw_type: proxy_host}
        else:
            proxy_port = str(settings.UPSTREAM_PROXY_PORT)
            proxy_host = '{}://{}:{}@{}:{}'.format(
                settings.UPSTREAM_PROXY_TYPE,
                settings.UPSTREAM_PROXY_USERNAME,
                settings.UPSTREAM_PROXY_PASSWORD,
                settings.UPSTREAM_PROXY_IP,
                proxy_port)
            proxies = {flaw_type: proxy_host}
    else:
        proxies = {flaw_type: None}
    verify = bool(settings.UPSTREAM_PROXY_SSL_VERIFY)
    return proxies, verify

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def find_java_binary():
    """Find Java."""
    # Respect user settings
    if platform.system() == 'Windows':
        jbin = 'java.exe'
    else:
        jbin = 'java'
    if is_dir_exists(settings.JAVA_DIRECTORY):
        if settings.JAVA_DIRECTORY.endswith('/'):
            return settings.JAVA_DIRECTORY + jbin
        elif settings.JAVA_DIRECTORY.endswith('\\'):
            return settings.JAVA_DIRECTORY + jbin
        else:
            return settings.JAVA_DIRECTORY + '/' + jbin
    if os.getenv('JAVA_HOME'):
        java = os.path.join(
            os.getenv('JAVA_HOME'),
            'bin',
            jbin)
        if is_file_exists(java):
            return java
    return 'java'

def filename_from_path(path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)

def is_dir_exists(dir_path):
    if os.path.isdir(dir_path):
        return True
    else:
        return False

def is_file_exists(file_path):
    if os.path.isfile(file_path):
        return True
    # This fix situation where a user just typed "adb" or another executable
    # inside settings.py/config.py
    if shutil.which(file_path):
        return True
    else:
        return False

def print_and_extract_api_and_ref(apis, info: str = "API"):
    """Print list of API and its references
    :dbs: the list of data storages 
    """
    api_ref = set()
    print(f"{bcolors.HEADER}{bcolors.BOLD}\n#### {info} EXTRACTION ####{bcolors.ENDC}")
    #print(dbs)
    for k, a in apis.items():
        print(f"\n{bcolors.OKBLUE} API: '{a['metadata']['description']}'{bcolors.ENDC}")
        #data_storages.append(a['metadata']['description'])
        for f, p in a['files'].items():
            print(f"- File: '{f}' \tline '{p}'")
            api_ref.add(tuple([convert_path_to_component(f), a['metadata']['description']]))
    return api_ref

def convert_path_to_component(java_path):
    # Replace forward slashes with periods
    android_name = java_path.replace('/', '.')
    # Remove ".java" file extension
    android_name = android_name.replace('.java', '')
    return android_name

def convert_permission_map_to_api_mapping():
    api_mapping: dict[str, list] = {}

    for k, v in PERMISSION_ZONE.items():
        for a in v:
            if a in api_mapping:
                api_mapping[a].append(k)
            else:
                api_mapping[a] = [k]
    return api_mapping

def append_two_list_with_unique_items(list1, list2):
    return list(set(list1 + list2))

def open_firebase(url):
    # Detect Open Firebase Database
    try:
        purl = urlparse(url)
        base_url = '{}://{}/.json'.format(purl.scheme, purl.netloc)
        proxies, verify = upstream_proxy('https')
        headers = {
            'User-Agent': ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1)'
                           ' AppleWebKit/537.36 (KHTML, like Gecko) '
                           'Chrome/39.0.2171.95 Safari/537.36')}
        resp = requests.get(base_url, headers=headers,
                            proxies=proxies, verify=verify)
        if resp.status_code == 200:
            return base_url, True
    except Exception:
        logger.warning('Open Firebase DB detection failed.')
    return url, False


def firebase_analysis(urls):
    # Detect Firebase URL
    firebase_db = []
    logger.info('Detecting Firebase URL(s)')
    for url in urls:
        if 'firebaseio.com' in url:
            returl, is_open = open_firebase(url)
            fbdic = {'url': returl, 'open': is_open}
            if fbdic not in firebase_db:
                firebase_db.append(fbdic)
    return firebase_db