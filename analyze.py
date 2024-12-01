#!/usr/bin/env python3
from pathlib import Path
from urllib.parse import urlparse
from stastic_analysis.strings import strings_from_apk
from stastic_analysis.binary_analysis import elf_analysis
from stastic_analysis.code_analysis import code_analysis
from stastic_analysis.manifest_analysis import (get_manifest, manifest_analysis, manifest_data)
from common.converter import apk_2_java
import pyfiglet
import re
import json
from common.utils import (append_two_list_with_unique_items, print_and_extract_api_and_ref, convert_path_to_component)
from graphviz import Source
from communication_helper.iccex_wrapper import exportICC
from communication_helper.iccbot_wrapper import exportICCBot
from communication_helper.component_class_wrapper import exportComponentClassLink
from common.permission_map import(PERMISSION_ZONE, API_CALLS_PERMISSIONS, TRUST_BOUNDARY)
from common.execute_command import execute, Timeout
from common.shared_func import clean
import os
import argparse
import logging
from settings import *
import time


# Initialize logger
logging.basicConfig(level=logging.DEBUG)

# Get current directory
CURRENT_DIRECTORY = os.path.dirname(os.path.realpath(__file__))

# Arguments for the program
# -a: Path to the APK file
APK_FILE_NAME = "app-debug.apk"
# -d: Path to the directory containing the APK file
APK_DIRECTORY = "app/"
FILE_PATH = APK_DIRECTORY + "/" + APK_FILE_NAME
# -i: Mode for ICC analysis
ICC_MODE = "ArgusLite"
# -l: Enable library analysis
LIB_ANALYSIS = "False"


TMP_FOLDER_COMMUNICATION = "communication_helper/tmp"

DFD_ELEMENT_PROCESS_TYPE = "Process"
DFD_ELEMENT_DATA_STORE_TYPE = "DataStore"
DFD_ELEMENT_EXTERNAL_ENTITY_TYPE = "ExternalEntity"
DFD_ELEMENT_DATA_FLOW_TYPE = "DataFlow"
DFD_ELEMENT_PERMISSION_TYPE = "Permission"
DFD_ELEMENT_WEB_SERVER_TYPE = "WebServer"
DFD_ELEMENT_CONNECTION_TYPE = "Connection"
DFD_ELEMENT_PERSONAL_DATA_TYPE = "PersonalData"

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

def print_list(l):
    print(*l, sep = "\n") 

def argeparse_operation():
    logging.debug('Start parsing arguments')
    logging.info('Start parsing arguments')
    argparser = argparse.ArgumentParser(description="AndrAS: Automated Attack Surface Analysis for Android Applications")
    argparser.add_argument("-a", "--apk", help="Path to the APK file")
    argparser.add_argument("-d", "--dir", help="Path to the directory containing the APK file")
    argparser.add_argument("-i", "--icc", help="Mode for ICC analysis", choices=["Argus", "ArgusLite", "Soot", "ICCBot", "None"], default="ArgusLite")
    argparser.add_argument("-l", "--library", help="Enable library analysis", choices=["True", "False"], default="False")

    global APK_FILE_NAME
    global APK_DIRECTORY
    global FILE_PATH
    global LIB_ANALYSIS
    global ICC_MODE

    args = argparser.parse_args()
    #print(args.icc)
    if args.apk:
        APK_FILE_NAME = args.apk
    if args.dir:
        APK_DIRECTORY = args.dir
    if args.icc:
        ICC_MODE = args.icc
    if args.library:
        LIB_ANALYSIS = args.library

    FILE_PATH = APK_DIRECTORY + "/" + APK_FILE_NAME
    check_file_exist(FILE_PATH)
    logging.info('Finished parsing arguments')

def check_file_exist(file_path):
    if not Path(file_path).is_file():
        print(bcolors.FAIL + "File not found: " + file_path + bcolors.ENDC)
        exit(1)

def main():
    """A main function to analyze a APK file and draw the threat model
    Performs static analysis, extracts manifest information and api calls.
    """
    ascii_banner = pyfiglet.figlet_format("AndrAS")
    print(ascii_banner)

    # Parse arguments
    argeparse_operation()
    #print("APK file: " + FILE_PATH)

    app_dic={}
    elf_dict={}
    app_dic['app_file'] = APK_FILE_NAME
    app_dic['app_dir'] = APK_DIRECTORY
    app_dic['app_path'] = FILE_PATH
    app_dic['tools_dir'] = "tools"
    elf_dict = elf_analysis(app_dic['app_dir'])
    logging.info("Finished setting up the app_dic and elf_dict")

    # Identify exported components
    man_an_dic, man_data_dic = analyze_manifest(app_dic)
    logging.info("Finished analyzing the manifest")

    # Add main activity to exported components
    man_an_dic['exported_act'].append(man_data_dic['mainactivity'])

    print_exported_components(man_an_dic)

    # Get list of components
    # components: [activity, service, receiver, provider]
    components = get_list_components(man_data_dic)

    # Print permissions which are defined in manifest file.
    print_permissions(man_an_dic['permissions'])

    # Perform static analysis to get strings, api calls (REST api, Data storages api and other connections api) from java files.
    code_an_dic = code_analysis_apk(app_dic)
    logging.info("Finished analyzing the code using static analysis")

    # Output REST API mapping
    # with open("restapis.json", "w") as outfile:
    #     json.dump(code_an_dic['raw_api'], outfile)
    
    # with open("urls.json", "w") as outfile:
    #     json.dump(code_an_dic['urls'], outfile)

    # Get app name
    app_name = get_strings_from_apk(app_dic, elf_dict, code_an_dic)
    
    # Filter out the garbage urls
    # filter_urls(code_an_dic)

    # Get mapping between REST API and URL
    url_mapping = mapping_rest_api_calls_and_urls(code_an_dic['api'], code_an_dic['urls'])
    logging.info("Finished mapping REST API calls and URLs")
    logging.debug("URL Mapping %s", url_mapping)

    # Get list domain names.
    domains = get_rest_api_server(code_an_dic)

    source_class = [] #List of classes that are not components but have communication with API calls
    
    # Print informations
    print_rest_api_server(domains)
    print_urls_n_ref(code_an_dic['urls'])

    #print("App Permission ", man_an_dic['permissions'])
    # Rest APIs
    rest_apis = print_and_extract_api_and_ref(code_an_dic['api'], "HTTP APIS")
    rest_apis_mapping = mapping_permission_zones_and_api_calls(rest_apis, man_an_dic['permissions'])
    logging.debug("REST API mapping %s", rest_apis_mapping)
    source_class =  append_two_list_with_unique_items(source_class, get_list_source_class(rest_apis_mapping, components))
    logging.info("Finished mapping REST API calls and permissions")

    # Data storages
    data_storages = print_and_extract_api_and_ref(code_an_dic['dbs'], "DATA STORAGES")
    # data_storages_mapping: {permission_zone: [(component, api_call), (component, api_call), ...], permission_zone: [(component, api_call), (component, api_call), ...], ...}
    data_storages_mapping = mapping_permission_zones_and_api_calls(data_storages, man_an_dic['permissions'])
    logging.debug("Data Storages mapping %s", data_storages_mapping)
    source_class =  append_two_list_with_unique_items(source_class, get_list_source_class(data_storages_mapping, components))
    logging.info("Finished mapping DATA STORAGES calls and permissions")

    #print(source_class)

    # Connections
    print(code_an_dic['conn'])
    connections = print_and_extract_api_and_ref(code_an_dic['conn'], "CONNECTIONS")
    # connections_mapping: {permission_zone: [(component, api_call), (component, api_call), ...], permission_zone: [(component, api_call), (component, api_call), ...], ...}
    connections_mapping = mapping_permission_zones_and_api_calls(connections, man_an_dic['permissions'])
    #print(connections_mapping)
    logging.debug("Connections mapping %s", connections_mapping)
    source_class =  append_two_list_with_unique_items(source_class, get_list_source_class(connections_mapping, components))
    logging.info("Finished mapping CONNECTIONS calls and permissions")


    # Personal Data Access
    personal_data_access = print_and_extract_api_and_ref(code_an_dic['personal'], "PERSONAL DATA ACCESS")
    # connections_mapping: {permission_zone: [(component, api_call), (component, api_call), ...], permission_zone: [(component, api_call), (component, api_call), ...], ...}
    personal_data_access_mapping = mapping_permission_zones_and_api_calls(personal_data_access, man_an_dic['permissions'])
    logging.debug("Personal data access mapping %s", personal_data_access_mapping)
    source_class =  append_two_list_with_unique_items(source_class, get_list_source_class(personal_data_access_mapping, components))
    logging.info("Finished mapping PERSONAL DATA ACCESS calls and permissions")

    # Export Source classes
    export_source_classes(source_class)

    icc_link = []
    logging.info("ICC mode: " + ICC_MODE)
    logging.debug("File Path: %s", FILE_PATH)
    components_class_link = []
    # Extract the ICC of the application
    if ICC_MODE != "None":    
        if ICC_MODE == "ICCBot":
            #print("In ICCBot mode")
            icc_link = exportICCBot(apk_path=FILE_PATH)
            logging.debug("ICC Links: %s", icc_link)    
        else:
            #print("In ICC Others mode")
            icc_link = exportICC(apk_path=FILE_PATH, type=ICC_MODE) #If the component does not have a connection, it will not be in the list
            logging.debug("ICC Links: %s", icc_link)
        logging.info("Finished extracting ICC")
        # Extract the Component-Class Link of the application
        components_class_link = exportComponentClassLink(apk_path=FILE_PATH)
        logging.debug("Component-Class Links: %s", components_class_link)
        logging.info("Finished extracting Component-Class Link")
    else:
        logging.info("Skip extracting ICC")    

    # # draw the threat model
    draw_threat_model_graph(app_name, man_an_dic, data_storages_mapping, connections_mapping, rest_apis_mapping, personal_data_access_mapping, man_an_dic['permissions'], icc_link, components_class_link)
    export_xml_file_for_sparta(app_name, man_an_dic, data_storages_mapping, connections_mapping, rest_apis_mapping, personal_data_access_mapping, man_an_dic['permissions'], icc_link, components_class_link)
    logging.info("Finished drawing the threat model")
    clean(app_dic['app_dir']+"/apktool_out")
    clean(app_dic['app_dir']+"/java_source")

def export_source_classes(source_class):
    with open(TMP_FOLDER_COMMUNICATION + "/source_classes.txt", "w") as outfile:
        for item in source_class:
            outfile.write(str(item) + '\n')

def get_list_source_class(communications, components):
    source_class = []
    for i, c in communications.items():
        for j in c:
            if j[0] not in components and j[0] not in source_class:
                source_class.append(j[0])
    return source_class

def get_list_components(man_data_dic):
    components = []
    #Join all the components in a list
    components = man_data_dic['activities'] + man_data_dic['services'] + man_data_dic['receivers'] + man_data_dic['providers']

    return components

def extract_file_path_from_rest_api_call(rest_api_call):
    file_path = []
    for k, a in rest_api_call.items():
        for f, p in a['files'].items():
            if f not in file_path:
                file_path.append(f)
    return file_path

def mapping_rest_api_calls_and_urls(rest_api_calls, urls):
    file_path = extract_file_path_from_rest_api_call(rest_api_calls)
    mapping: set[tuple] = []
    for u in urls:
        if u['path'] in file_path: #Check if the file has rest api calls
            for l in u['urls']:
                mapping.append((convert_path_to_component(u['path']), urlparse(l).netloc))
    return mapping

def mapping_permission_zones_and_api_calls_ex(api_calls, app_permision):
    # Define a dictionary with the permission zones as keys and the API calls as list of tuples
    # The elements of the tuple are two nodes of the graph
    mapping: dict[str, tuple] = {}
    #print(api_calls)
    #print(app_permision)
    for u,v in api_calls:
        if v in API_CALLS_PERMISSIONS:
            for k in API_CALLS_PERMISSIONS[v]:
                if check_api_call_has_permission(v, app_permision):
                    if k in mapping and (u,v) not in mapping[k]:
                        mapping[k].append((u,v))
                    else:
                        mapping[k] = [(u,v)]
                else:
                    if LOCAL_APP in mapping and (u,v) not in mapping[LOCAL_APP]:
                        mapping[LOCAL_APP].append((u,v))
                    else:
                        mapping[LOCAL_APP] = [(u,v)]
        else:
            if LOCAL_APP in mapping and (u,v) not in mapping[LOCAL_APP]:
                mapping[LOCAL_APP].append((u,v))
            else:
                mapping[LOCAL_APP] = [(u,v)]
    #print(mapping)
    return mapping

def mapping_permission_zones_and_api_calls(api_calls, app_permision):
    # Define a dictionary with the permission zones as keys and the API calls as list of tuples
    # The elements of the tuple are two nodes of the graph
    mapping: dict[str, tuple] = {}
    #print(api_calls)
    #print(app_permision)
    for u,v in api_calls:
        #print(u,v)
        if v in API_CALLS_PERMISSIONS:
            #print(v)
            for k in API_CALLS_PERMISSIONS[v]:
                #print(k)
                if check_api_call_has_permission(v, app_permision):
                    #print("Have Permission", k, v)
                    if k in mapping:
                        if (u,v) not in mapping[k]:
                            mapping[k].append((u,v))
                    else:
                        mapping[k] = [(u,v)]
                else:
                    #print("No Permission")
                    if NO_PERMISSION in mapping:
                        if (u,v) not in mapping[NO_PERMISSION]:
                            mapping[NO_PERMISSION].append((u,v))
                    else:
                        mapping[NO_PERMISSION] = [(u,v)]
        else:
            #print("Local App")
            if LOCAL_APP in mapping:
                if (u,v) not in mapping[LOCAL_APP]:
                    mapping[LOCAL_APP].append((u,v))
            else:
                mapping[LOCAL_APP] = [(u,v)]
    #print(mapping)
    return mapping

def check_api_call_has_permission(api_call, app_permision):
    for k in API_CALLS_PERMISSIONS[api_call]:
        if k in app_permision:
            return True
    return False

def analyze_manifest(app_dic):
    """Analyze the Manifest file of the app.
    Return the result of manifest analysis.
    """
    mani_file, mani_xml = get_manifest(
                            app_dic['app_path'],
                            app_dic['app_dir'],
                            app_dic['tools_dir'],
                            '',
                            True,
                        )
    app_dic['manifest_file'] = mani_file
    app_dic['parsed_xml'] = mani_xml
    man_data_dic = manifest_data(app_dic['parsed_xml'])
    #print(man_data_dic['activities'])
    man_an_dic = manifest_analysis(
                            app_dic['parsed_xml'],
                            man_data_dic,
                            '',
                            app_dic['app_dir'],
                        )
    return man_an_dic, man_data_dic

def print_permissions(perms):
    print(f"{bcolors.HEADER}{bcolors.BOLD}\n#### PERMISSIONS ####\n{bcolors.ENDC}")

    for p, d in perms.items():
        print(p)

def print_exported_components(man_an_dic):
    print(f"{bcolors.HEADER}{bcolors.BOLD}\n#### EXPORTED COMPONENTS ####\n{bcolors.ENDC}")
    
    print(f"{bcolors.OKGREEN}{bcolors.BOLD}* Exported Activities\n{bcolors.ENDC}")
    print_list(man_an_dic['exported_act'])
    
    print(f"{bcolors.OKGREEN}{bcolors.BOLD}\n* Exported Services\n{bcolors.ENDC}")
    print_list(man_an_dic['exported_ser'])
    
    print(f"{bcolors.OKGREEN}{bcolors.BOLD}\n* Exported Content Providers\n{bcolors.ENDC}")
    print_list(man_an_dic['exported_pro'])
    
    print(f"{bcolors.OKGREEN}{bcolors.BOLD}\n* Exported Broadcast Receivers\n{bcolors.ENDC}")
    print_list(man_an_dic['exported_rev'])

def code_analysis_apk(app_dic):
    """Perform static analysis on a apk file
    """
    apk_2_java(app_dic['app_path'], app_dic['app_dir'],
                                    app_dic['tools_dir'])
    #dex_2_smali(app_dic['app_dir'], app_dic['tools_dir'])
    #print("In Code Analysis")
    code_an_dic = code_analysis(
                        app_dic['app_dir'],
                        app_dic['app_path'],
                        'apk',
                        app_dic['manifest_file'],
                        LIB_ANALYSIS)
    return code_an_dic

def get_strings_from_apk(app_dic, elf_dict, code_an_dic):
    string_res = strings_from_apk(
                        app_dic['app_file'],
                        app_dic['app_dir'],
                        elf_dict['elf_strings'])
    if string_res:
        app_dic['strings'] = string_res['strings']
        app_dic['secrets'] = string_res['secrets']
        if string_res['urls_list']:
            code_an_dic['urls_list'].extend(string_res['urls_list'])
        if string_res['url_nf']:
            code_an_dic['urls'].extend(string_res['url_nf'])
        if string_res['emails_nf']:
            code_an_dic['emails'].extend(string_res['emails_nf'])
    else:
        app_dic['strings'] = []
        app_dic['secrets'] = []
    return string_res['app_name']

def get_rest_api_server(code_an_dic):
    domains = []
    for url in code_an_dic['urls_list']:
        domains.append(urlparse(url).netloc)
    domains = [*set(domains)]
    return domains

def filter_urls(code_an_dic):
    regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
        r'localhost|' #localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    for url in code_an_dic['urls_list']:
        if re.match(regex, url) is None:
            code_an_dic['urls_list'].remove(url)

def print_rest_api_server(domains):
    print(f"{bcolors.HEADER}{bcolors.BOLD}\n#### REST API SERVERS ####{bcolors.ENDC}")
    print_list(domains)

def print_urls_n_ref(urls):
    print(f"{bcolors.HEADER}{bcolors.BOLD}\n#### URLS EXTRACTION ####{bcolors.ENDC}")
    for u in urls:
        print(f"\n{bcolors.OKBLUE} File: '{u['path']}'{bcolors.ENDC}")
        print_list(u['urls'])
    
def create_data_flow_string(src, dst):
    return src + '->' + dst

def draw_threat_model_graph(app_name, man_an_dic, data_storages, connections, rest_apis, personal_data_accesses, permissions, icc_link, components_class_link):
    import graphviz
    #model_graph = graphviz.Digraph('threat_model', filename='exp/'+APK_FILE_NAME+'.gv')
    model_graph = graphviz.Digraph('threat_model', filename= APK_DIRECTORY + '/' +APK_FILE_NAME+'.gv')
    model_graph.attr(rankdir='TD', size='8,5')

    model_graph.attr('node', shape=COMPONENT_SHAPE)
    
    # NOTE: the subgraph name needs to begin with 'cluster' (all lowercase)
    #       so that Graphviz recognizes it as a special cluster subgraph
    # Check duplicated edges
    edge_list = [] 

    app_list_exported_comp = ['exported_act', 'exported_ser', 'exported_pro', 'exported_rev']
    with model_graph.subgraph(name='cluster_android') as android_graph:
        android_graph.attr(label='Android OS', color="green")
        # Draw Exported Components
        with android_graph.subgraph(name='cluster_app') as app_graph:
            for comp_type in app_list_exported_comp:
                for comp in man_an_dic[comp_type]:
                    add_elements_and_dataflow_to_graph("External Entities", comp, 
                                                       DFD_ELEMENT_EXTERNAL_ENTITY_TYPE, DFD_ELEMENT_PROCESS_TYPE,
                                                       android_graph, app_graph, android_graph)
            app_graph.attr(label=app_name, color="red")
    
        # Draw ICC
        with android_graph.subgraph(name='cluster_app') as app_graph:
            for u,v in icc_link:
                add_elements_and_dataflow_to_graph(u, v,
                                                   DFD_ELEMENT_PROCESS_TYPE, DFD_ELEMENT_PROCESS_TYPE,
                                                   app_graph, app_graph, app_graph)

        # Draw Component-Class Link
        with android_graph.subgraph(name='cluster_app') as app_graph:
            for u,v in components_class_link:
                add_elements_and_dataflow_to_graph(u, v,
                                                   DFD_ELEMENT_PROCESS_TYPE, DFD_ELEMENT_PROCESS_TYPE,
                                                   app_graph, app_graph, app_graph)

    
    # Draw Web Connections    
    for permission, links in rest_apis.items():
        if permission != NO_PERMISSION: #Only APIs that have permissions
            with model_graph.subgraph(name='cluster_android') as android_graph:
                with android_graph.subgraph(name='cluster_app') as app_graph:
                    for component,entity in links:
                        trust_zone = determine_trust_zone(permission, entity, app_graph, android_graph, model_graph)
                        if (component,entity) not in edge_list:
                            add_elements_and_dataflow_to_graph(component, entity,
                                                                DFD_ELEMENT_PROCESS_TYPE, DFD_ELEMENT_WEB_SERVER_TYPE,
                                                                app_graph, model_graph, trust_zone, two_way=True)
                            edge_list.append((component,entity))
                        if trust_zone != app_graph:
                            add_element_to_graph(permission, DFD_ELEMENT_PERMISSION_TYPE, android_graph)
                            add_dataflow_to_graph(component, permission, trust_zone)
                            add_dataflow_to_graph(entity, permission, trust_zone)

    # Draw Data Storanges
    for permission, links in data_storages.items():
        if permission != NO_PERMISSION: 
            with model_graph.subgraph(name='cluster_android') as android_graph:
                with android_graph.subgraph(name='cluster_app') as app_graph:
                    for component,entity in links:
                        trust_zone = determine_trust_zone(permission, entity, app_graph, android_graph, model_graph)
                        if (component,entity) not in edge_list:
                            add_elements_and_dataflow_to_graph(component, entity,
                                                                DFD_ELEMENT_PROCESS_TYPE, DFD_ELEMENT_DATA_STORE_TYPE,
                                                                app_graph, trust_zone, trust_zone, two_way=True)
                            edge_list.append((component,entity))
                        if trust_zone != app_graph:
                            add_element_to_graph(permission, DFD_ELEMENT_PERMISSION_TYPE, android_graph)
                            add_dataflow_to_graph(component, permission, trust_zone)
                            add_dataflow_to_graph(entity, permission, trust_zone)

    # Draw Sensitive Connections  
    for permission, links in connections.items():
        if permission != NO_PERMISSION: #Only APIs that have permissions
            with model_graph.subgraph(name='cluster_android') as android_graph:
                with android_graph.subgraph(name='cluster_app') as app_graph:
                    for component,entity in links:
                        trust_zone = determine_trust_zone(permission, entity, app_graph, android_graph, model_graph)
                        if (component,entity) not in edge_list:
                            add_elements_and_dataflow_to_graph(component, entity,
                                                                DFD_ELEMENT_PROCESS_TYPE, DFD_ELEMENT_CONNECTION_TYPE,
                                                                app_graph, trust_zone, trust_zone, two_way=True)
                            edge_list.append((component,entity))
                        if trust_zone != app_graph:
                            add_element_to_graph(permission, DFD_ELEMENT_PERMISSION_TYPE, android_graph)
                            add_dataflow_to_graph(component, permission, trust_zone)
                            add_dataflow_to_graph(entity, permission, trust_zone)

    # Draw Personal Data Access    
    for permission, links in personal_data_accesses.items():
        if permission != NO_PERMISSION: #Only APIs that have permissions
            with model_graph.subgraph(name='cluster_android') as android_graph:
                with android_graph.subgraph(name='cluster_app') as app_graph:
                    for component,entity in links:
                        trust_zone = determine_trust_zone(permission, entity, app_graph, android_graph, model_graph)
                        if (component,entity) not in edge_list:
                            add_elements_and_dataflow_to_graph(component, entity,
                                                                DFD_ELEMENT_PROCESS_TYPE, DFD_ELEMENT_PERSONAL_DATA_TYPE,
                                                                app_graph, model_graph, trust_zone, two_way=True)
                            edge_list.append((component,entity))
                        if trust_zone != app_graph:
                            add_element_to_graph(permission, DFD_ELEMENT_PERMISSION_TYPE, android_graph)
                            add_dataflow_to_graph(component, permission, trust_zone)
                            add_dataflow_to_graph(entity, permission, trust_zone)

    #model_graph.view()
    #print('Exporting to file... %s', APK_DIRECTORY+ '/' +APK_FILE_NAME+'.gv')
    #model_graph.render(filename=APK_DIRECTORY+ '/' +APK_FILE_NAME+'.gv', view=False)
    model_graph.format = 'svg'
    model_graph.render(filename=APK_DIRECTORY+ '/' +APK_FILE_NAME+'.gv', view=False)

def draw_threat_model_graph_exp(app_name, man_an_dic, data_storages, connections, rest_apis, personal_data_accesses, permissions, icc_link, components_class_link):
    import graphviz
    #model_graph = graphviz.Digraph('threat_model', filename='exp/'+APK_FILE_NAME+'.gv')
    model_graph = graphviz.Digraph('threat_model', filename= APK_DIRECTORY + '/' +APK_FILE_NAME+'.gv')
    model_graph.attr(rankdir='TD', size='8,5')

    model_graph.attr('node', shape=COMPONENT_SHAPE)
    
    # NOTE: the subgraph name needs to begin with 'cluster' (all lowercase)
    #       so that Graphviz recognizes it as a special cluster subgraph
    # Check duplicated edges
    edge_list = [] 

    app_list_exported_comp = ['exported_act', 'exported_ser', 'exported_pro', 'exported_rev']
    with model_graph.subgraph(name='cluster_android') as android_graph:
        android_graph.attr(label='Android OS', color="green")
        # Draw Exported Components
        with android_graph.subgraph(name='cluster_app') as app_graph:
            for comp_type in app_list_exported_comp:
                for comp in man_an_dic[comp_type]:
                    add_elements_and_dataflow_to_graph("External Entities", comp, 
                                                       DFD_ELEMENT_EXTERNAL_ENTITY_TYPE, DFD_ELEMENT_PROCESS_TYPE,
                                                       android_graph, app_graph, android_graph)
            app_graph.attr(label=app_name, color="red")
    
        # Draw ICC
        with android_graph.subgraph(name='cluster_app') as app_graph:
            for u,v in icc_link:
                add_elements_and_dataflow_to_graph(u, v,
                                                   DFD_ELEMENT_PROCESS_TYPE, DFD_ELEMENT_PROCESS_TYPE,
                                                   app_graph, app_graph, app_graph)

        # Draw Component-Class Link
        with android_graph.subgraph(name='cluster_app') as app_graph:
            for u,v in components_class_link:
                add_elements_and_dataflow_to_graph(u, v,
                                                   DFD_ELEMENT_PROCESS_TYPE, DFD_ELEMENT_PROCESS_TYPE,
                                                   app_graph, app_graph, app_graph)

    
    # Draw Web Connections    
    for permission, links in rest_apis.items():
        if permission != NO_PERMISSION: #Only APIs that have permissions
            with model_graph.subgraph(name='cluster_android') as android_graph:
                with android_graph.subgraph(name='cluster_app') as app_graph:
                    for component,entity in links:
                        trust_zone = determine_trust_zone(permission, entity, app_graph, android_graph, model_graph)
                        if (component,entity) not in edge_list:
                            add_elements_and_dataflow_to_graph(component, entity,
                                                                DFD_ELEMENT_PROCESS_TYPE, DFD_ELEMENT_WEB_SERVER_TYPE,
                                                                app_graph, model_graph, trust_zone, two_way=True)
                            edge_list.append((component,entity))
                        if trust_zone != app_graph:
                            add_element_to_graph(permission, DFD_ELEMENT_PERMISSION_TYPE, android_graph)
                            add_dataflow_to_graph(component, permission, trust_zone)
                            add_dataflow_to_graph(entity, permission, trust_zone)

    # Draw Data Storanges
    for permission, links in data_storages.items():
        if permission != NO_PERMISSION: 
            with model_graph.subgraph(name='cluster_android') as android_graph:
                with android_graph.subgraph(name='cluster_app') as app_graph:
                    for component,entity in links:
                        trust_zone = determine_trust_zone(permission, entity, app_graph, android_graph, model_graph)
                        if (component,entity) not in edge_list:
                            add_elements_and_dataflow_to_graph(component, entity,
                                                                DFD_ELEMENT_PROCESS_TYPE, DFD_ELEMENT_DATA_STORE_TYPE,
                                                                app_graph, trust_zone, trust_zone, two_way=True)
                            edge_list.append((component,entity))
                        if trust_zone != app_graph:
                            add_element_to_graph(permission, DFD_ELEMENT_PERMISSION_TYPE, android_graph)
                            add_dataflow_to_graph(component, permission, trust_zone)
                            add_dataflow_to_graph(entity, permission, trust_zone)

    # Draw Sensitive Connections  
    for permission, links in connections.items():
        if permission != NO_PERMISSION: #Only APIs that have permissions
            with model_graph.subgraph(name='cluster_android') as android_graph:
                with android_graph.subgraph(name='cluster_app') as app_graph:
                    for component,entity in links:
                        trust_zone = determine_trust_zone(permission, entity, app_graph, android_graph, model_graph)
                        if (component,entity) not in edge_list:
                            add_elements_and_dataflow_to_graph(component, entity,
                                                                DFD_ELEMENT_PROCESS_TYPE, DFD_ELEMENT_CONNECTION_TYPE,
                                                                app_graph, trust_zone, trust_zone, two_way=True)
                            edge_list.append((component,entity))
                        if trust_zone != app_graph:
                            add_element_to_graph(permission, DFD_ELEMENT_PERMISSION_TYPE, android_graph)
                            add_dataflow_to_graph(component, permission, trust_zone)
                            add_dataflow_to_graph(entity, permission, trust_zone)

    # Draw Personal Data Access    
    for permission, links in personal_data_accesses.items():
        if permission != NO_PERMISSION: #Only APIs that have permissions
            with model_graph.subgraph(name='cluster_android') as android_graph:
                with android_graph.subgraph(name='cluster_app') as app_graph:
                    for component,entity in links:
                        trust_zone = determine_trust_zone(permission, entity, app_graph, android_graph, model_graph)
                        if (component,entity) not in edge_list:
                            add_elements_and_dataflow_to_graph(component, entity,
                                                                DFD_ELEMENT_PROCESS_TYPE, DFD_ELEMENT_PERSONAL_DATA_TYPE,
                                                                app_graph, model_graph, trust_zone, two_way=True)
                            edge_list.append((component,entity))
                        if trust_zone != app_graph:
                            add_element_to_graph(permission, DFD_ELEMENT_PERMISSION_TYPE, android_graph)
                            add_dataflow_to_graph(component, permission, trust_zone)
                            add_dataflow_to_graph(entity, permission, trust_zone)

    #model_graph.view()
    #print('Exporting to file... %s', APK_DIRECTORY+ '/' +APK_FILE_NAME+'.gv')
    #model_graph.render(filename=APK_DIRECTORY+ '/' +APK_FILE_NAME+'.gv', view=False)
    model_graph.format = 'svg'
    model_graph.render(filename='exp'+ '/' +APK_FILE_NAME+'.gv', view=False)

def determine_trust_zone(permission, entity, app_graph, android_graph, model_graph):
    trust_zone = app_graph
    if permission == 'Local App':
        trust_zone = app_graph
    elif entity in TRUST_BOUNDARY['Android OS']:
        trust_zone = android_graph
    elif entity in TRUST_BOUNDARY['External Scope']:
        trust_zone = model_graph
    return trust_zone

def export_xml_file_for_sparta(app_name, man_an_dic, data_storages, connections, rest_apis, personal_data_accesses, permissions, icc_link, components_class_link):
    import pyecore.type as xmltypes
    from pyecore.resources import ResourceSet, URI
    from pyecore.utils import DynamicEPackage

    rset = ResourceSet()
    mm_rs = rset.get_resource(URI('./common/spartamodel.ecore'))
    mm_root = mm_rs.contents[0]
    rset.metamodel_registry[mm_root.nsURI] = mm_root # register package NS in the resource set

    Sparta = DynamicEPackage(mm_root)
    stride = rset.get_resource(URI('./common/AndroidThreatTypeCatalog.sparta'))
    model = Sparta.DFDModel(name="Android Threat Model")
    model.resource.append(stride.contents[0])

    # Create App Trust Boundary
    tb_app = Sparta.TrustBoundaryContainer()
    # Create Android Trust Boundary
    tb_android = Sparta.TrustBoundaryContainer()
    # Add App Trust Boundary to Android Trust Boundary
    tb_android.containedElements.append(tb_app)
    # Add Android Trust Boundary to Model
    model.containedElements.append(tb_android)

    # Create Elements Dictionary
    # Key: Element Name
    # Value: Element DFD Object
    element_dict = {}

    # Check duplicated edges
    egde_list = []
    no_perm_list =[]
    
    # Create App External Entities
    # add_element_to_model(element_dict, "External Entities", 'ExternalEntity', tb_android, Sparta)
    exported_count = 0
    datastorage_count = 0
    web_count = 0
    sensitive_count = 0
    personal_data_accesses_count = 0
    no_permission_count = 0

    # Add Exported Components
    app_list_exported_comp = ['exported_act', 'exported_ser', 'exported_pro', 'exported_rev']
    for comp_type in app_list_exported_comp:
        for comp in man_an_dic[comp_type]:
            add_elements_and_dataflow_to_model(element_dict, "External Entities", comp, 
                                               DFD_ELEMENT_EXTERNAL_ENTITY_TYPE, DFD_ELEMENT_PROCESS_TYPE, 
                                               tb_android, tb_app, tb_android, Sparta)
            exported_count += 1
    
    # Draw ICC
    for u,v in icc_link:
        add_elements_and_dataflow_to_model(element_dict, u, v, 
                                    DFD_ELEMENT_PROCESS_TYPE, DFD_ELEMENT_PROCESS_TYPE, 
                                    tb_app, tb_app, tb_app, Sparta)

    # Draw Component-Class Link
    for u,v in components_class_link:
        add_elements_and_dataflow_to_model(element_dict, u, v, 
                                    DFD_ELEMENT_PROCESS_TYPE, DFD_ELEMENT_PROCESS_TYPE, 
                                    tb_app, tb_app, tb_app, Sparta)

    # Draw REST APIs
    for permission, links in rest_apis.items():
        if permission != NO_PERMISSION:
            for component,entity in links:
                if (component,entity) not in egde_list:
                    trust_zone = determine_trust_zone(permission, entity, tb_app, tb_android, model)
                    add_elements_and_dataflow_to_model(element_dict, component, entity, 
                                DFD_ELEMENT_PROCESS_TYPE, DFD_ELEMENT_EXTERNAL_ENTITY_TYPE, 
                                tb_app, trust_zone, trust_zone, Sparta, two_way=True)
                    egde_list.append((component,entity))
                    web_count += 2
        else:
            for component,entity in links:
                if (component,entity) not in no_perm_list:
                    no_permission_count += 2
                    no_perm_list.append((component,entity))

    # Draw Data Storanges
    for permission, links in data_storages.items():
        # If the data storage is local (no need permission), draw it in the same subgraph
        if permission != NO_PERMISSION:
            for component,entity in links:
                if (component,entity) not in egde_list:
                    trust_zone = determine_trust_zone(permission, entity, tb_app, tb_android, model)
                    add_elements_and_dataflow_to_model(element_dict, component, entity, 
                                DFD_ELEMENT_PROCESS_TYPE, DFD_ELEMENT_DATA_STORE_TYPE, 
                                tb_app, trust_zone, trust_zone, Sparta, two_way=True)
                    egde_list.append((component,entity))
                    datastorage_count += 2
        else:
            for component,entity in links:
                if (component,entity) not in no_perm_list:
                    no_permission_count += 2
                    no_perm_list.append((component,entity))
                

    # Draw Connections  
    for permission, links in connections.items():
        if permission != NO_PERMISSION:
            for component,entity in links:
                if (component,entity) not in egde_list:
                    trust_zone = determine_trust_zone(permission, entity, tb_app, tb_android, model)
                    add_elements_and_dataflow_to_model(element_dict, component, entity, 
                                DFD_ELEMENT_PROCESS_TYPE, DFD_ELEMENT_EXTERNAL_ENTITY_TYPE, 
                                tb_app, trust_zone, trust_zone, Sparta, two_way=True)
                    egde_list.append((component,entity))
                    sensitive_count += 2
        else:
            for component,entity in links:
                if (component,entity) not in no_perm_list:
                    no_permission_count += 2
                    no_perm_list.append((component,entity))
        

    # Draw Personal Data Access
    for permission, links in personal_data_accesses.items():
        if permission != NO_PERMISSION:
            for component,entity in links:
                print(component, entity)
                if (component,entity) not in egde_list:
                    trust_zone = determine_trust_zone(permission, entity, tb_app, tb_android, model)
                    add_elements_and_dataflow_to_model(element_dict, component, entity, 
                                DFD_ELEMENT_PROCESS_TYPE, DFD_ELEMENT_EXTERNAL_ENTITY_TYPE, 
                                tb_app, trust_zone, trust_zone, Sparta, two_way=True)
                    egde_list.append((component,entity))
                    personal_data_accesses_count += 2
        else:
            for component,entity in links:
                if (component,entity) not in no_perm_list:
                    no_permission_count += 2
                    no_perm_list.append((component,entity))
                            
    #output_rs = rset.create_resource(URI('exp/'+APK_FILE_NAME+'.sparta'))
    output_rs = rset.create_resource(URI(APK_DIRECTORY + "/" +APK_FILE_NAME+'.sparta'))
    output_rs.use_uuid = True
    output_rs.append(model)
    output_rs.save()

    # Elicit Threats to CSV
    logging.debug("Elicit Threats to CSV")
    elicit_threat_with_sparta(APK_DIRECTORY + '/' + APK_FILE_NAME+'.sparta', APK_DIRECTORY +'/' +APK_FILE_NAME+'.csv')
    #elicit_threat_with_sparta('exp/'+APK_FILE_NAME+'.sparta', 'exp/'+APK_FILE_NAME+'.csv')

    # Print Statistics
    logging.debug("Exported Components:\t %d", exported_count)
    logging.debug("Data Storages:\t %d", datastorage_count)
    logging.debug("Web APIs:\t %d", web_count)
    logging.debug("Sensitive Connections:\t %d", sensitive_count)
    logging.debug("Personal Data Access:\t %d", personal_data_accesses_count)
    logging.debug("No Permission Count:\t %d", no_permission_count)
    logging.debug("Total size of attack surfaces: \t %d", exported_count + datastorage_count + web_count + sensitive_count + personal_data_accesses_count)

    # Print Number of Threats
    logging.debug("Number of Threats:\t %d", len(open(APK_DIRECTORY+'/'+APK_FILE_NAME+'.csv').readlines()) - 1)

def elicit_threat_with_sparta(spartamodel, exported_csv_file):
    cmd = "java -jar" + " " + \
            CURRENT_DIRECTORY + "/tools/sparta-cli-2022.1.1-shaded.jar" + " " + "-i " + spartamodel + " " + "-oc " + exported_csv_file
    logging.debug("Elicit Threats with Sparta: %s", cmd)
    print(cmd)
    try:
        execute(cmd, timeout=10000)
    except Timeout:
        print(f"[*] Timed out ({10000} secs)")
        return False

def add_element_to_model(element_dict, element_name, element_type, parent_model, Sparta):
    if element_name not in element_dict:
        if element_type == 'Process':
            proc = Sparta.Process(name=element_name)
            element_dict[element_name] = proc
            parent_model.containedElements.append(proc)
        elif element_type == 'DataStore':
            ds = Sparta.DataStore(name=element_name)
            element_dict[element_name] = ds
            parent_model.containedElements.append(ds)
        elif element_type == 'ExternalEntity':
            ee = Sparta.ExternalEntity(name=element_name)
            element_dict[element_name] = ee
            parent_model.containedElements.append(ee)

def add_dataflow_to_model(element_dict, sender_name, recipient_name, parent_model, Sparta):
    df = Sparta.DataFlow(sender=element_dict[sender_name], recipient=element_dict[recipient_name], name=sender_name + '->' + recipient_name)
    parent_model.containedElements.append(df)

def add_elements_and_dataflow_to_model(element_dict, sender_name, recipient_name, sender_type, recipient_type, 
                                               sender_model, recipient_model, data_flow_model, Sparta, two_way=False):
    add_element_to_model(element_dict, sender_name, sender_type, sender_model, Sparta)
    add_element_to_model(element_dict, recipient_name, recipient_type, recipient_model, Sparta)
    add_dataflow_to_model(element_dict, sender_name, recipient_name, data_flow_model, Sparta)
    if two_way == True:
        add_dataflow_to_model(element_dict, recipient_name, sender_name, data_flow_model, Sparta)

def add_element_to_graph(element_name, element_type, graph):
    if element_type == 'Process':
        graph.node(element_name)
    elif element_type == 'DataStore':
        graph.node(element_name, shape=DATA_STORAGE_SHAPE, 
                    style='filled', 
                    color=DATA_STORAGE_COLOR)
    elif element_type == 'ExternalEntity':
        graph.node(element_name, shape=EXTERNAL_ENTITY_SHAPE, 
                           style='filled', color=EXTERNAL_ENTITY_COLOR)
    elif element_type == 'WebServer':
        graph.node(element_name, shape=REST_API_SHAPE, 
                   style='filled', color=REST_API_COLOR)
    elif element_type == 'Connection':
        graph.node(element_name, shape=CONNECTION_SHAPE, 
                   style='filled', color=CONNECTION_COLOR)
    elif element_type == 'PersonalData':
        graph.node(element_name, shape=PERSONAL_SHAPE, 
                   style='filled', color=PERSONAL_COLOR)
    elif element_type == "Permission":
        graph.node(element_name, shape=PERMISSION_SHAPE, 
                   style='filled', color=PERMISSION_COLOR)
        
def add_dataflow_to_graph(sender_name, recipient_name, cluster):
    cluster.edge(sender_name, recipient_name)

def add_elements_and_dataflow_to_graph(sender_name, recipient_name, sender_type, recipient_type, 
                                       sender_cluster, recipient_cluster, data_flow_cluster, two_way=False):
    add_element_to_graph(sender_name, sender_type, sender_cluster)
    add_element_to_graph(recipient_name, recipient_type, recipient_cluster)
    add_dataflow_to_graph(sender_name, recipient_name, data_flow_cluster)
    if two_way == True:
        add_dataflow_to_graph(recipient_name, sender_name, data_flow_cluster)

def check_node_exist_graphviz(graph, node_name):
    for n in graph.body:
        if n.startswith(node_name):
            return True
    return False

def split(list_a, chunk_size):
  for i in range(0, len(list_a), chunk_size):
    yield list_a[i:i + chunk_size]

def export_xml_file_for_sparta_exp(app_name, man_an_dic, data_storages, connections, rest_apis, personal_data_accesses, permissions, icc_link, components_class_link):
    import pyecore.type as xmltypes
    from pyecore.resources import ResourceSet, URI
    from pyecore.utils import DynamicEPackage

    rset = ResourceSet()
    mm_rs = rset.get_resource(URI('./common/spartamodel.ecore'))
    mm_root = mm_rs.contents[0]
    rset.metamodel_registry[mm_root.nsURI] = mm_root # register package NS in the resource set

    Sparta = DynamicEPackage(mm_root)
    stride = rset.get_resource(URI('./common/AndroidThreatTypeCatalog.sparta'))
    model = Sparta.DFDModel(name="Android Threat Model")
    model.resource.append(stride.contents[0])

    # Create App Trust Boundary
    tb_app = Sparta.TrustBoundaryContainer()
    # Create Android Trust Boundary
    tb_android = Sparta.TrustBoundaryContainer()
    # Add App Trust Boundary to Android Trust Boundary
    tb_android.containedElements.append(tb_app)
    # Add Android Trust Boundary to Model
    model.containedElements.append(tb_android)

    # Create Elements Dictionary
    # Key: Element Name
    # Value: Element DFD Object
    element_dict = {}

    # Check duplicated edges
    egde_list = []
    no_perm_list =[]
    
    # Create App External Entities
    # add_element_to_model(element_dict, "External Entities", 'ExternalEntity', tb_android, Sparta)
    exported_count = 0
    datastorage_count = 0
    web_count = 0
    sensitive_count = 0
    personal_data_accesses_count = 0
    no_permission_count = 0

    # Add Exported Components
    app_list_exported_comp = ['exported_act', 'exported_ser', 'exported_pro', 'exported_rev']
    for comp_type in app_list_exported_comp:
        for comp in man_an_dic[comp_type]:
            add_elements_and_dataflow_to_model(element_dict, "External Entities", comp, 
                                               DFD_ELEMENT_EXTERNAL_ENTITY_TYPE, DFD_ELEMENT_PROCESS_TYPE, 
                                               tb_android, tb_app, tb_android, Sparta)
            exported_count += 1
    
    # Draw ICC
    for u,v in icc_link:
        add_elements_and_dataflow_to_model(element_dict, u, v, 
                                    DFD_ELEMENT_PROCESS_TYPE, DFD_ELEMENT_PROCESS_TYPE, 
                                    tb_app, tb_app, tb_app, Sparta)

    # Draw Component-Class Link
    for u,v in components_class_link:
        add_elements_and_dataflow_to_model(element_dict, u, v, 
                                    DFD_ELEMENT_PROCESS_TYPE, DFD_ELEMENT_PROCESS_TYPE, 
                                    tb_app, tb_app, tb_app, Sparta)

    # Draw REST APIs
    for permission, links in rest_apis.items():
        if permission != NO_PERMISSION:
            for component,entity in links:
                if (component,entity) not in egde_list:
                    trust_zone = determine_trust_zone(permission, entity, tb_app, tb_android, model)
                    add_elements_and_dataflow_to_model(element_dict, component, entity, 
                                DFD_ELEMENT_PROCESS_TYPE, DFD_ELEMENT_EXTERNAL_ENTITY_TYPE, 
                                tb_app, trust_zone, trust_zone, Sparta, two_way=True)
                    egde_list.append((component,entity))
                    web_count += 2
        else:
            for component,entity in links:
                if (component,entity) not in no_perm_list:
                    no_permission_count += 2
                    no_perm_list.append((component,entity))

    # Draw Data Storanges
    for permission, links in data_storages.items():
        # If the data storage is local (no need permission), draw it in the same subgraph
        if permission != NO_PERMISSION:
            for component,entity in links:
                if (component,entity) not in egde_list:
                    trust_zone = determine_trust_zone(permission, entity, tb_app, tb_android, model)
                    add_elements_and_dataflow_to_model(element_dict, component, entity, 
                                DFD_ELEMENT_PROCESS_TYPE, DFD_ELEMENT_DATA_STORE_TYPE, 
                                tb_app, trust_zone, trust_zone, Sparta, two_way=True)
                    egde_list.append((component,entity))
                    datastorage_count += 2
        else:
            for component,entity in links:
                if (component,entity) not in no_perm_list:
                    no_permission_count += 2
                    no_perm_list.append((component,entity))
                

    # Draw Connections  
    for permission, links in connections.items():
        if permission != NO_PERMISSION:
            for component,entity in links:
                if (component,entity) not in egde_list:
                    trust_zone = determine_trust_zone(permission, entity, tb_app, tb_android, model)
                    add_elements_and_dataflow_to_model(element_dict, component, entity, 
                                DFD_ELEMENT_PROCESS_TYPE, DFD_ELEMENT_EXTERNAL_ENTITY_TYPE, 
                                tb_app, trust_zone, trust_zone, Sparta, two_way=True)
                    egde_list.append((component,entity))
                    sensitive_count += 2
        else:
            for component,entity in links:
                if (component,entity) not in no_perm_list:
                    no_permission_count += 2
                    no_perm_list.append((component,entity))
        

    # Draw Personal Data Access
    for permission, links in personal_data_accesses.items():
        if permission != NO_PERMISSION:
            for component,entity in links:
                print(component, entity)
                if (component,entity) not in egde_list:
                    trust_zone = determine_trust_zone(permission, entity, tb_app, tb_android, model)
                    add_elements_and_dataflow_to_model(element_dict, component, entity, 
                                DFD_ELEMENT_PROCESS_TYPE, DFD_ELEMENT_EXTERNAL_ENTITY_TYPE, 
                                tb_app, trust_zone, trust_zone, Sparta, two_way=True)
                    egde_list.append((component,entity))
                    personal_data_accesses_count += 2
        else:
            ### Need a for loop here
            for component,entity in links:
                if (component,entity) not in no_perm_list:
                    no_permission_count += 2
                    no_perm_list.append((component,entity))
                       
                            
    output_rs = rset.create_resource(URI('exp/'+APK_FILE_NAME+'.sparta'))
    #output_rs = rset.create_resource(URI(APK_DIRECTORY + "/" +APK_FILE_NAME+'.sparta'))
    output_rs.use_uuid = True
    output_rs.append(model)
    output_rs.save()

    # Elicit Threats to CSV
    logging.debug("Elicit Threats to CSV")
    #elicit_threat_with_sparta(APK_DIRECTORY + '/' + APK_FILE_NAME+'.sparta', APK_DIRECTORY +'/' +APK_FILE_NAME+'.csv')
    elicit_threat_with_sparta('exp/'+APK_FILE_NAME+'.sparta', 'exp/'+APK_FILE_NAME+'.csv')

    # Print Statistics
    logging.debug("Exported Components:\t %d", exported_count)
    logging.debug("Data Storages:\t %d", datastorage_count)
    logging.debug("Web APIs:\t %d", web_count)
    logging.debug("Sensitive Data:\t %d", sensitive_count)
    logging.debug("Personal Data Access:\t %d", personal_data_accesses_count)
    logging.debug("No Permission Count:\t %d", no_permission_count)
    logging.debug("Total size of attack surfaces: \t %d", exported_count + datastorage_count + web_count + sensitive_count)

    # Print Number of Threats
    #logging.debug("Number of Threats:\t %d", len(open(APK_DIRECTORY+'/'+APK_FILE_NAME+'.csv').readlines()) - 1)
        # Print Number of Threats
    number_of_threats = len(open('exp/'+APK_FILE_NAME+'.csv').readlines()) - 1
    logging.debug("Number of Threats:\t %d", number_of_threats)

    return exported_count, datastorage_count, web_count, sensitive_count, personal_data_accesses_count, no_permission_count, len(element_dict), number_of_threats


def experiment(apk_file_name, APK_DIRECTORY, FILE_PATH):
    experiment_info = {}
    start_time = time.time()
    #print("APK file: " + FILE_PATH)

    global APK_FILE_NAME
    APK_FILE_NAME = apk_file_name

    
    # redirect stdout to a file
    import sys

    orig_stdout = sys.stdout
    f = open("exp/"+apk_file_name+"_log.txt", 'w')
    sys.stdout = f

    app_dic={}
    elf_dict={}
    app_dic['app_file'] = apk_file_name
    app_dic['app_dir'] = APK_DIRECTORY
    app_dic['app_path'] = FILE_PATH
    app_dic['tools_dir'] = "tools"
    elf_dict = elf_analysis(app_dic['app_dir'])
    logging.info("Finished setting up the app_dic and elf_dict")

    # Identify exported components
    man_an_dic, man_data_dic = analyze_manifest(app_dic)
    logging.info("Finished analyzing the manifest")

    # Add main activity to exported components
    man_an_dic['exported_act'].append(man_data_dic['mainactivity'])

    print_exported_components(man_an_dic)

    # Get list of components
    # components: [activity, service, receiver, provider]
    components = get_list_components(man_data_dic)

    # Print permissions which are defined in manifest file.
    print_permissions(man_an_dic['permissions'])

    
    manifest_analysis_time = time.time()
    manifest_analysis_duration = manifest_analysis_time - start_time


    # Perform static analysis to get strings, api calls (REST api, Data storages api and other connections api) from java files.
    code_an_dic = code_analysis_apk(app_dic)
    web_duration = code_an_dic['web_duration']
    db_duration = code_an_dic['db_duration']
    conn_duration = code_an_dic['conn_duration']
    personal_duration = code_an_dic['personal_duration']

    logging.info("Finished analyzing the code using static analysis")

    # Output REST API mapping
    # with open("restapis.json", "w") as outfile:
    #     json.dump(code_an_dic['raw_api'], outfile)
    
    # with open("urls.json", "w") as outfile:
    #     json.dump(code_an_dic['urls'], outfile)

    # Get app name
    app_name = get_strings_from_apk(app_dic, elf_dict, code_an_dic)
    
    # Filter out the garbage urls
    # filter_urls(code_an_dic)

    code_analysis_time = time.time()
    code_analysis_duration = code_analysis_time - manifest_analysis_time

    # Get mapping between REST API and URL
    url_mapping = mapping_rest_api_calls_and_urls(code_an_dic['api'], code_an_dic['urls'])
    logging.info("Finished mapping REST API calls and URLs")
    logging.debug("URL Mapping %s", url_mapping)

    # Get list domain names.
    domains = get_rest_api_server(code_an_dic)

    source_class = [] #List of classes that are not components but have communication with API calls
    
    # Print informations
    print_rest_api_server(domains)
    print_urls_n_ref(code_an_dic['urls'])

    # Rest APIs
    rest_apis = print_and_extract_api_and_ref(code_an_dic['api'], "HTTP APIS")
    rest_apis_mapping = mapping_permission_zones_and_api_calls(rest_apis, man_an_dic['permissions'])
    logging.debug("REST API mapping %s", rest_apis_mapping)
    source_class =  append_two_list_with_unique_items(source_class, get_list_source_class(rest_apis_mapping, components))
    logging.info("Finished mapping REST API calls and permissions")

    # Data storages
    data_storages = print_and_extract_api_and_ref(code_an_dic['dbs'], "DATA STORAGES")
    # data_storages_mapping: {permission_zone: [(component, api_call), (component, api_call), ...], permission_zone: [(component, api_call), (component, api_call), ...], ...}
    data_storages_mapping = mapping_permission_zones_and_api_calls(data_storages, man_an_dic['permissions'])
    logging.debug("Data Storages mapping %s", data_storages_mapping)
    source_class =  append_two_list_with_unique_items(source_class, get_list_source_class(data_storages_mapping, components))
    logging.info("Finished mapping DATA STORAGES calls and permissions")

    #print(source_class)

    # Connections
    connections = print_and_extract_api_and_ref(code_an_dic['conn'], "CONNECTIONS")
    # connections_mapping: {permission_zone: [(component, api_call), (component, api_call), ...], permission_zone: [(component, api_call), (component, api_call), ...], ...}
    connections_mapping = mapping_permission_zones_and_api_calls(connections, man_an_dic['permissions'])
    logging.debug("Connections mapping %s", connections_mapping)
    source_class =  append_two_list_with_unique_items(source_class, get_list_source_class(connections_mapping, components))
    logging.info("Finished mapping CONNECTIONS calls and permissions")

    # Personal Data Access
    personal_data_access = print_and_extract_api_and_ref(code_an_dic['personal'], "PERSONAL DATA ACCESS")
    # connections_mapping: {permission_zone: [(component, api_call), (component, api_call), ...], permission_zone: [(component, api_call), (component, api_call), ...], ...}
    personal_data_access_mapping = mapping_permission_zones_and_api_calls(personal_data_access, man_an_dic['permissions'])
    logging.debug("Personal data access mapping %s", personal_data_access_mapping)
    source_class =  append_two_list_with_unique_items(source_class, get_list_source_class(personal_data_access_mapping, components))
    logging.info("Finished mapping PERSONAL DATA ACCESS calls and permissions")


    # Export Source classes
    export_source_classes(source_class)
    permission_mapping_time = time.time()
    permission_mapping_duration = permission_mapping_time - code_analysis_time

    icc_link = []
    # logging.info("ICC mode: " + ICC_MODE)
    # logging.debug("File Path: %s", FILE_PATH)
    # # Extract the ICC of the application
    # if ICC_MODE == "ICCBot":
    #     #print("In ICCBot mode")
    #     icc_link = exportICCBot(apk_path=FILE_PATH)
    #     logging.debug("ICC Links: %s", icc_link)
    # else:
    #     #print("In ICC Others mode")
    #     icc_link = exportICC(apk_path=FILE_PATH, type=ICC_MODE) #If the component does not have a connection, it will not be in the list
    #     logging.debug("ICC Links: %s", icc_link)
    # logging.info("Finished extracting ICC")
    
    components_class_link   = []
    # # Extract the Component-Class Link of the application
    # components_class_link = exportComponentClassLink(apk_path=FILE_PATH)
    # logging.debug("Component-Class Links: %s", components_class_link)
    # logging.info("Finished extracting Component-Class Link")

    # # draw the threat model
    draw_threat_model_graph_exp(app_name, man_an_dic, data_storages_mapping, connections_mapping, rest_apis_mapping, personal_data_access_mapping, man_an_dic['permissions'], icc_link, components_class_link)
    export_dfd_graph_time = time.time()
    export_dfd_graph_duration = export_dfd_graph_time - permission_mapping_time
    
    exported_count, datastorage_count, web_count, sensitive_count, personal_data_accesses_count, no_permission_count, node_count, number_of_threats = export_xml_file_for_sparta_exp(app_name, man_an_dic, data_storages_mapping, connections_mapping, rest_apis_mapping, personal_data_access_mapping, man_an_dic['permissions'], icc_link, components_class_link)
    threat_modeling_with_sparta_time = time.time()
    threat_modeling_with_sparta_duration = threat_modeling_with_sparta_time - export_dfd_graph_time

    logging.info("Finished drawing the threat model")

    total_duration = threat_modeling_with_sparta_time - start_time

    sys.stdout = orig_stdout
    f.close()
    experiment_info = {
        "total_duration": total_duration,
        "manifest_analysis_duration": manifest_analysis_duration,
        "decompile_duration": code_analysis_duration-(web_duration+db_duration+conn_duration+personal_duration),
        "web_duration": web_duration,
        "db_duration": db_duration,
        "conn_duration": conn_duration,
        "personal_duration": personal_duration,
        "code_analysis_duration": web_duration+db_duration+conn_duration+personal_duration,
        "permission_mapping_duration": permission_mapping_duration,
        "export_dfd_graph_duration": export_dfd_graph_duration,
        "threat_modeling_with_sparta_duration": threat_modeling_with_sparta_duration,
        "exported_count": exported_count,
        "datastorage_count": datastorage_count,
        "web_count": web_count,
        "sensitive_count": sensitive_count,
        "personal_data_accesses_count": personal_data_accesses_count,
        "no_permission_count": no_permission_count,
        "node_count": node_count,
        "number_of_threats": number_of_threats,
    }
    return experiment_info

def backend_analysis(apk_file_name, apk_directory, tpl, icc):
    start_time = time.time()
    #print("APK file: " + FILE_PATH)

    global APK_FILE_NAME
    global APK_DIRECTORY
    global FILE_PATH
    global LIB_ANALYSIS
    global ICC_MODE
    
    APK_DIRECTORY = apk_directory
    APK_FILE_NAME = apk_file_name
    ICC_MODE = icc
    LIB_ANALYSIS = tpl

    print("ICC_MODE: " + ICC_MODE)
    print("LIB_ANALYSIS: " + LIB_ANALYSIS)
    
    FILE_PATH = APK_DIRECTORY + "/" + APK_FILE_NAME
    print("FILE_PATH: " + FILE_PATH)

    app_dic={}
    elf_dict={}
    app_dic['app_file'] = APK_FILE_NAME
    app_dic['app_dir'] = APK_DIRECTORY
    app_dic['app_path'] = FILE_PATH
    app_dic['tools_dir'] = "tools"
    elf_dict = elf_analysis(app_dic['app_dir'])
    logging.info("Finished setting up the app_dic and elf_dict")

    # Identify exported components
    man_an_dic, man_data_dic = analyze_manifest(app_dic)
    logging.info("Finished analyzing the manifest")

    # Add main activity to exported components
    man_an_dic['exported_act'].append(man_data_dic['mainactivity'])

    print_exported_components(man_an_dic)

    # Get list of components
    # components: [activity, service, receiver, provider]
    components = get_list_components(man_data_dic)

    # Print permissions which are defined in manifest file.
    print_permissions(man_an_dic['permissions'])

    # Perform static analysis to get strings, api calls (REST api, Data storages api and other connections api) from java files.
    code_an_dic = code_analysis_apk(app_dic)
    logging.info("Finished analyzing the code using static analysis")

    # Output REST API mapping
    # with open("restapis.json", "w") as outfile:
    #     json.dump(code_an_dic['raw_api'], outfile)
    
    # with open("urls.json", "w") as outfile:
    #     json.dump(code_an_dic['urls'], outfile)

    # Get app name
    app_name = get_strings_from_apk(app_dic, elf_dict, code_an_dic)
    
    # Filter out the garbage urls
    # filter_urls(code_an_dic)

    # Get mapping between REST API and URL
    url_mapping = mapping_rest_api_calls_and_urls(code_an_dic['api'], code_an_dic['urls'])
    logging.info("Finished mapping REST API calls and URLs")
    logging.debug("URL Mapping %s", url_mapping)

    # Get list domain names.
    domains = get_rest_api_server(code_an_dic)

    source_class = [] #List of classes that are not components but have communication with API calls
    
    # Print informations
    print_rest_api_server(domains)
    print_urls_n_ref(code_an_dic['urls'])

    # Rest APIs
    rest_apis = print_and_extract_api_and_ref(code_an_dic['api'], "HTTP APIS")
    rest_apis_mapping = mapping_permission_zones_and_api_calls(rest_apis, man_an_dic['permissions'])
    logging.debug("REST API mapping %s", rest_apis_mapping)
    source_class =  append_two_list_with_unique_items(source_class, get_list_source_class(rest_apis_mapping, components))
    logging.info("Finished mapping REST API calls and permissions")

    # Data storages
    data_storages = print_and_extract_api_and_ref(code_an_dic['dbs'], "DATA STORAGES")
    # data_storages_mapping: {permission_zone: [(component, api_call), (component, api_call), ...], permission_zone: [(component, api_call), (component, api_call), ...], ...}
    data_storages_mapping = mapping_permission_zones_and_api_calls(data_storages, man_an_dic['permissions'])
    #print(data_storages_mapping)
    logging.debug("Data Storages mapping %s", data_storages_mapping)
    source_class =  append_two_list_with_unique_items(source_class, get_list_source_class(data_storages_mapping, components))
    logging.info("Finished mapping DATA STORAGES calls and permissions")

    #print(source_class)

    # Connections
    connections = print_and_extract_api_and_ref(code_an_dic['conn'], "CONNECTIONS")
    # connections_mapping: {permission_zone: [(component, api_call), (component, api_call), ...], permission_zone: [(component, api_call), (component, api_call), ...], ...}
    connections_mapping = mapping_permission_zones_and_api_calls(connections, man_an_dic['permissions'])
    #print(connections_mapping)
    logging.debug("Connections mapping %s", connections_mapping)
    source_class =  append_two_list_with_unique_items(source_class, get_list_source_class(connections_mapping, components))
    logging.info("Finished mapping CONNECTIONS calls and permissions")

    # Export Source classes
    export_source_classes(source_class)

    icc_link = []
    logging.info("ICC mode: " + ICC_MODE)
    logging.debug("File Path: %s", FILE_PATH)
    components_class_link = []
    # Extract the ICC of the application
    if ICC_MODE != "None":    
        if ICC_MODE == "ICCBot":
            #print("In ICCBot mode")
            icc_link = exportICCBot(apk_path=FILE_PATH)
            logging.debug("ICC Links: %s", icc_link)    
        else:
            #print("In ICC Others mode")
            icc_link = exportICC(apk_path=FILE_PATH, type=ICC_MODE) #If the component does not have a connection, it will not be in the list
            logging.debug("ICC Links: %s", icc_link)
        logging.info("Finished extracting ICC")
        # Extract the Component-Class Link of the application
        components_class_link = exportComponentClassLink(apk_path=FILE_PATH)
        logging.debug("Component-Class Links: %s", components_class_link)
        logging.info("Finished extracting Component-Class Link")
    else:
        logging.info("Skip extracting ICC")    

    # # draw the threat model
    draw_threat_model_graph(app_name, man_an_dic, url_mapping, data_storages_mapping, connections_mapping, rest_apis_mapping, man_an_dic['permissions'], icc_link, components_class_link)
    #export_xml_file_for_sparta(app_name, man_an_dic, url_mapping, data_storages_mapping, connections_mapping, rest_apis_mapping, man_an_dic['permissions'], icc_link, components_class_link)
    logging.info("Finished drawing the threat model")
    clean(app_dic['app_dir']+"/apktool_out")
    clean(app_dic['app_dir']+"/java_source")

if __name__ == "__main__":
    start_time = time.time()
    main()
    print("--- %s seconds ---" % (time.time() - start_time))


