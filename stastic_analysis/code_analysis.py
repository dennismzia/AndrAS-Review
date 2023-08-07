# -*- coding: utf_8 -*-
"""Module holding the functions for code analysis."""

import logging
from pathlib import Path

import settings as settings

from common.utils import filename_from_path
from common.shared_func import (
    url_n_email_extract,
)
from common.sast_engine import (
    niap_scan,
    scan,
)
import time

from tools.LiteRadar.LiteRadar.literadar import export_libs

logger = logging.getLogger(__name__)


def detect_third_party_libs(app_path):
    print(app_path)
    libs = export_libs(app_path)
    lib_paths = set()
    if libs:
        for lib in libs:
            #print(lib['Package'][1:])
            lib_paths.add(lib['Package'][1:])
    #print(lib_paths)
    return lib_paths

def code_analysis(app_dir, app_path, typ, manifest_file, lib_analysis="False"):
    """Perform the code analysis."""
    try:
        start_time = time.time()
        root = Path(settings.BASE_DIR)
        code_rules = root / 'rules' / 'android_rules.yaml'
        api_rules = root / 'rules' / 'android_apis.yaml'
        niap_rules = root / 'rules' / 'android_niap.yaml'
        db_rules = root / 'rules' / 'android_datastorage.yaml'
        conn_rules = root / 'rules' / 'android_connections.yaml'
        personal_rules = root / 'rules' / 'android_personal.yaml'
        code_findings = {}
        api_findings = {}
        db_findings = {}
        conn_findings = {}
        niap_findings = {}
        email_n_file = []
        url_n_file = []
        url_list = []
        app_dir = Path(app_dir)
        if typ == 'apk':
            src = app_dir / 'java_source'
        elif typ == 'studio':
            src = app_dir / 'app' / 'src' / 'main' / 'java'
            kt = app_dir / 'app' / 'src' / 'main' / 'kotlin'
            if not src.exists() and kt.exists():
                src = kt
        elif typ == 'eclipse':
            src = app_dir / 'src'
        src = src.as_posix() + '/'
        logging.info("Lib Analysis: %s", lib_analysis)
        if lib_analysis == "False":
            skp = settings.SKIP_CLASS_PATH
        else:
            skp = settings.SKIP_CLASS_PATH.union(detect_third_party_libs(app_path))
        #print("skp:", skp)
        logger.info('Code Analysis Started on - %s',
                    filename_from_path(src))
        # Code and API Analysis
        # code_findings = scan(
        #     code_rules.as_posix(),
        #     {'.java', '.kt'},
        #     [src],
        #     skp)
        logging.info("Set Up Time: %s", time.time() - start_time)
        start_time = time.time()
        api_findings, raw_api_findings = scan(
            api_rules.as_posix(),
            {'.java', '.kt'},
            [src],
            skp)
        web_time = time.time()
        web_duration = web_time - start_time
        logging.info("Web Connection Analysis Duration: %s", web_duration)


        db_findings, _ = scan(
            db_rules.as_posix(),
            {'.java', '.kt'},
            [src],
            skp)
        db_time = time.time()
        db_duration = db_time - web_time
        logging.info("DB Connection Analysis Duration: %s", db_duration)

        conn_findings, _ = scan(
            conn_rules.as_posix(),
            {'.java', '.kt'},
            [src],
            skp)
        conn_time = time.time()
        conn_duration = conn_time - db_time
        logging.info("Sensitive Connection Analysis Duration: %s", conn_duration)

        personal_findings, _ = scan(
            personal_rules.as_posix(),
            {'.java', '.kt'},
            [src],
            skp)
        personal_time = time.time()
        personal_duration = personal_time - conn_time
        logging.info("Personal Data Access Analysis Duration: %s", personal_duration)
        # NIAP Scan
        # logger.info('Running NIAP Analyzer')
        # niap_findings = niap_scan(
        #     niap_rules.as_posix(),
        #     {'.java', '.xml'},
        #     [src],
        #     manifest_file,
        #     None)
        # Extract URLs and Emails
        for pfile in Path(src).rglob('*'):
            if (
                (pfile.suffix in ('.java', '.kt')
                    and any(skip_path in pfile.as_posix()
                            for skip_path in skp) is False)
            ):
                content = None
                try:
                    content = pfile.read_text('utf-8', 'ignore')
                    # Certain file path cannot be read in windows
                except Exception:
                    continue
                relative_java_path = pfile.as_posix().replace(src, '')
                urls, urls_nf, emails_nf = url_n_email_extract(
                    content, relative_java_path)
                url_list.extend(urls)
                url_n_file.extend(urls_nf)
                email_n_file.extend(emails_nf)
        logger.info('Finished Code Analysis, Email and URL Extraction')
        url_time = time.time()
        url_duration = url_time - conn_time
        logging.info("URL Analysis Duration: %s", url_duration)

        code_an_dic = {
            'api': api_findings,
            'raw_api': raw_api_findings,
            'dbs': db_findings,
            'conn': conn_findings,
            'personal': personal_findings,
            'findings': code_findings,
            'niap': niap_findings,
            'urls_list': url_list,
            'urls': url_n_file,
            'emails': email_n_file,
            'web_duration': web_duration,
            'db_duration': db_duration,
            'conn_duration': conn_duration,
            'personal_duration': personal_duration,
        }
        return code_an_dic
    except Exception:
        logger.exception('Performing Code Analysis')