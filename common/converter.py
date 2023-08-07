# -*- coding: utf_8 -*-
"""Module holding the functions for converting."""

import glob
import logging
import os
import platform
import shutil
import subprocess
import threading
import stat

#from django.conf import settings

from common.utils import (
    is_file_exists,
)
import settings as settings

logger = logging.getLogger(__name__)



def apk_2_java(app_path, app_dir, tools_dir):
    """Run jadx."""
    try:
        logger.info('APK -> JAVA')
        args = []
        output = os.path.join(app_dir, 'java_source/')
        logger.info('Decompiling to Java with jadx')

        if os.path.exists(output):
            # ignore WinError3 in Windows
            shutil.rmtree(output, ignore_errors=True)

        if (len(settings.JADX_BINARY) > 0
                and is_file_exists(settings.JADX_BINARY)):
            jadx = settings.JADX_BINARY
        elif platform.system() == 'Windows':
            jadx = os.path.join(tools_dir, 'jadx/bin/jadx.bat')
        else:
            jadx = os.path.join(tools_dir, 'jadx/bin/jadx')
        # Set execute permission, if JADX is not executable
        if not os.access(jadx, os.X_OK):
            os.chmod(jadx, stat.S_IEXEC)
        args = [
            jadx,
            '-ds',
            output,
            '-q',
            '-r',
            '--show-bad-code',
            app_path,
        ]
        fnull = open(os.devnull, 'w')
        subprocess.run(args,
                       stdout=fnull,
                       stderr=subprocess.STDOUT,
                       timeout=settings.JADX_TIMEOUT)
    except subprocess.TimeoutExpired:
        logger.warning('Decompiling with jadx timed out')
    except Exception:
        logger.exception('Decompiling to JAVA')
