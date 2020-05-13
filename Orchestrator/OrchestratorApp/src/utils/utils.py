import requests
import re
import math
import os
import subprocess

def get_js_files_linkfinder(url):
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    TOOL_DIR = ROOT_DIR + '/tools/LinkFinder/linkfinder.py'

    # python3 linkfinder.py -i https://sky.com/ -d -o cli
    linkfinder_out = subprocess.run(
        ['python3', TOOL_DIR, '-i', url, '-d', '-o', 'cli'],
        capture_output=True)

    output = linkfinder_out.stdout
    output = str(output).split('\\n')

    js_files = list()
    for found in output:
        if 'http' in found and found[-3:] == '.js':
            js_files.append(found)

    return found