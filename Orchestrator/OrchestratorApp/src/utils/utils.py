import requests
import re
import math
import os
import subprocess
import time
import pycurl
import traceback
from io import BytesIO

from selenium import webdriver

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

regex_str = r"""
          (?:"|')                               # Start newline delimiter
          (
            ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
            [^"'/]{1,}\.                        # Match a domainname (any character + dot)
            [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path
            |
            ((?:/|\.\./|\./)                    # Start with /,../,./
            [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
            [^"'><,;|()]{1,})                   # Rest of the characters can't be
            |
            ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
            [a-zA-Z0-9_\-/]{1,}                 # Resource name
            \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
            (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters
            |
            ([a-zA-Z0-9_\-/]{1,}/               # REST API (no extension) with /
            [a-zA-Z0-9_\-/]{3,}                 # Proper REST endpoints usually have 3+ chars
            (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters
            |
            ([a-zA-Z0-9_\-]{1,}                 # filename
            \.(?:php|asp|aspx|jsp|json|
                 action|html|js|txt|xml)        # . + extension
            (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters
          )
          (?:"|')                               # End newline delimiter
        """

def get_response(url):
    try:
        response = requests.get(url, verify=False, timeout=3)
    except requests.exceptions.SSLError:
        print('Url %s raised SSL Error at utils.py' % url)
        return None
    except requests.exceptions.ConnectionError:
        print('Url %s raised Connection Error at utils.py' % url)
        return None
    except requests.exceptions.ReadTimeout:
        print('Url %s raised Read Timeout Error at utils.py' % url)
        return None
    except requests.exceptions.TooManyRedirects:
        print('Url %s raised Too many redirects Error at utils.py' % url)
        return None
    except Exception:
        error_string = traceback.format_exc()
        final_error = 'On {0}, was Found: {1}'.format(url,error_string)
        print(final_error)
        return None
    return response


def get_js_files(url):
    js_files = list()
    regex = re.compile(regex_str, re.VERBOSE)
    response = get_response(url)
    if response is None:
        return []
    all_matches = [(m.group(1), m.start(0), m.end(0)) for m in re.finditer(regex, response.text)]
    for match in all_matches:
        url = match[0]
        http_js = ['.js', 'http://']
        https_js = ['.js', 'https://']
        if all(substring in url for substring in http_js):
            js_files.append(url)
        if all(substring in url for substring in https_js):
            js_files.append(url)
    return js_files


def get_css_files_linkfinder(url):
    css_files = list()
    regex = re.compile(regex_str, re.VERBOSE)
    response = get_response(url)
    if response is None:
        return []
    all_matches = [(m.group(1), m.start(0), m.end(0)) for m in re.finditer(regex, response.text)]
    for match in all_matches:
        url = match[0]
        http_css = ['.css', 'http://']
        https_css = ['.css', 'https://']
        if all(substring in url for substring in http_css):
            css_files.append(url)
        if all(substring in url for substring in https_css):
            css_files.append(url)
    return css_files


def url_screenshot(url):
    global ROOT_DIR
    options = webdriver.ChromeOptions()
    options.add_argument('--no-sandbox') #Sino pongo esto rompe
    options.add_argument('--headless') #no cargue la ventana (background)
    driver = webdriver.Chrome(options=options)
    driver.set_window_size(1920,1080)
    driver.get(url)
    name = url.replace("http://","").replace("https://","").split("/")[0]
    OUTPUT_DIR = ROOT_DIR+'/../security/tools_output'
    driver.save_screenshot(OUTPUT_DIR+name+".png")
    driver.quit()
