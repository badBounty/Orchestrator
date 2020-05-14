import requests
import re
import math
import os
import subprocess
from selenium import webdriver

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

def get_js_files_linkfinder(url):
    global ROOT_DIR    
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

def url_screenshot(url):
    global ROOT_DIR
    options = webdriver.ChromeOptions()
    options.add_argument('--no-sandbox') #Sino pongo esto rompe
    options.add_argument('--headless') #no cargue la ventana (background)
    driver = webdriver.Chrome(options=options)
    driver.set_window_size(1920,1080)
    driver.get(url)
    print('--------------- TAKING URL SCREENSHOT ----------------')
    name = url.replace("http://","").replace("https://","").split("/")[0]
    OUTPUT_DIR = ROOT_DIR+'/../security/tools_output'
    driver.save_screenshot(OUTPUT_DIR+name+".png")
    driver.quit()
    print('---------------        DONE!!!!!!         ----------------')