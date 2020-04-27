import base64
import os
import shutil
import subprocess
from ..mongo import mongo


def start_aquatone(subdomain_list):

    # Subdomains are already alive
    # We need to put the subdomains into a text file for feeding it into aquatone

    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    OUTPUT_DIR = ROOT_DIR + '/tools_output'
    if not os.path.exists(OUTPUT_DIR + '/aquatone'):
        os.makedirs(OUTPUT_DIR + '/aquatone')

    OUTPUT_DIR = ROOT_DIR + '/tools_output' + '/aquatone'
    INPUT_DIR = OUTPUT_DIR + '/aquatone_input.txt'
    AQUATONE_DIR = ROOT_DIR + '/tools/aquatone'

    print('------------------- AQUATONE STARTING -------------------')
    print('Scanning ' + str(len(subdomain_list)) + ' targets')
    for subdomain in subdomain_list:
        run_aquatone(subdomain['name'], AQUATONE_DIR, OUTPUT_DIR)

    cleanup(OUTPUT_DIR)

    return


def run_aquatone(subdomain, AQUATONE_DIR, OUTPUT_DIR):

    print('Scanning ' + subdomain)
    command = ['echo', subdomain, '|', AQUATONE_DIR, '-ports', 'large', '-out', OUTPUT_DIR]
    aquatone_process = subprocess.run(
       ' '.join(command), shell=True)

    # Parsing de resultados
    parse_results(subdomain, OUTPUT_DIR)
    # Cleanup
    cleanup_after_scan(OUTPUT_DIR)

    return


def parse_results(subdomain, OUTPUT_DIR):

    # Check if we have http and https
    with open(OUTPUT_DIR + '/aquatone_urls.txt') as fp:
        lines = fp.read()
        urls = lines.split('\n')

    if urls:
        urls_string = ';'.join(urls)
        has_urls = 'True'
    else:
        urls_string = ''
        has_urls = 'False'

    http_image_string = ''
    https_image_string = ''
    image_files = os.listdir(OUTPUT_DIR + '/screenshots')
    if image_files:
        for image in image_files:
            if 'http__' in image:
                with open(OUTPUT_DIR + '/screenshots/' + image, "rb") as image_file:
                    http_image_string = base64.b64encode(image_file.read())
            if 'https__' in image:
                with open(OUTPUT_DIR + '/screenshots/' + image, "rb") as image_file:
                    https_image_string = base64.b64encode(image_file.read())

    mongo.add_urls_to_subdomain(subdomain, has_urls, urls_string)
    mongo.add_images_to_subdomain(subdomain, http_image_string, https_image_string)

    return


def cleanup_after_scan(OUTPUT_DIR):
    try:
        os.remove(OUTPUT_DIR + '/aquatone_report.html')
    except FileNotFoundError as e:
        print("Error: %s : %s" % (OUTPUT_DIR + '/headers', e.strerror))
    try:
        os.remove(OUTPUT_DIR + '/aquatone_session.json')
    except FileNotFoundError as e:
        print("Error: %s : %s" % (OUTPUT_DIR + '/aquatone_session.json', e.strerror))
    try:
        os.remove(OUTPUT_DIR + '/aquatone_urls.txt')
    except FileNotFoundError as e:
        print("Error: %s : %s" % (OUTPUT_DIR + '/aquatone_urls.txt', e.strerror))
    try:
        shutil.rmtree(OUTPUT_DIR + '/headers')
    except OSError as e:
        print("Error: %s : %s" % (OUTPUT_DIR + '/headers', e.strerror))
    try:
        shutil.rmtree(OUTPUT_DIR + '/html')
    except OSError as e:
        print("Error: %s : %s" % (OUTPUT_DIR + '/html', e.strerror))
    try:
        shutil.rmtree(OUTPUT_DIR + '/screenshots')
    except OSError as e:
        print("Error: %s : %s" % (OUTPUT_DIR + '/screenshots', e.strerror))

    return


def cleanup(OUTPUT_DIR):

    try:
        shutil.rmtree(OUTPUT_DIR)
    except OSError as e:
        print("Error: %s : %s" % (OUTPUT_DIR, e.strerror))
    return