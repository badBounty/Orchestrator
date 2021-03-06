import requests,os,subprocess,traceback
import base64
from PIL import Image
from io import BytesIO
from datetime import datetime
import uuid
import copy
import time

from ..mongo import mongo
from ..comms import image_creator
from ..slack import slack_sender
from ..redmine import redmine
from .. import constants
from ...objects.vulnerability import Vulnerability


def handle_target(info):
    print('Module IIS Shortname starting against '+ str(len(info['url_to_scan'])) + ' targets')
    slack_sender.send_simple_message("Check and scann : %s. %d alive urls found!"% (info['target'], len(info['url_to_scan'])))
    subject = 'Module IIS Shortname Scan finished'
    desc = ''
    for url in info['url_to_scan']:
        sub_info = copy.deepcopy(info)
        sub_info['url_to_scan'] = url
        print('Scanning ' + url)
        finished_ok = scan_target(sub_info, sub_info['url_to_scan'])
        if finished_ok:
            desc = 'IIS Shortname Scan termino sin dificultades para el target {}\n'.format(info['url_to_scan'])
        else:
            desc = 'IIS Shortname Scan encontro un problema y no pudo correr para el target {}\n'.format(info['url_to_scan'])
    redmine.create_informative_issue(info,subject,desc)
    print('Module IIS Shortname finished')
    return


def handle_single(scan_info):
    print('Module IIS Shortname (single) scan started against %s' % scan_info['url_to_scan'])
    slack_sender.send_simple_message("IIS ShortName Scanner scan started against %s" % scan_info['url_to_scan'])
    info = copy.deepcopy(scan_info)
    finished_ok = scan_target(info, info['url_to_scan'])
    subject = 'Module IIS Shortname Scan finished'
    if finished_ok:
        desc = 'IIS Shortname Scan termino sin dificultades para el target {}'.format(info['url_to_scan'])
    else:
        desc = 'IIS Shortname Scan encontro un problema y no pudo correr para el target {}'.format(info['url_to_scan'])
    redmine.create_informative_issue(info,subject,desc)
    print('Module IIS Shortname (single) finished against %s' % scan_info['url_to_scan'])
    return


def scan_target(scan_info, url_to_scan):
    try:
        time.sleep(2)
        headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:76.0) Gecko/20100101 Firefox/78.0'}
        resp = requests.get(url_to_scan,headers=headers)
    except requests.exceptions.SSLError:
        return False
    except Exception:
        error_string = traceback.format_exc()
        print('ERROR on {0}, description:{1}'.format(url_to_scan,error_string))
        return False
    try:
        if 'IIS' in resp.headers['Server']:
            ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
            TOOL_DIR = ROOT_DIR + '/tools/IIS-ShortName-Scanner/iis_shortname_scanner.jar'
            CONFIG_DIR = ROOT_DIR + '/tools/IIS-ShortName-Scanner/config.xml'
            iis_process = subprocess.run(['java', '-jar', TOOL_DIR, '0', '10', url_to_scan, CONFIG_DIR],
                                         capture_output=True)
            message = iis_process.stdout.decode()
            if "NOT VULNERABLE" not in message:
                img_str = image_creator.create_image_from_string(message)
                random_filename = uuid.uuid4().hex
                output_dir = ROOT_DIR + '/tools_output/' + random_filename + '.png'
                im = Image.open(BytesIO(base64.b64decode(img_str)))
                im.save(output_dir, 'PNG')

                vulnerability = Vulnerability(constants.IIS_SHORTNAME_MICROSOFT, scan_info,
                                              "IIS Microsoft files and directories enumeration found at %s" % scan_info['url_to_scan'])

                vulnerability.add_image_string(img_str)
                vulnerability.add_attachment(output_dir, 'IIS-Result.png')
                slack_sender.send_simple_vuln(vulnerability)
                redmine.create_new_issue(vulnerability)
                mongo.add_vulnerability(vulnerability)
                os.remove(output_dir)
    except KeyError:
        pass
    except Exception:
        pass
    return True