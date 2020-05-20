import re
import requests
import urllib3
import subprocess
from datetime import datetime

from ..slack import slack_sender
from ..utils import utils
from .. import constants
from ..mongo import mongo
from ..redmine import redmine

regions = ['us-east-2', 'us-east-1', 'us-west-1', 'us-west-2', 'ap-east-1', 'ap-south-1', 'ap-northeast-3',
           'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ca-central-1', 'cn-north-1',
           'cn-northwest-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-north-1', 'me-south-1',
           'sa-east-1', 'us-gov-east-1', 'us-gov-west-1']

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def handle_target(target, url_list, language):
    print('------------------- S3BUCKET TARGET SCAN STARTING -------------------')
    slack_sender.send_simple_message("Bucket finder scan started against target: %s. %d alive urls found!"
                                     % (target, len(url_list)))
    print('Found ' + str(len(url_list)) + ' targets to scan')
    for url in url_list:
        print('Scanning ' + url['url_with_http'])
        scan_target(url['target'], url['url_with_http'], language)
    print('------------------- S3BUCKET TARGET SCAN FINISHED -------------------')
    return


def handle_single(url, language):
    print('------------------- S3BUCKET SINGLE SCAN STARTING -------------------')
    slack_sender.send_simple_message("Bucket finder scan started against %s" % url)
    scan_target(url, url, language)
    print('------------------- S3BUCKET SINGLE SCAN FINISHED -------------------')
    return


def filter_invalids(some_list):
    res = []
    # ------ Filter invalid matches
    for item in some_list:
        if all(char not in item for char in ['\\', '=', '>', '<', '[', ']', '{', '}', ';', '(', ')']):
            res.append(item)
    return res


def scan_target(target_name, url_to_scan, language):
    # We first search for buckets inside the html code
    get_buckets(target_name, url_to_scan, url_to_scan, language)
    # We now scan javascript files
    javascript_files_found = utils.get_js_files_linkfinder(url_to_scan)
    print(str(len(javascript_files_found)) + ' javascript files found')
    for javascript in javascript_files_found:
        get_buckets(target_name, url_to_scan, javascript, language)
    return


def add_vulnerability_to_mongo(target, scanned_url, bucket_found_url, vulnerability, bucket_name, language):
    timestamp = datetime.now()
    vuln_name = None

    if language == constants.LANGUAGE_ENGLISH:
        if vulnerability == 'ls':
            vuln_name = constants.BUCKET_LS_ENGLISH
        elif vulnerability == 'nf':
            vuln_name = constants.BUCKET_NF_ENGLISH
        elif vulnerability == 'cprm':
            vuln_name = constants.BUCKET_CPRM_ENGLISH
    elif language == constants.LANGUAGE_SPANISH:
        if vulnerability == 'ls':
            vuln_name = constants.BUCKET_LS_SPANISH
        elif vulnerability == 'nf':
            vuln_name = constants.BUCKET_NF_SPANISH
        elif vulnerability == 'cprm':
            vuln_name = constants.BUCKET_CPRM_SPANISH

    redmine.create_new_issue(vuln_name, constants.REDMINE_BUCKET % (bucket_name, bucket_found_url))
    mongo.add_vulnerability(target, scanned_url, vuln_name,
                            timestamp, language, 'Bucket ' + bucket_name + ' found at ' + bucket_found_url)
    return


# Bucket that allows ls
def get_ls_buckets(bucket_list, target, sub_url, url_being_scanned, language):
    ls_allowed_buckets = []
    does_not_exist_buckets = []
    for bucket in bucket_list:
        if any(x.isupper() for x in bucket):
            continue
        try:
            output = subprocess.check_output('aws s3 ls s3://' + bucket, shell=True, stderr=subprocess.STDOUT)
            slack_sender.send_simple_vuln('Bucket ' + bucket + ' found at ' + url_being_scanned + ' with ls allowed')
            add_vulnerability_to_mongo(target, sub_url, url_being_scanned, 'ls',
                                       bucket, language)
            ls_allowed_buckets.append(bucket)
        except subprocess.CalledProcessError as e:
            if 'does not exist' in e.output.decode():
                slack_sender.send_simple_vuln(
                    'Bucket ' + bucket + ' found at ' + url_being_scanned + ' being used but does not exist')
                add_vulnerability_to_mongo(target, sub_url, url_being_scanned, 'nf',
                                           bucket, language)
                does_not_exist_buckets.append(bucket)
            continue
    return ls_allowed_buckets, does_not_exist_buckets


# Buckets that allow copy and remove
def get_cprm_buckets(bucket_list, target, sub_url, url_being_scanned, language):
    cprm_allowed_buckets = []
    for bucket in bucket_list:
        try:
            output = subprocess.check_output('aws s3 cp test.txt s3://' + bucket, shell=True, stderr=subprocess.DEVNULL)
            subprocess.check_output('aws s3 rm s3://' + bucket + '/test.txt', shell=True)
            slack_sender.send_simple_vuln('Bucket ' + bucket + ' found at ' + url_being_scanned + ' with cprm allowed')
            add_vulnerability_to_mongo(target, sub_url, url_being_scanned, 'cprm',
                                       bucket, language)
            cprm_allowed_buckets.append(bucket)
        except subprocess.CalledProcessError as e:
            continue
    return cprm_allowed_buckets


def get_buckets(target_name, from_url, url_to_scan, language):
    try:
        response = requests.get(url_to_scan, verify=False, timeout=3)
    except requests.exceptions.ConnectionError:
        return
    except requests.exceptions.ReadTimeout:
        return
    except Exception as e:
        return

    # Buckets can come in different ways
    # Way 1: http<s>://s3.amazonaws.com/bucketName
    # Way 2: http<s>://bucketName.s3.amazonaws.com
    # Way 3: //bucketName.s3.amazonaws.com
    # Way 4: https://s3-area.amazonaws.com/<bucketName>/
    # ---------Way I----------
    buckets_first_https = re.findall('"https://s3.amazonaws.com([^\"/,]+)"', response.text)
    buckets_first_https = filter_invalids(buckets_first_https)
    buckets_first_http = re.findall('"http://s3.amazonaws.com([^\"/,]+)"', response.text)
    buckets_first_http = filter_invalids(buckets_first_http)
    # ---------Way II----------
    buckets_second_https = re.findall('https://([^\"/,]+).s3.amazonaws.com', response.text)
    buckets_second_https = filter_invalids(buckets_second_https)
    buckets_second_http = re.findall('http://([^\"/,]+).s3.amazonaws.com', response.text)
    buckets_second_http = filter_invalids(buckets_second_http)
    # ---------Way III---------
    buckets_third = re.findall('\"//(.+?).s3.amazonaws.com', response.text)
    buckets_third = filter_invalids(buckets_third)
    # ---------Way IV----------
    buckets_fourth = re.findall('https://s3.amazonaws.com/(.+?)/', response.text)
    buckets_fourth = filter_invalids(buckets_fourth)
    way_iv_bis = re.findall('https://([^\"/,]+).s3.amazonaws.com/([^\"/,]+)/', response.text)
    for bucket in way_iv_bis:
        # In this case the match are tuples, not lists
        bucket = list(bucket)
        if any(x in regions for x in bucket[0]):
            buckets_fourth.append(bucket[1])
    # ---------Way IV----------
    buckets_fourth = re.findall('https://s3.amazonaws.com/(.+?)/', response.text)
    buckets_fourth = filter_invalids(buckets_fourth)

    buckets_fifth = list()
    way_v = re.findall('https://([^.\"/,]+).([^\"/,]+).amazonaws.com', response.text)
    for bucket in way_v:
        # In this case the match are tuples, not lists
        bucket = list(bucket)
        if 's3' in bucket[1]:
            buckets_fifth.append(bucket[0])

    bucket_list = buckets_first_http + buckets_second_http + buckets_first_https + buckets_second_https + buckets_third + buckets_fourth + buckets_fifth
    bucket_list = list(dict.fromkeys(bucket_list))
    for i in range(len(bucket_list)):
        bucket_list[i] = bucket_list[i].replace('/', '')

    # We now have to check the buckets
    ls_allowed, does_not_exist = get_ls_buckets(bucket_list, target_name, from_url, url_to_scan, language)
    cprm_allowed = get_cprm_buckets(bucket_list, target_name, from_url, url_to_scan, language)
    access_denied = list(set(bucket_list) - set(ls_allowed) - set(cprm_allowed) - set(does_not_exist))

