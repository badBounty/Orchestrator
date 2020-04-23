from ..mongo import mongo
from ..slack import slack_sender

import subprocess
import os
from os import path
from datetime import datetime
import time
import requests
import json


def run_recon(target_name, project_name='None', user_name='None'):

    # /home/handerllon/Desktop/OrchestratorV1/Orchestrator/src/recon
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    OUTPUT_DIR = ROOT_DIR + '/tools_output'

    # Recon start notification
    slack_sender.send_recon_start_message(target_name)

    if not path.exists(OUTPUT_DIR + '/' + target_name):
        os.makedirs(OUTPUT_DIR + '/' + target_name)

    PROJECT_DIR = OUTPUT_DIR + '/' + target_name

    # Commands
    amass_dir = ROOT_DIR + '/tools/amass'
    subfinder_dir = ROOT_DIR + '/tools/subfinder'
    sublist3r_dir = ROOT_DIR + "/tools/Sublist3r/sublist3r.py"

    # Amass
    print('------------------- AMASS STARTING -------------------')
    amass_process = subprocess.run(
       [amass_dir, 'enum', '-active', '-d', target_name, '-o', PROJECT_DIR + '/amass_out.txt', '-timeout', '10'])
    if path.exists(PROJECT_DIR + '/amass_out.txt'):
        print('------------------- AMASS FINISHED CORRECTLY -------------------')

    # Subfinder
    print('------------------- SUBFINDER STARTING -------------------')
    subfinder_process = subprocess.run([subfinder_dir, '-d', target_name, '-o', PROJECT_DIR + '/subfinder_out.txt'])
    if path.exists(PROJECT_DIR + '/subfinder_out.txt'):
        print('------------------- SUBFINDER FINISHED CORRECTLY -------------------')

    # sublist3r
    print('------------------- SUBLIST3R STARTING -------------------')
    sublist3r_process = subprocess.run(
       ['python3', sublist3r_dir, '-d', target_name, '-o', PROJECT_DIR + '/sublist3r_out.txt'])
    if path.exists(PROJECT_DIR + '/sublist3r_out.txt'):
        print('------------------- SUBLIST3R FINISHED CORRECTLY -------------------')

    parse_results(PROJECT_DIR)
    gather_data(PROJECT_DIR, project_name, user_name, target_name)
    cleanup(PROJECT_DIR, OUTPUT_DIR, target_name)

    slack_sender.send_recon_end_message(target_name)

    return


def parse_results(project_dir):
    filenames = [project_dir + '/amass_out.txt', project_dir + '/subfinder_out.txt', project_dir + '/sublist3r_out.txt']
    with open(project_dir + '/all.txt', 'w') as outfile:
        for fname in filenames:
            with open(fname) as infile:
                outfile.write(infile.read())

    lines = open(project_dir + '/all.txt', 'r').readlines()
    lines = [line for line in lines if ('<' not in line or '>' not in line)]
    lines = [line.lower() for line in lines]
    lines = list(dict.fromkeys(lines))
    lines_set = set(lines)
    out = open(project_dir + '/all.txt', 'w')
    for line in lines_set:
        out.write(line)
    out.close()

    return


def gather_data(project_dir, project_name, user_name, target_name):
    # Take final text file and run through API that checks information
    # Here we call the add_to_db
    timestamp = datetime.now()
    lines = open(project_dir + '/all.txt', 'r').readlines()

    for url in lines:
        url = url.replace('\n', '')
        # (dig $subdomain +short | sed '/[a-z]/d')
        try:
            is_alive = subprocess.check_output(['dig', url, '+short', '|', 'sed', "'/[a-z]/d'"])
        except subprocess.CalledProcessError:
            continue
        if is_alive.decode():
            is_alive_clause = 'True'
        else:
            is_alive_clause = 'False'
        try:
            has_ip = subprocess.check_output(['dig', url, '+short', '|', 'sed', "'/[a-z]/d'", '|', 'sed', '-n', 'lp'])
        except subprocess.CalledProcessError:
            continue
        if has_ip.decode():
            value = has_ip.decode().split('\n')
            ip = value[-2]
            gather_additional_info(project_name, user_name, is_alive_clause, ip, url, target_name)

        else:
            ip = None
            mongo.add_resource(project_name, user_name, url, is_alive_clause, timestamp, timestamp, ip, target_name,
                                 None, None, None, None, None, None, None, None)

    return


def gather_additional_info(project_name, user_name, is_alive, ip, url, target_name):
    timestamp = datetime.now()
    response = requests.get('http://ip-api.com/json/' + ip, verify=False)
    response_json = response.content.decode().replace('as', 'asn')
    parsed_json = json.loads(response_json)
    try:
        mongo.add_resource(
                        project_name,
                        user_name,
                        url,
                        is_alive,
                        timestamp,
                        timestamp,
                        ip,
                        target_name,
                        parsed_json['isp'],
                        parsed_json['asn'],
                        parsed_json['country'],
                        parsed_json['region'],
                        parsed_json['city'],
                        parsed_json['org'],
                        parsed_json['lat'],
                        parsed_json['lon'])
    except KeyError:
        time.sleep(1)
        return
    time.sleep(1)
    return


def cleanup(PROJECT_DIR, OUTPUT_DIR, target_name):
    try:
        os.remove(PROJECT_DIR + '/all.txt')
    except FileNotFoundError:
        pass
    try:
        os.remove(PROJECT_DIR + '/amass_out.txt')
    except FileNotFoundError:
        pass
    try:
        os.remove(PROJECT_DIR + '/subfinder_out.txt')
    except FileNotFoundError:
        pass
    try:
        os.remove(PROJECT_DIR + '/sublist3r_out.txt')
    except FileNotFoundError:
        pass
