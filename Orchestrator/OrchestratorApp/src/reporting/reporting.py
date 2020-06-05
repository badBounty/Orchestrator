import os
from . import reportGenerator
from collections import defaultdict
from ..mongo import mongo


ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

"""
{'scan_type': 'single_target',
 'existing_target_choice': 'deloitte.com',
 'new_target_choice': '', 
 'single_target_choice': 'https://juice-shop.herokuapp.com/', 
 'input_file_name': None, 
 'use_active_modules': True, 
 'checkbox_email': False, 'email': '', 
 'checkbox_report': True, 
 'report_type': 'F', 
 'selected_language': 'eng',
 'checkbox_redmine': True, 'redmine_project': 'orchestator-test-proj', 
 'assigned_users': ['17'], 
 'watcher_users': ['17']
 }
"""

def create_report(info):
    language = info['selected_language']
    reportType = info['report_type']
    target = info['single_target_choice']
    findings = get_findings(target, language) 
    file_dir,missing_finding = reportGenerator.crearReporte(language, reportType, findings)
    return file_dir,missing_finding


def get_findings(target, language):
    default_dict = defaultdict(list)
    default_dict_extra = defaultdict(list)
    default_dict_img = defaultdict(list)
    vulnerabilities = mongo.get_vulns_with_language(target, language)
    for vul in vulnerabilities:
        default_dict[vul["vulnerability_name"]].append(vul["affected_resource"])
        default_dict_extra[vul["vulnerability_name"]].append(vul["extra_info"])
        default_dict_img[vul["vulnerability_name"]].append(vul["image_string"])
    result = [{"title": k, "resourceAf": v} for k, v in default_dict.items()]
    result_extra = [{"title": k, "extra_info": v} for k, v in default_dict_extra.items()]
    result_img = [{"title": k, "image_string": v} for k, v in default_dict_img.items()]
    for r, re,ri in zip(result, result_extra, result_img):
        r['extra_info'] = re['extra_info'][0]
        r['image_string'] = ri['image_string'][0]
    findings = result
    return findings

def get_findings_and_create_report(vulnerabilities):
    reportInformation={}
    reportInformation["language"] = vulnerabilities[0]["language"]
    reportInformation["typeReport"] = "S"
    reportInformation["client"] = ""
    reportInformation["findings"] = []
    d =defaultdict(list)
    for vul in vulnerabilities:
        d[vul["vulnerability_name"]].append(vul["subdomain"])
    result = [{"title": k, "resourceAf": v} for k, v in d.items()]
    reportInformation["findings"] = result
    return create_report(reportInformation)