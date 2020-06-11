import os
from . import reportGenerator
from collections import defaultdict
from ..mongo import mongo
from ..redmine import redmine
import zipfile
import uuid

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))


def create_report(info):
    language = info['language']
    reportType = info['report_type']
    target = info['target']
    findings = get_findings(target, language)
    file_dir,missing_finding = reportGenerator.crearReporte(language, reportType, findings)
    print("------------- FILE DIR -------------")
    print(file_dir)
    print("--------------------------")
    """    
    random_filename = uuid.uuid4().hex
    zip_path = ROOT_DIR+'/out/'+random_filename+'.zip'
    report_zip = zipfile.ZipFile(zip_path, 'w')
    report_zip.write(file_dir, compress_type=zipfile.ZIP_DEFLATED)
    report_zip.close()
    """
    print("------------- Saving report in redmine -------------")
    redmine.create_report_issue(info,file_dir,missing_finding)
    print("------------- DONE !!! -------------")
    return

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