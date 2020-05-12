import os
from . import reportGenerator
from collections import defaultdict
from ..mongo import mongo


ROOT_DIR = os.path.dirname(os.path.abspath(__file__))


def create_report(client, language, report_type, selected_target,findings=None):
    if findings:
        findings = get_findings(selected_target, language)
    language = language
    reportType = report_type
    client = client
    file_dir = reportGenerator.crearReporte(language, reportType, client, findings)
    return file_dir


def get_findings(target, language):
    default_dict = defaultdict(list)
    vulnerabilities = mongo.get_vulns_with_language(target, language)
    for vul in vulnerabilities:
        default_dict[vul["vulnerability_name"]].append(vul["affected_resource"])
    result = [{"title": k, "resourceAf": v} for k, v in default_dict.items()]
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