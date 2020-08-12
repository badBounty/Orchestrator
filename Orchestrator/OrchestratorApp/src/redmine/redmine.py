from redminelib import Redmine
from Orchestrator.settings import redmine_client
import redminelib
import uuid


# Projects under orchestrator
def get_project_names():
    if redmine_client is None:
        return []
        
    projects = redmine_client.project.all()
    project_names = list()
    for project in projects:
        project_names.append((project.identifier, project.name))
    return project_names


def get_users():
    if redmine_client is None:
        return []
    project = redmine_client.project.get('vulnerability-management')
    available_users = list()
    for user in project['memberships']:
        available_users.append((user['user'].id, user['user'].name))

    return available_users


def create_new_issue(vulnerability):
    if redmine_client is None:
        return
    project_name = vulnerability.redmine['project_id']
    if project_name == 'no_project':
        return
    issue = redmine_client.issue.new()
    issue.project_id = project_name                              # project name
    issue.subject = vulnerability.vulnerability_name             # Nombre de la obs
    issue.tracker_id = vulnerability.redmine['tracker_id']       # [0,1,2: Finding, 3:Consulta, 4: Notificacion de estado]
    issue.description = vulnerability.custom_description         # Descripcion
    issue.status_id = vulnerability.redmine['status_id']         # [0: Borrador, 1: Nuevo QA Pendiente]
    issue.priority_id = vulnerability.redmine['priority_id']     # [1: Informational, 2: Low, 3: Medium, 4: High, 5: Critical]
    issue.assigned_to_id = vulnerability.redmine['assigned_to']  # Id de la asignacion, Orchestrator es 17
    issue.watcher_user_ids = vulnerability.redmine['watchers']   # Ids de los watchers, Orchestrator es 17
    if vulnerability.redmine['attachment_path'] is not None:
        issue.uploads = [{'path': vulnerability.redmine['attachment_path'],
                          'filename': vulnerability.redmine['attachment_name']}]
    try:
        issue.save()
    except Exception as e:
        print("ERROR SAVING THE ISSUE - SHOWING FULL ERROR:\n")
        print(e)
        print("CONTINUING WITH THE SCAN")
        pass

def create_issue_scan_finished(scan_information):
    if redmine_client is None:
        return
    issue = redmine_client.issue.new()
    issue.project_id = scan_information['redmine_project']
    issue.subject = 'One Shot Scan Finalizado'
    issue.tracker_id = 4
    issue.description = 'One shot Scan ha finalizado, todas las vulns detectadas fueron subidas como issues al redmine'
    issue.status_id = 0 
    issue.priority_id = 1
    issue.assigned_to_id = scan_information['assigned_users']
    issue.watcher_user_ids = scan_information['watchers']
    try:
        issue.save()
    except Exception as e:
        print("ERROR SAVING THE ISSUE - SHOWING FULL ERROR:\n")
        print(e)
        print("CONTINUING WITH THE SCAN")
        pass
            

def create_report_issue(info,file_dir,missing_finding):
    message = 'RECORDAR, ABRIRLO Y GUARDARLO DE NUEVO PORQUE TIENE EL XML ROTO POR LA GENERACION\n'
    message+= 'The following findings were not found: '+ missing_finding
    random_filename = uuid.uuid4().hex
    f = redmine_client.file.new()
    f.project_id = info['redmine_project']
    f.path = file_dir
    f.filename = 'Report-'+random_filename+'.docm'
    f.description = message
    f.content_type = 'application/vnd.ms-word.document.macroEnabled.12'
    f.save()