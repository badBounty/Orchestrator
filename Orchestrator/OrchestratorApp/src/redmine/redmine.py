from redminelib import Redmine
import redminelib

from ...__init__ import redmine


# Projects under orchestrator
def get_project_names():
    projects = redmine.project.all()
    project_names = list()
    for project in projects:
        project_names.append((project.identifier, project.name))
    return project_names


def get_users():
    project = redmine.project.get('vulnerability-management')
    available_users = list()
    for user in project['memberships']:
        available_users.append((user['user'].id, user['user'].name))

    return available_users


def create_new_issue(vulnerability):
    project_name = vulnerability.redmine['project_id']
    if project_name == 'no_project':
        return
    issue = redmine.issue.new()
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
