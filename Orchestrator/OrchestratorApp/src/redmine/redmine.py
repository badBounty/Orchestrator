from redminelib import Redmine
import redminelib
import datetime
import os
from ...__init__ import redmine


# Projects under orchestrator
def get_project_names():
    projects = redmine.project.all()
    project_names = list()
    for project in projects:
        project_names.append((project.identifier, project.name))
    return project_names


def create_new_issue(vuln_name, description, project_name, attachment_path=None, attachment_name=None):

    issue = redmine.issue.new()
    issue.project_id = project_name             # orchestator-test-proj ?
    issue.subject = vuln_name                   # Nombre de la obs
    issue.tracker_id = 0                        # [0,1,2: Finding, 3:Consulta, 4: Notificacion de estado]
    issue.description = description             # Descripcion
    issue.status_id = 1                         # [0: Borrador, 1: Nuevo QA Pendiente]
    issue.priority_id = 3                       # [1: Informational, 2: Low, 3: Medium, 4: High, 5: Critical]
    issue.assigned_to_id = 17                   # Id de la asignacion, Orchestrator es 17
    issue.watcher_user_ids = [17]               # Ids de los watchers, Orchestrator es 17
    if attachment_path is not None:
        issue.uploads = [{'path': attachment_path, 'filename': attachment_name}]
    issue.save()