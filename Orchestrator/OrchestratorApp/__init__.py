from pymongo import MongoClient
import os,json
import urllib3
from slack import WebClient
from redminelib import Redmine

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import os,json
# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
settings = json.loads(open(BASE_DIR+'/settings.json').read())
# Enviroment variables
os.environ['C_FORCE_ROOT'] = settings['C_FORCE_ROOT']
# Connections

WAPPALIZE_KEY = settings['WAPPALIZE_KEY']
client = MongoClient(settings['MONGO_CLIENT'])
slack_web_client = WebClient(settings['SLACK_KEY'])

REDMINE_URL = settings['REDMINE_URL']
REDMINE_USER = settings['REDMINE_USER']
REDMINE_PASSWORD = settings['REDMINE_PASSWORD']

redmine = Redmine(str(REDMINE_URL), username=str(REDMINE_USER), password=str(REDMINE_PASSWORD),
                  requests={'verify': False})