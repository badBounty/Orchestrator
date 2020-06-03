from pymongo import MongoClient
import os,json
import urllib3, requests
from slack import WebClient
from slack.errors import SlackApiError
import redminelib

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import os,json
# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
settings = json.loads(open(BASE_DIR+'/settings.json').read())
# Enviroment variables
os.environ['C_FORCE_ROOT'] = settings['C_FORCE_ROOT']
# Connections

WAPPALIZE_KEY = settings['WAPPALIZE_KEY']

# Mongo connection
try:
    client = MongoClient(settings['MONGO_CLIENT'])
except Exception as e:
    print(str(e))

# Slack connection
try:
    slack_web_client = WebClient(settings['SLACK_KEY'])
    slack_channel_name = settings['SLACK_CHANNEL']
    response = slack_web_client.chat_postMessage(channel=slack_channel_name, text=str('test'))
except SlackApiError as e:
    slack_web_client = None


REDMINE_URL = settings['REDMINE_URL']
REDMINE_USER = settings['REDMINE_USER']
REDMINE_PASSWORD = settings['REDMINE_PASSWORD']

# Redmine connection
try:
    redmine_client = redminelib.Redmine(str(REDMINE_URL), username=str(REDMINE_USER), password=str(REDMINE_PASSWORD),
                  requests={'verify': False})
    projects = redmine_client.project.all()
except requests.exceptions.MissingSchema:
    redmine_client = None
except redminelib.exceptions.AuthError:
    redmine_client = None
except Exception:
    redmine_client = None