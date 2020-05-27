from pymongo import MongoClient
import os
import urllib3
from slack import WebClient
from redminelib import Redmine

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Connections
MONGO_CLIENT = os.getenv('MONGO_CLIENT')
SLACK_CLIENT = os.getenv('SLACK_CLIENT')
WAPPALIZE_KEY = os.getenv('WAPPALIZE_KEY')

client = MongoClient(str(MONGO_CLIENT))

slack_web_client = WebClient(str(SLACK_CLIENT))

REDMINE_URL = os.getenv('REDMINE_URL')
REDMINE_USER = os.getenv('REDMINE_USER')
REDMINE_PASSWORD = os.getenv('REDMINE_PASSWORD')

redmine = Redmine(str(REDMINE_URL), username=str(REDMINE_USER), password=str(REDMINE_PASSWORD),
                  requests={'verify': False})

