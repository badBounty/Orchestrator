
import os,json
import urllib3, requests
import pymongo
from Orchestrator.settings import MONGO_INFO, settings

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
MONGO_CLIENT = pymongo.MongoClient(MONGO_INFO['CLIENT_URL'], connect=False)