from pymongo import MongoClient
import os
from slack import WebClient

# Connections
MONGO_CLIENT = os.getenv('MONGO_CLIENT')
SLACK_CLIENT = os.getenv('SLACK_CLIENT')
WAPPALIZE_KEY = os.getenv('WAPPALIZE_KEY')

client = MongoClient(str(MONGO_CLIENT))

slack_web_client = WebClient(str(SLACK_CLIENT))
