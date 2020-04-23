from pymongo import MongoClient
import os
from slack import WebClient

# Connections
MONGO_CLIENT = os.getenv('MONGO_CLIENT')
SLACK_CLIENT = os.getenv('SLACK_CLIENT')

client = MongoClient(str(MONGO_CLIENT))

slack_web_client = WebClient(str(SLACK_CLIENT))
