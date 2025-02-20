from pymongo import MongoClient
import os
from dotenv import load_dotenv

load_dotenv()

URL=os.getenv("MONGO_URL")
KEY=os.getenv("JWT_KEY")


client = MongoClient(URL)
db = client['alltimedesign']
users_collection = db['users']
templates_collection = db['templates']
