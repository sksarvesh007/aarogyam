import requests

URL = "https://discover.search.hereapi.com/v1/discover"
import os 
import dotenv 
dotenv.load_dotenv()

here_api_key = os.getenv("here_api")
def get_hospitals(api_key , latitude , longitude , query , limit):
    PARAMS = {
    'apikey': api_key,
    'q': query,
    'limit': limit,
    'at': f'{latitude},{longitude}'
    }
    response = requests.get(url=URL, params=PARAMS)
    data = response.json()
    return data
