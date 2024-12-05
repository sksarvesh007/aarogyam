import os
from groq import Groq
import base64
import os 
import dotenv 
import sqlite3
dotenv.load_dotenv()

groq_api_key = os.getenv("GROQ_API_KEY")

def extract_image_info(image_path):
    """
    Extract structured information from an image using Groq's vision model.
    
    Args:
        image_path (str): Path to the image file to be processed
    
    Returns:
        dict: Extracted information in JSON format
    """
    # Ensure the Groq API key is set
    if not os.getenv('GROQ_API_KEY'):
        raise ValueError("GROQ_API_KEY environment variable must be set")
    
    # Initialize Groq client
    client = Groq(api_key = groq_api_key)
    
    # Read the image file and encode it to base64
    with open(image_path, "rb") as image_file:
        base64_image = base64.b64encode(image_file.read()).decode('utf-8')
    
    try:
        # Create the completion
        completion = client.chat.completions.create(
            model="llama-3.2-90b-vision-preview",
            messages=[
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": "extract out all the user information which is relevant to store in a database in a json format"
                        },
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/jpeg;base64,{base64_image}"
                            }
                        }
                    ]
                }
            ],
            temperature=1,
            max_tokens=1024,
            top_p=1,
            stream=False,
            response_format={"type": "json_object"},
            stop=None,
        )
        
        
        extracted_info = completion.choices[0].message.content
        print(extracted_info)
        # Append extracted information to the database
        append_to_database(extracted_info)
        
        return extracted_info
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def append_to_database(extracted_info):
    # Connect to the SQLite database
    conn = sqlite3.connect('user.db')
    cursor = conn.cursor()
    cursor.execute("ALTER TABLE users ADD COLUMN extracted_info TEXT")

    # Insert the extracted information into the new column
    cursor.execute("UPDATE users SET extracted_info = ? WHERE id = (SELECT MAX(id) FROM users)", (extracted_info,))
    
    # Commit the changes and close the connection
    conn.commit()
    conn.close()

