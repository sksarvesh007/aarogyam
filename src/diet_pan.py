from groq import Groq
import os 
import dotenv 
dotenv.load_dotenv()
groq_api_key = os.getenv("GROQ_API_KEY")
def diet_plan_chatbot(user_message, message_history, system_prompt=None):
    """
    Generate a response for a diet and nutrition chatbot.
    
    Parameters:
    - user_message (str): User's input message
    - message_history (list, optional): Previous conversation messages
    - system_prompt (str, optional): Custom system prompt for the chatbot
    
    Returns:
    - tuple: (bot_response, updated_message_history)
    """
    
    client = Groq(api_key= groq_api_key)
    
    # Default system prompt
    default_system_prompt = """
    You are a helpful and knowledgeable nutritional assistant designed to provide 
    comprehensive dietary advice, meal planning, and nutrition guidance. Your goal is to:
    - Offer personalized nutritional recommendations
    - Provide clear and scientifically-backed dietary information
    - Help users make informed choices about their nutrition
    - Adapt to individual dietary needs and preferences
    - Maintain a supportive and informative tone
    
    You can discuss various topics including:
    - General nutrition advice
    - Meal planning
    - Dietary guidelines
    - Nutritional balance
    - Healthy eating strategies
    - Food and nutrient information
    """
    
    # Use provided system prompt or default
    current_system_prompt = system_prompt or default_system_prompt
    
    # Initialize or use provided message history
    if message_history is None:
        message_history = [
            {
                "role": "system",
                "content": current_system_prompt
            }
        ]
    
    # Add user message to history
    message_history.append({
        "role": "user",
        "content": user_message
    })
    
    try:
        # Create completion
        completion = client.chat.completions.create(
            model="llama-3.1-70b-versatile",
            messages=message_history,
            temperature=0.7,
            max_tokens=1024,
            top_p=0.9,
            stream=False
        )
        
        # Extract response
        bot_response = completion.choices[0].message.content
        
        # Add bot response to history
        message_history.append({
            "role": "assistant",
            "content": bot_response
        })
        
        return bot_response, message_history
    
    except Exception as e:
        error_response = f"An error occurred: {str(e)}"
        message_history.append({
            "role": "assistant",
            "content": error_response
        })
        return error_response, message_history

# Example usage
if __name__ == "__main__":
    # Initial conversation
    message_history = None
    
    # Example interactions
    messages = [
        "my name is sarvesh",
        "what is my name "
    ]
    
    for message in messages:
        # Generate response
        response, message_history = diet_plan_chatbot(message, message_history)
        
        print(f"User: {message}")
        print(f"Chatbot: {response}")
        print("\n")