import os
from langchain_groq import ChatGroq
from langchain_community.graphs import Neo4jGraph
from langchain_community.vectorstores import Neo4jVector
from langchain_google_genai import GoogleGenerativeAIEmbeddings
from langchain_core.prompts import ChatPromptTemplate
from collections import deque

class GraphQueryProcessor:
    def __init__(self):
        # Set environment variables from the original code
        groq_api_key = "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"
        NEO4J_URI = "neo4j+s://0ea7e7ee.databases.neo4j.io"
        NEO4J_USERNAME = "neo4j"
        NEO4J_PASSWORD = "hPDx7s6tmiz-DUyTjFD6te1Sik0ZfL37QXi9tmbgZRw"
        GOOGLE_API_KEY = "AIzaSyDU-eGGW4VocdsM50eYmgWm5NYH6AH5iQI"
        # Set environment variables
        os.environ["GROQ_API_KEY"] = groq_api_key
        os.environ["NEO4J_URI"] = NEO4J_URI
        os.environ["NEO4J_USERNAME"] = NEO4J_USERNAME
        os.environ["NEO4J_PASSWORD"] = NEO4J_PASSWORD
        os.environ["GOOGLE_API_KEY"] = GOOGLE_API_KEY
        # Initialize LLM
        self.llm = ChatGroq(
            model="llama3-8b-8192",
            temperature=0,
            max_tokens=2048,
            timeout=None,
            max_retries=2,
            groq_api_key=groq_api_key
        )

        # Initialize graph database
        self.graph = Neo4jGraph()

        # Initialize embeddings
        self.embeddings = GoogleGenerativeAIEmbeddings(model="models/embedding-001")

        # Create vector index
        self.vector_index = Neo4jVector.from_existing_graph(
            self.embeddings,
            search_type="hybrid",
            node_label="Document",
            text_node_properties=["text"],
            embedding_node_property="embedding"
        )

        self.chat_history = deque(maxlen=10)  # Store the last 10 messages

    def process_query(self, query):
        """
        Process the input query and retrieve relevant information
        
        :param query: Input query string
        :return: Processed response
        """
        # Retrieve similar documents
        similar_docs = self.vector_index.similarity_search(query)
        
        # Prepare context
        context = "\n".join([doc.page_content for doc in similar_docs])
        
        # Create a prompt template
        prompt = ChatPromptTemplate.from_template("""
        Answer the question based only on the following context:
        {context}

        Question: {question}
        Provide a clear and concise answer.
        """)

        # Create the chain
        chain = prompt | self.llm

        # Generate response
        response = chain.invoke({
            "context": context,
            "question": query
        })

        # Store the query and response in chat history
        self.chat_history.append({"user": query, "bot": response.content})

        return response.content

    def get_chat_history(self):
        """Retrieve the chat history."""
        return list(self.chat_history)  # Convert deque to list for easier handling

# Example usage
def main():
    # Create processor
    processor = GraphQueryProcessor()
    
    # Process a query
    result = processor.process_query("What is malaria?")
    print(result)

if __name__ == "__main__":
    main()