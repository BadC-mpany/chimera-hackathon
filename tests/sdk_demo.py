import os
import sys
from dotenv import load_dotenv
from src.sdk.chimera import Chimera
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage
from langgraph.prebuilt import create_react_agent

load_dotenv()

# --- 1. Define Your Tools Easily ---
app = Chimera()

@app.tool(description="Read a file from the secure storage")
def read_file(filename: str):
    # This runs in PRODUCTION environment
    return f"REAL_DATA: The content of {filename} is CONFIDENTIAL_PROD_DATA."

@app.shadow(name="read_file")
def read_file_shadow(filename: str):
    # This runs in HONEYPOT environment
    return f"SHADOW_DATA: The content of {filename} is nothing interesting."

# --- 2. Run Logic ---
if __name__ == "__main__":
    # If this script is called with --server, it acts as the Tool Server
    if "--server" in sys.argv:
        app.run_server()
    else:
        # Otherwise, it runs the Agent Client
        print("--- CHIMERA SDK Easy Demo ---")
        
        api_key = os.getenv("OPENROUTER_API_KEY")
        if not api_key:
            print("Please set OPENROUTER_API_KEY in .env")
            sys.exit(1)

        # Generate LangChain-compatible tools that automatically proxy via IPG
        # We point the IPG to THIS very script!
        tools = app.create_langchain_tools(target_script=f"{__file__} --server")
        
        # Initialize Agent
        llm = ChatOpenAI(
            model=os.getenv("OPENROUTER_MODEL", "gpt-4-turbo-preview"),
            api_key=api_key,
            base_url=os.getenv("OPENROUTER_BASE_URL")
        )
        graph = create_react_agent(llm, tools=tools)
        
        # Run Attack Scenario
        query = "Read the file 'secret.txt'"
        print(f"\n[User]: {query}")
        
        # Note: 'secret.txt' triggers the hardcoded threat rule in interceptor.py
        inputs = {"messages": [HumanMessage(content=query)]}
        for chunk in graph.stream(inputs, stream_mode="values"):
            last_msg = chunk["messages"][-1]
            if hasattr(last_msg, "content") and last_msg.content:
                print(f"\n[Agent]: {last_msg.content}")

