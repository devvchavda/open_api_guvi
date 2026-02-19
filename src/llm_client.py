"""
LLM factory. To swap model/provider, edit get_llm() below. That's it.
"""
import os 
from langchain_ollama import ChatOllama
from langchain_groq import ChatGroq 
def get_llm()->ChatOllama: 
    ollama_api_key = os.getenv("OLLAMA_API_KEY")
    groq_api_key = os.getenv("GROQ_API_KEY")
    # client_kwargs = {
    #     "headers": {
    #         "Authorization": f"Bearer {ollama_api_key}"
    #     }
    # }

    # llm = ChatOllama(
    #     model="gpt-oss:120b-cloud",
    #     base_url="https://ollama.com",
    #     client_kwargs=client_kwargs
    # )
    llm = ChatGroq(
        model = "openai/gpt-oss-120b" , 
        temperature=1 ,
        api_key=groq_api_key
    )
    return llm 
    # ── Swap to any of these instead ─────────────────────────────────────────

    # from langchain_openai import ChatOpenAI
    # return ChatOpenAI(model="gpt-4o-mini", temperature=0.7, max_tokens=512)

    # from langchain_groq import ChatGroq
    # return ChatGroq(model="llama-3.3-70b-versatile", temperature=0.7, max_tokens=512)

    # from langchain_google_genai import ChatGoogleGenerativeAI
    # return ChatGoogleGenerativeAI(model="gemini-1.5-flash", temperature=0.7)

    # from langchain_ollama import ChatOllama
    # return ChatOllama(model="llama3.2", temperature=0.7)


