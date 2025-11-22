import os

from langchain_openai import ChatOpenAI


def get_llm_client():
    """
    Initializes and returns the LangChain LLM client.

    This function is configured via environment variables to support different
    models and providers, primarily targeting OpenAI-compatible APIs like OpenRouter.
    """
    api_key = os.getenv("OPENROUTER_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not api_key:
        # For security, we don't raise a fatal error here.
        # The ProbabilisticJudge will degrade gracefully if no LLM is available.
        return None

    model = os.getenv("OPENROUTER_MODEL", "gpt-4-turbo-preview")
    base_url = os.getenv("OPENROUTER_BASE_URL")

    try:
        llm = ChatOpenAI(
            model=model,
            api_key=api_key,
            base_url=base_url,
            temperature=0,
            model_kwargs={"response_format": {"type": "json_object"}},
        )
        return llm
    except Exception:
        # Catch potential initialization errors (e.g., invalid API key format)
        return None
