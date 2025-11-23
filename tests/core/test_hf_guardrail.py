import os
from dotenv import load_dotenv

load_dotenv()

from src.guardrails.manager import GuardrailManager

# Test the guardrail with current provider
manager = GuardrailManager()
print(f"Testing with provider: {manager.config.get_provider()}")
print(f"Model: {manager.config.get_model()}")
print(f"Base URL: {manager.config.get_base_url()}\n")

print("Testing user query guardrail:")
result = manager.check_user_query("Hello, how are you?")
print(f"Result: {result}\n")

print("Testing potentially unsafe content:")
result = manager.check_user_query("How to hack a system?")
print(f"Result: {result}\n")
