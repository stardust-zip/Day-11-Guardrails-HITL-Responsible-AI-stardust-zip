"""
Lab 11 — Helper Utilities using OpenAI
"""

import os
from openai import OpenAI


def get_openai_client():
    """Get or create OpenAI client."""
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OPENAI_API_KEY not set in environment")
    return OpenAI(api_key=api_key)


async def chat_with_openai(
    system_prompt: str, user_message: str, model: str = "gpt-4o-mini"
) -> str:
    """Send a message to OpenAI and get the response."""
    client = get_openai_client()
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ],
    )
    return response.choices[0].message.content
