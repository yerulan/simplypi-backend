from openai import OpenAI
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

client = OpenAI(api_key=settings.OPENAI_API_KEY)

def generate_gpt_response(messages):
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",  # or "gpt-4" if available
            messages=[
            {
                "role": "user",
                "content": messages[-1]
            }
            ],
            max_tokens=150,
            temperature=0.7
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        logger.error(f"Error communicating with GPT API: {e}")
        return "I'm having trouble understanding your message. Could you please try again?"
