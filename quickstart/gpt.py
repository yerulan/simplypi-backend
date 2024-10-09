import openai
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

def generate_gpt_response(user_message):
    openai.api_key = settings.OPENAI_API_KEY

    try:
        response = openai.Completion.create(
            engine="gpt-4o-mini",  # or "gpt-4" if available
            prompt=user_message,
            max_tokens=150,
            temperature=0.7
        )
        return response.choices[0].text.strip()
    except Exception as e:
        logger.error(f"Error communicating with GPT API: {e}")
        return "I'm having trouble understanding your message. Could you please try again?"
