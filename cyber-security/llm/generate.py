import httpx
from dotenv import load_dotenv
import os

load_dotenv()
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")

async def generate_chatbot_response(system_prompt: str,
            user_message: str,
            temperature: float,
            max_tokens: int,
            context: str = "") -> str:

    try:
        headers = {
            'Authorization': f'Bearer {OPENROUTER_API_KEY}',
            'Content-Type': 'application/json',
        }
        
        # Build the user message with RAG context if provided
        full_user_message = user_message
        if context:
            full_user_message = f"{context}\n\n### INTERVIEW QUESTION:\n{user_message}"
        
        payload = {
            "model": "mistralai/mistral-small-3.1-24b-instruct",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": full_user_message}
            ],
            "max_tokens": max_tokens,
            "temperature": temperature
        }
        
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                'https://openrouter.ai/api/v1/chat/completions',
                headers=headers,
                json=payload
            )
            
            if response.status_code == 200:
                result = response.json()
                content = result['choices'][0]['message']['content']
                # Validate that we got actual content, not an error message
                if content and not content.startswith("Error"):
                    return content
                else:
                    print(f"LLM returned error in content: {content}")
                    return "NO_URL_FOUND" if "NO_URL_FOUND" in system_prompt else ""
            else:
                print(f"LLM API error: {response.status_code} - {response.text}")
                return ""

    except httpx.TimeoutException:
        print(f"LLM timeout error - request took too long")
        return ""
    except httpx.RemoteProtocolError as e:
        print(f"LLM connection error: {str(e)}")
        return ""
    except Exception as e:
        print(f"LLM general conversation error: {type(e).__name__}: {e}")
        return ""

