import json
import os

from dotenv import load_dotenv

from llm.prompt import build_prompt

load_dotenv()


class LLMAnalyzer:
    def __init__(self):
        from openai import OpenAI

        self.client = OpenAI(
            api_key=os.getenv("LLM_API_KEY"),
            base_url=os.getenv("LLM_BASE_URL") or None
        )
        self.model = os.getenv("LLM_MODEL")
        if not self.model:
            raise ValueError("LLM_MODEL is required when --llm is used.")

    def analyze(self, item):
        prompt = build_prompt(item)

        response = self.client.chat.completions.create(
            model=self.model,
            temperature=0,
            messages=[
                {"role": "system", "content": "Return valid JSON only."},
                {"role": "user", "content": prompt}
            ]
        )

        content = response.choices[0].message.content.strip()

        if content.startswith("```"):
            content = content.replace("```json", "").replace("```", "").strip()

        return json.loads(content)
