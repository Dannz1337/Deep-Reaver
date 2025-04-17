import os
import requests
from dotenv import load_dotenv

load_dotenv()

class AIAssistant:
    def __init__(self):
        self.api_key = os.getenv("OPENROUTER_API_KEY")
        self.api_url = "https://openrouter.ai/api/v1/chat/completions"
        self.model = "openai/gpt-3.5-turbo"

    def generate_summary(self, vulnerabilities):
        if not self.api_key:
            print("[AI Assistant Error] OPENROUTER_API_KEY tidak ditemukan di file .env")
            return None  # Kembalikan None jika ada error

        if not vulnerabilities:
            print("[AI Assistant] Tidak ada kerentanan ditemukan.")
            return None  # Kembalikan None jika tidak ada kerentanan

        lines = []
        for v in vulnerabilities:
            title = v.get('name') or v.get('title') or v.get('type') or 'Tidak diketahui'
            desc = v.get('description') or v.get('detail') or 'Tidak ada deskripsi'
            lines.append(f"{title}: {desc}")

        vuln_text = "\n".join(lines)
        prompt = f"Berikan analisis keamanan dan rekomendasi dari hasil scan berikut:\n{vuln_text}"

        try:
            response = requests.post(self.api_url, headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://your-site.com",
                "X-Title": "Security Scanner"
            }, json={
                "model": self.model,
                "messages": [
                    {"role": "user", "content": prompt}
                ]
            }, timeout=30)

            result = response.json()
            if "choices" in result:
                message = result["choices"][0]["message"]["content"]
                print("\n[Laporan AI Assistant]\n" + message)
                return message  # Kembalikan hasil analisis AI
            elif "error" in result:
                print(f"[AI Assistant Error] {result['error']['message']}")
            else:
                print(f"[AI Assistant Error] Response tidak dikenali: {result}")
            
            return None  # Kembalikan None jika ada error

        except Exception as e:
            print(f"[AI Assistant Error] {e}")
            return None  # Kembalikan None jika ada exception