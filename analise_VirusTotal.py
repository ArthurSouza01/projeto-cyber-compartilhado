import requests
import json
import time
from datetime import datetime
from urllib.parse import urlparse
import os
from dotenv import load_dotenv
load_dotenv()

VT_URL_ANALYSIS = "https://www.virustotal.com/api/v3/urls"
VT_URL_REPORT = "https://www.virustotal.com/api/v3/analyses"
VT_DOMAIN_REPORT = "https://www.virustotal.com/api/v3/domains/"
VT_API_KEY = os.getenv("VT_API_KEY")


def verificar_virustotal(url_alvo):
    url_id = requests.utils.quote(url_alvo)

    headers = {
        "x-apikey": VT_API_KEY,
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    try:
        # 1. Envia a URL para análise (POST request)
        response = requests.post(
            VT_URL_ANALYSIS,
            headers=headers,
            data=f"url={url_alvo}"
        )
        response.raise_for_status()  # Lança exceção para códigos de erro

        analysis_id = response.json()['data']['id']

        # 2. Pede o relatório da análise (GET request)
        report_url = f"{VT_URL_REPORT}/{analysis_id}"

        print(f"Análise iniciada no VirusTotal. Aguardando resultado (máx 20s)...")
        print('Carregando', end='')
        n = 15
        while n > 0:
            print(f'.', end='')
            if n == 1:
                print('Pronto')
            n -= 1
            time.sleep(1)


        # Faz a chamada para obter o relatório.
        report_response = requests.get(report_url, headers=headers)
        report_response.raise_for_status()

        data = report_response.json()['data']['attributes']

        # O VirusTotal retorna
        malicious_count = data['stats']['malicious']

        # Retorna o número de motores de segurança que detectaram a URL como maliciosa.
        return malicious_count

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 429:
            print("Aviso: Limite de requisições do VirusTotal atingido (429).")
        # Se ocorrer qualquer erro, ou se a chave for inválida, evita travar o programa.
        return 0
    except Exception as e:
        print(f"Erro ao processar VirusTotal: {e}")
        return 0  # Retorna 0 para que a falta de dados não seja considerada risco


def verificar_virustotal_dominio(domain_alvo):
    """
    Consulta o relatório de reputação de um domínio no VirusTotal.
    """
    headers = {
        "x-apikey": VT_API_KEY,
        "Accept": "application/json"
    }

    url_reporte = f"{VT_DOMAIN_REPORT}{domain_alvo}"

    try:
        response = requests.get(url_reporte, headers=headers)
        response.raise_for_status()

        data = response.json()['data']['attributes']

        # O VT retorna um dicionário 'last_analysis_stats' com a contagem
        stats = data.get('last_analysis_stats', {})

        # Retorna a contagem de motores que classificaram o DOMÍNIO como malicioso
        malicious_count = stats.get('malicious', 0)

        return malicious_count

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            # 404 significa que o domínio nunca foi analisado antes, ou não existe.
            return 0
        if e.response.status_code == 429:
            print("Aviso: Limite de requisições do VirusTotal atingido (429).")
        return 0
    except Exception:
        print('Falha geral (ex: rede, chave inválida)')
        return 0