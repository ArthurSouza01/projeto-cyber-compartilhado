from pontuacao_risco import analisar_url

print('Exemplo de URL completa: https://www.google.com/')
url = str(input('Digite a URL completa que deseja verificar: '))
url_final = url.strip() # Remove espaços em branco extras

if not url_final.startswith('http://') and not url_final.startswith('https://'):
    url_final = 'https://' + url_final

if url_final.startswith('http://') or url_final.startswith('https://'):
    from urllib.parse import urlparse
    netloc = urlparse(url_final).netloc
    if not netloc.startswith('www.'):
        url_final = url_final.replace(netloc, 'www.' + netloc, 1)

print('Iniciando motores de análise...')
pontuacao_final = analisar_url(url_final)

print(f"Risco total do domínio {url_final}: {pontuacao_final}")