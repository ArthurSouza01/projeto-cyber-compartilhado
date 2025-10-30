from datetime import datetime
import pytz
import whois
from urllib.parse import urlparse
from analise_VirusTotal import verificar_virustotal, verificar_virustotal_dominio

utc = pytz.utc

def analisar_url(url_alvo):
    pontuacao_risco = 0
    data_atual_utc = datetime.now(pytz.utc)

    try:
        # Analisar domínio
        netloc = urlparse(url_alvo).netloc

        # TESTE 1: Checar Idade do Domínio
        try:
            w = whois.whois(netloc)
            if w.creation_date:
                data_criacao = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                if isinstance(data_criacao, datetime):
                    if data_criacao.tzinfo is None or data_criacao.tzinfo.utcoffset(data_criacao) is None:
                        data_criacao_utc = pytz.utc.localize(data_criacao)
                    else:
                        data_criacao_utc = data_criacao.astimezone(pytz.utc)

                    diferenca_dias = (data_atual_utc - data_criacao_utc).days

                    # Se o domínio tem menos de 30 dias, aumetar risco
                    if diferenca_dias < 30:
                        pontuacao_risco += 10
                        tempo_criacao = str(f'-> Este domínio tem {diferenca_dias} dias, isso o torna suspeito! Adicionado 10 pontos de risco!')
                        print(tempo_criacao)

        except Exception as e:
            print(f"Aviso - Whois falhou para {netloc}: {e}")
            pass

        # TESTE 2: Muito subdomínio na url, aumentar risco
        if netloc.count('.') > 3:
            pontuacao_risco += 5
            print('-> Esta URL apresenta um número elevado de subdomínio, isso o torna supeito! Adicionado 5 pontos de risco!')

        # TESTE 3: Presença de Caracteres Estranhos - Homógrafos
        # Aqui posso melhorar buscando uma lista com diversos homógrafos (avaliar)
        homografos_suspeitos = [
            'α', 'ο', 'ρ', 'ϲ',  # Gregos
            'ø', 'ə', 'é', 'à', 'ä', 'ö', 'ü',  # Diacríticos e outros
            '@', '1', '0'  # Símbolos e Números
        ]
        if any(c in netloc for c in homografos_suspeitos):
            pontuacao_risco += 15
            print('-> Esta URL apresenta homógrafo, isso o torna suspeito! Adicionado 15 pontos de risco!')

        # TESTE 4: Reputação do VirusTotal
        motores_maliciosos = verificar_virustotal(url_alvo)
        # Ponderação: Adiciona 10 pontos se 1 ou 2 engines detectarem, 30 se 3 ou mais.
        if motores_maliciosos > 0 and motores_maliciosos <= 2:
            pontuacao_risco += 10
            print('-> De acordo com análise de risco do VirusTotal, foi adicionado 10 pontos de risco a este domínio')
        elif motores_maliciosos >= 3:
            pontuacao_risco += 30
            print('-> De acordo com análise de risco do VirusTotal, foi adicionado 30 pontos de risco a este domínio')




        # TESTE 5: Analisar domínio
        netloc = urlparse(url_alvo).netloc
        try:
            # Usa o 'netloc' que já foi extraído
            motores_maliciosos_domain = verificar_virustotal_dominio(netloc)

            if motores_maliciosos_domain > 0:
                # Adiciona uma pontuação significativa se o domínio for conhecido como malicioso
                pontos = motores_maliciosos_domain * 5
                print(f'-> A verificação de domínio do VirusTotal definiu {pontos} pontos!', end=' ')
                if pontos > 5:
                    print('Isso faz o domínio ser de alto risco')
                pontuacao_risco += pontos  # Ponderação de 5 pontos por motor
            else:
                print(f'-> O VirusTotal não encontrou indícios de risco no domínio: {url_alvo}')

        except Exception:
            pass
    except Exception as e:
        print(f"Erro inesperado na análise da URL: {e}")
        return 100

    return pontuacao_risco


