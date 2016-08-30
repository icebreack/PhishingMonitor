
import simplejson
import urllib.request
import sys
import time

# API_KEY (virusTotal)
API_KEY = ""

def countdown(n):
    print('Aguardando 30 segundos para o proximo request')
    for i in reversed(range(0, 30)):
        time.sleep(1)
        sys.stdout.write('#')
        sys.stdout.flush()

def firstRequestScan(url):
    url_API = "https://www.virustotal.com/vtapi/v2/url/scan"

    # use /n para concatenar requests
    parameters = {"url": url, "apikey": API_KEY }

    # Faz o primeiro request
    data = urllib.parse.urlencode(parameters)
    data = data.encode('utf-8')
    req = urllib.request.Request(url_API, data)
    response = urllib.request.urlopen(req)
    json_retorno_passo1 = response.read()


    dict_retorno_passo1 = simplejson.loads(json_retorno_passo1)

    texto_msg_retorno_consulta = dict_retorno_passo1.get('verbose_msg')
    texto_link_retorno_consulta = dict_retorno_passo1.get('permalink')

    print(texto_link_retorno_consulta)

def secondRequestScan(url):
    #this is the VT url scan api link
    url_API = 'https://www.virustotal.com/vtapi/v2/url/report'

    #API parameters
    parameters = {'resource': url, 'apikey': API_KEY}

    #
    data = urllib.parse.urlencode(parameters)
    data = data.encode('utf-8')
    req = urllib.request.Request(url_API, data)
    response = urllib.request.urlopen(req)
    json_retorno_passo2 = response.read()

	#
    response_dict = simplejson.loads(json_retorno_passo2)

    #
    permalink = response_dict.get('permalink', {})
    scanDate = response_dict.get('scan_date', {})
    PositivosHit = response_dict.get('positives', {})
    total = response_dict.get('total', {})
	
	#
    PositivosHit = str(PositivosHit)
    total = str(total)
    ratio = PositivosHit + '/' + total

    #
    print("")
    resultsString = (url + ' verificado em ' + scanDate + ' contendo ' + ratio + ' problemas')
    print(resultsString)
    resultsOutput = url + ',' + ratio + ',' + permalink + '\n'
    print("" + permalink)

    if int(PositivosHit) >= 1:
        global verificar
        verificar += (url + "|")
        print(verificar)
        #print(resultsOutput)
    
    results = open(url.replace("/",".") + '_results.txt', 'w') 
    results.write('')
    results.write(url)
    results.write(ratio)
    results.write(permalink)

def main(argv):

    with open('API.txt') as f:
        API_KEY = f.read()
    
    if API_KEY=='':
        print('No API_KEY was found in API.txt file')
        sys.exit(2)


    fileIP = sys.argv[1]

    global verificar     
    verificar = "|"

    # Abre o arquivo
    with open(fileIP, 'r') as infile:
        data = infile.read()  

    # Pega as linhas
    my_list = data.splitlines()

    # scaneia
    for line in my_list:        
        print('----------------------------------------')
        print(line)
        firstRequestScan(line)
        countdown(10)
        secondRequestScan(line)
        print('----------------------------------------')
    
    print(verificar)

if __name__ == "__main__":
       main(sys.argv[1:])