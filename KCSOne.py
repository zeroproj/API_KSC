import requests
import base64
import json
import urllib3
import sys
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

print("MICROHARD - API KASPERSKY SECURITY CENTER")
#Credencias e Servidores
ks = input("Digite o Nome/IP do servidor de Administração: ")
port = input("Digite a Porta de Conexão: ")
usuario_ksc = input("Digite o usuario do Servidor de Administração: ")
senha_ksc = input("Digite a senha do Servidor de Administração: ")
ksc_server = f"https://{ks}:{port}"

url = ksc_server + "/api/v1.0/login" 
usuario_ksc = base64.b64encode(usuario_ksc.encode('utf-8')).decode("utf-8")
senha_ksc = base64.b64encode(senha_ksc.encode('utf-8')).decode("utf-8")
session = requests.Session()
data = {}
##String de Autenticação 
auth_headers = {
    'Authorization': 'KSCBasic user="' + usuario_ksc + '", pass="' + senha_ksc + '", internal="1"',
    'Content-Type': 'application/json',
}
#Autenticando e Coletando Resultados
response = session.post(url=url, headers=auth_headers, data=data, verify=False)
#Validação
if(response.status_code == 200):
    a = ksc_server.replace('https://', '').split(":")
    print(f"Conexão estabelecida com o servidor: {a[0]} porta: {a[1]}")
else:
    print("Invalida")
    sys.exit()

    
url = ksc_server + "/api/v1.0/HostGroup.FindGroups"
common_headers = {
    'Content-Type': 'application/json',
}
data = {"wstrFilter": "", "vecFieldsToReturn": ['id', 'name'], "lMaxLifeTime": 100}
response = session.post(url=url, headers=common_headers, data=json.dumps(data), verify=False)
strAccessor = json.loads(response.text)['strAccessor']


#Checar Grupo
def get_search_results(strAccessor):
    url = ksc_server + "/api/v1.0/ChunkAccessor.GetItemsCount"
    common_headers = {
        'Content-Type': 'application/json',
    }
    data = {"strAccessor": strAccessor}
    response = session.post(url=url, headers=common_headers, data=json.dumps(data), verify=False)
    items_count = json.loads(response.text)['PxgRetVal']
    start = 0
    step = 100000
    results = list()
    while start < items_count:
        url = ksc_server + "/api/v1.0/ChunkAccessor.GetItemsChunk"
        data = {"strAccessor": strAccessor, "nStart": 0, "nCount": items_count}
        response = session.post(url=url, headers=common_headers, data=json.dumps(data), verify=False)
        results += json.loads(response.text)['pChunk']['KLCSP_ITERATOR_ARRAY']
        start += step
    return (results)

#################################################################################################################
#Checando Dispositivo
def kes_listarGrupos():
    id_ksc = []
    gr_ksc = []
    groups  = get_search_results(strAccessor)
    for group in groups:
        id_ksc.append(str(group['value']['id']))
        gr_ksc.append(str(group['value']['name']))
    return([id_ksc,gr_ksc])


#################################################################################################################
def kes_disp(inter):
    dispositivo = []
    IDC = []
    de = []
    if(inter == "PO"):
        for kesp in kes_listarGrupos()[0]: 
            group_id = kesp
            url = ksc_server + "/api/v1.0/HostGroup.FindHosts"
            common_headers = {
        'Content-Type': 'application/json',
        }
            data = {"wstrFilter": "(KLHST_WKS_GROUPID = " + str(group_id) + ")",
            "vecFieldsToReturn": ['KLHST_WKS_FQDN', 'KLHST_WKS_HOSTNAME'], "lMaxLifeTime": 100}
            response = session.post(url=url, headers=common_headers, data=json.dumps(data), verify=False)
            if 'strAccessor' in json.loads(response.text):
                strAccessor = json.loads(response.text)['strAccessor']
                hosts = get_search_results(strAccessor)
                for host in hosts:
                    dispositivo.append(host['value']['KLHST_WKS_FQDN'])
                    IDC.append(host['value']['KLHST_WKS_HOSTNAME'])
        return [dispositivo,IDC]
    else:
        group_id = inter
        url = ksc_server + "/api/v1.0/HostGroup.FindHosts"
        common_headers = {'Content-Type': 'application/json',}
        data = {"wstrFilter": "(KLHST_WKS_GROUPID = " + str(group_id) + ")",
            "vecFieldsToReturn": ['KLHST_WKS_FQDN', 'KLHST_WKS_HOSTNAME'], "lMaxLifeTime": 100}
        response = session.post(url=url, headers=common_headers, data=json.dumps(data), verify=False)
        if 'strAccessor' in json.loads(response.text):
            strAccessor = json.loads(response.text)['strAccessor']
            hosts = get_search_results(strAccessor)
            for host in hosts:
                a = (host['value']['KLHST_WKS_FQDN'] + " - " +  host['value']['KLHST_WKS_HOSTNAME'])
                de.append(a)
            return de

#################################################################################################################
def checarON(id_disp):
    host_id = str(id_disp)

    url = ksc_server + "/api/v1.0/HostGroup.GetHostProducts"
    common_headers = {
        'Content-Type': 'application/json',
    }
    data = {"strHostName": host_id}
    response = session.post(url=url, headers=common_headers, data=json.dumps(data), verify=False)
    product_data = json.loads(response.text)['PxgRetVal']
    products = dict()
    for product in product_data:
        #print(product_data)
        major_ver = list(product_data[product]['value'].keys())[0]
        if 'DisplayName' in product_data[product]['value'][major_ver]['value']:
            name = product_data[product]['value'][major_ver]['value']['DisplayName']
        else:
            name = product
        products[name] = dict()
        if 'ProdVersion' in product_data[product]['value'][major_ver]['value']:
            products[name]['version'] = product_data[product]['value'][major_ver]['value']['ProdVersion']
        else:
            products[name]['version'] = major_ver
        if 'LastUpdateTime' in product_data[product]['value'][major_ver]['value']:
            products[name]['last_update'] = product_data[product]['value'][major_ver]['value']['LastUpdateTime'][
                'value']
        else:
            products[name]['last_update'] = "n/a"
        print(name)
        print(products[name])

#################################################################################################################
def chek_rsa():
    col = kes_disp("PO")
    dispositivo = col[0]
    IDC = col[1]
    for iliv in range(0,len(IDC),1):
        if(dispositivo[iliv]== ""):
            print(f"\nNome do dispositivo não indentificado - ID: {IDC[iliv]}")
        else:
            print(f"\n{dispositivo[iliv]} - ID: {IDC[iliv]}")
            checarON(IDC[iliv])
            print("\n")


while True:
    print("\n####################################################")
    print("MICROHARD - INTEGRADOR KSC\n")
    print("1 - Listar Grupos")
    print("2 - Listar Dispositivos do Grupo Espefico")
    print("3 - Checar Dispositivos pelo ID {BETA}")
    print("4 - Verificar Status de Todos os Equipamentos KSC")
    print("5 - Sobre")
    print("6 - Sair")
    a = input("Opção: ")
    if(a=="1" or a =="2"):
        lista = ""
        lista = kes_listarGrupos()
        print("\n\nLista Kaspersky Security Center\n")
        for in_o in range(0,len(lista[0]),1):
            print(f"{lista[0][in_o]} - {lista[1][in_o]}")
        print("\n\n")
        if(a=="2"):
            ind = input("Digite o grupo desejado: ")
            if kes_disp(ind) == []:
                print("/nGrupo não encontrado./n")
            else:
                print("\n")
                for indus in kes_disp(ind):
                    print(indus)
                print("\n")
                
    elif(a=="3"):
        idor = input("Digite o ID do dispositivo: ")
        print("\n")
        checarON(idor)
        print("\n")
        
    elif(a=="4"):
        kes_disp("PO")
        chek_rsa()
        
    elif(a=="6"):
        sys.exit()
        
    elif(a=="5"):
        print("\n####################################################")
        print("MICROHARD")
        print("Desenvolvido por LUCAS MATHEUS OLIVEIRA SILVA")
        print("####################################################\n")
        time.sleep(5)
    
























