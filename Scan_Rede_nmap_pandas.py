#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import nmap
import pandas as pd    
from datetime import datetime
from pathlib import Path

nm_read = nmap.PortScanner()                                            #variavel do scanner


options = "--host-timeout 1m -sn"                                       #opções to scaneador
print("test")


with open("C:\\output\\Teste.txt", "w", newline="\n") as file:           #diretorio para salvar
    file.write(str(nm_read.scan('10.0.0.0/24', arguments=options)))     #scanear e salva no arquivo de texto



# In[ ]:


#Importa a base de dados
#Corta a primeira linha de dados referente á leitura e não aos dados em si



network = pd.read_csv(Path("C:/output/Teste.txt"), sep="256" , header=None)
network.columns = ['delete','keep']                                     #define colunas para tratamento de dados                          
#display(network)                                                       #debugging
network = network.drop(columns=['delete'])                              #delete coluna com dados não utilizados
#display(network)                                                       #debugging
s = network['keep'].str[13:]                                            #Corta os dados "leftover" da coluna delete
#display(s)                                                             #debugging
#display(network['keep'])                                               #debugging
network['keep']  = s                                                    #Insere dados tratados na coluna
#display(network)                                                       #debugging

network.to_csv("C:\\output\\Teste2.txt", index=False)                    #Salva os dados tratados para tratamento posterior


# In[ ]:


network = pd.read_csv("C:\\output\\Teste2.txt", sep="}}")
network = network.reset_index()                                 #reestrutura -> ID para Colunas 
network = network.melt()                                        #reestrutura -> ID para linha
network = network.drop(columns=["variable"])                    #deleta coluna após oganizada


network['value'] = network['value'].str[3:]                     #remove "clutter" inicial
ip = network["value"].str.split(pat="':", expand=True)[0]       #Guarda os endereços de IP
network ["IP"] = ip                                             #cria uma coluna com os endereços de IP


network['value'] = network["value"].str.split(pat=':', n=1).str.get(1) #str.get(-1)-> last part after occurance #str.get(0)-> exact part being removed #str.get(1) cuts the removed part, keeps rest of string
network['value'] = network["value"].str.split(pat=':', n=1).str.get(1) #Ambas as linhas remove partes já tratadas (referentes a IPs)


network['value'] = network['value'].str[4:]                         #remove "clutter"
nome_maquina = network["value"].str.split(pat="':", expand=True)[1] #recebe nome da maquina
nome_maquina = nome_maquina.str[2:]                                 #limpa dados inicio
nome_maquina = nome_maquina.str[:-8]                                #limpa dados fim
network["Nome Maquina"] = nome_maquina                              #cria coluna nome da maquina

network['value'] = network["value"].str.split(pat="ipv4", n=1).str.get(1)
network['value'] = network["value"].str.split(pat="mac", n=1).str.get(-1)

network['value'] = network['value'].str[4:]                         #remove "clutter"
ende_mac = network["value"].str.split(pat="},", n=1).str.get(0)     #recebe mac
ende_mac = ende_mac.str[:-1]                                        #limpa final no mac
network['MAC'] = ende_mac                                           #coluna MAC recevbe valores mac


network['value'] = network["value"].str.split(pat="vendor", n=1).str.get(1) #removidas partes já tratadas

x=0                                                                         #loop para remover partes já tratdas do MAC
while x < 7:
    network['value'] = network["value"].str.split(pat=":", n=1).str.get(1)
    x = x+1

vendedor = network['value'].str.split(pat="},", n=1).str.get(0)            #alcançar partes tratadas 
vendedor = vendedor.str[2:]                                                #cortar clutter inicio
vendedor = vendedor.str[:-1]                                               #cortar clutter final
network["Vendedor"] = vendedor                                             #cria coluna

x=0                                                                         #loop para remover partes já tratdas do MAC
while x < 1:
    network['value'] = network["value"].str.split(pat=":", n=1).str.get(1)
    x = x+1

network = network.drop(columns=["value"])                                               #remove coluna com dados que não será tratados
network.drop(network.tail(2).index, inplace=True)                                       #remove as endereços finais 
#display(network)
current_time = datetime.now().strftime("%Y-%m-%d %H-%M-%S")                             #define o formato para arquivos
print(current_time)
filename = str(current_time)+".txt"                                                     #nome do arquivo com o tempo atual
network.to_csv("C:\\Scaneamento\\Logs\\"+filename, sep=';', index=False, header=True)     #exporta o arquivo
filename_csv = str(current_time)+".csv"                                                 #nome do arquivo com o fim .txt
network.to_csv("C:\\Scaneamento\\CSV\\"+filename_csv, sep=';', index=False, header=True)
