# Lab9
## Мониторинг состояния сети с помощью Python
### Обнаружение атаки arp_spoofing и отправка сообщения оператору.
### Цель:
### Необходимо доработать скрипт arp_spoof_detector.py, написанный на занятии, чтобы в случае обнаружения атаки arp_spoofing-а отправлялось письмо на почту  ответственного лица (можно на вашу).
!/usr/bin/env python
import scapy.all as scapy
import requests
import time

def get_mac_addr(ip):
    ''' Get mac address by ip '''
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_req_broadcast = broadcast/arp_req
    resp_list = scapy.srp(arp_req_broadcast, timeout=2, verbose=False)[0]
    
    return resp_list[0][1].hwsrc

def process_sniffed_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            real_mac = get_mac_addr(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc
            if real_mac != response_mac:
               print('ALARM! ARP-spoofing attack was detected!')
               print(requests.get("https://api.telegram.org/bot" + "5927179591:AAFmSCzAWMdGoH8A3Gym85vKShnNpGAIRfY" + "/sendMessage" + "?chat_id=" + "1362069585" + "&text=" + "Нас атакуют!!!!!!").json()) 
        except IndexError:
           pass

def sniff(interface):
    
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

    
sniff('eth0')
#### Необходимо доработать скрипт, используя библиотеку smtp для отправки сообщения при обнаружении атаки.
#### Также необходимо протестировать скрипт в трех разных случаях:
##### 1. машина не находится под атакой arp-spoofing
![не под атакой кали](https://user-images.githubusercontent.com/122459067/230773195-aef187e0-4218-4337-8137-7f97c88966ab.png)
![не под атакой клон](https://user-images.githubusercontent.com/122459067/230773202-d5da961a-5c42-4eac-8ab1-60b8bafb7b34.png)

##### 2. машинка находится под атакой и скрипт обнаружения был запущен до начала атаки
![под атакой детект запущен до атаки кали1](https://user-images.githubusercontent.com/122459067/230773213-38365da1-dc8e-44da-a9fc-891bac0b86e4.png)
![под атакой детект запущен до атаки клон](https://user-images.githubusercontent.com/122459067/230773219-844e0069-25a0-4ee1-be11-135413a264b4.png)

##### 3. машинка находится под атакой и скрипт обнаружения был запущен после начала атаки
![2023-04-09_15-23-35](https://user-images.githubusercontent.com/122459067/230773244-80947354-a2f0-46a8-8de0-64f9dce4a7a3.png)
![2023-04-09_15-23-05](https://user-images.githubusercontent.com/122459067/230773255-02d42731-4ee9-4376-80c3-32794223b13f.png)

##### Для проверки необходимо предоставить доработанный код, а также скриншоты, где видны арп-таблицы и консольный вывод скриптов.
##### Доработанный код представляет собой скрипт отправки сообщения в телеграмм чат-ботом, созданным для демонстрации
![2023-05-06_21-54-09](https://user-images.githubusercontent.com/122459067/236642576-9424dc1d-d099-472f-995a-2cb534b90c63.png)
##### Во избежание ошибок нагрузки на виртуальные машины Kali, а также блокировки бота, интервалы снифа снижены до 30 сек
![2023-05-06_21-50-15](https://user-images.githubusercontent.com/122459067/236642705-42bf4876-195c-443f-9b9d-94a825e4aed8.png)
##### Машина атакующего:
![2023-05-06_21-51-56](https://user-images.githubusercontent.com/122459067/236642754-7a90c4c0-e91f-45bf-8d03-e5b2de15716c.png)
![2023-05-06_21-48-00](https://user-images.githubusercontent.com/122459067/236642766-7c66b3fc-bed8-41eb-a1e7-b2f85a70efce.png)
##### Машина атакуемого:
![2023-05-06_21-54-09](https://user-images.githubusercontent.com/122459067/236642797-912d154c-58b4-4de3-bbb5-0c3530fbffd2.png)
![2023-05-06_21-55-43](https://user-images.githubusercontent.com/122459067/236642817-945e760d-5ffd-49b7-b5ec-4debc018eb83.png)
##### Чат-бот Телеграмм:
![2023-05-06_21-56-12](https://user-images.githubusercontent.com/122459067/236642839-faca4008-d7f9-4235-ad0d-104e997fd91c.png)


