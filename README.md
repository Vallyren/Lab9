# Lab9
## Мониторинг состояния сети с помощью Python
### Обнаружение атаки arp_spoofing и отправка сообщения оператору.
### Цель:
### Необходимо доработать скрипт arp_spoof_detector.py, написанный на занятии, чтобы в случае обнаружения атаки arp_spoofing-а отправлялось письмо на почту  ответственного лица (можно на вашу).
#!/usr/bin/env python
import scapy.all as scapy

def get_mac_addr(ip):
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_req_broadcast = broadcast/arp_req
    resp_list = scapy.srp(arp_req_broadcast, timeout=1, verbose=False)[0]
    return resp_list[0][1].hwsrc

def send_alarm(email, password, message):
   import smtplib
            from email.mime.multipart import MIMEMultipart
            from email.mime.text import MIMEText

            me = "re.nata2018@yandex.ru"
            my_password = "************"
            you = "vallyren@gmail.com"

            msg = MIMEMultipart('alternative')
            msg['Subject'] = "Alert"
            msg['From'] = me
            msg['To'] = you

            html = '<html><body><p>Hi, I have the following alerts for you!</p></body></html>'
            part2 = MIMEText(html, 'html')

            msg.attach(part2)

            s = smtplib.SMTP_SSL('smtp.yandex.ru')
            s.login(me, my_password)

            s.sendmail(me, you, msg.as_string())
            s.quit()
   pass

def process_sniffed_packet(packet):
   if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
      try:
         real_mac = get_mac_addr(packet[scapy.ARP].psrc)
         response_mac = packet[scapy.ARP].hwsrc
         if real_mac != response_mac:
            print('ALARM! ARP-spoofing attack was detected!')
         except IndexError:
         pass

def sniff(interface):
   scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

sniff('eth0')
#### Необходимо доработать скрипт, используя библиотеку smtp для отправки сообщения при обнаружении атаки.
#### Также необходимо протестировать скрипт в трех разных случаях:
##### 1. машина не находится под атакой arp-spoofing
##### 2. машинка находится под атакой и скрипт обнаружения был запущен до начала атаки
##### 3. машинка находится под атакой и скрипт обнаружения был запущен после начала атаки
##### Для проверки необходимо предоставить доработанный код, а также скриншоты, где видны арп-таблицы и консольный вывод скриптов.
