# Gerçek Dünyada SS7 Saldırıları Nasıl Yapılır?

Şu anda yazılım bilgisayarınızda (Windows) sorunsuz çalışıyor ve SS7 paketleri üretebiliyor. Ancak bu paketlerin bir telefonun konumunu bulabilmesi için **SS7 Ağına (Signaling Network)** ulaşması gerekir.

Bu işlemi evdeki internetinizden doğrudan yapamazsınız çünkü SS7 ağı, normal internetten izole edilmiş, operatörlerin kullandığı özel bir ağdır.

Gerçek sonuç almak için aşağıdaki adımları tamamlamanız gerekir:

## 1. SS7 Erişimi (SS7 Access) Edinme
Gerçek bir saldırı veya test yapmak için bir **SS7 Sağlayıcısına (Signaling Provider)** veya bir **Mobil Operatöre** doğrudan bağlantınız olması gerekir.

- Bu hizmeti satan "SS7 Hub" firmaları vardır.
- Genellikle VPN (OpenVPN, IPsec) veya SCTP over IP (SIGTRAN) tüneli ile erişim verirler.
- **Uyarı:** Bu erişim pahalıdır ve genellikle sadece lisanslı güvenlik firmalarına veya operatörlere verilir.

## 2. Bağlantı Bilgilerini Alma
Bir sağlayıcı ile anlaştığınızda size şu bilgileri vereceklerdir:

1.  **VPN Dosyası:** Bilgisayarınızı SS7 ağına bağlamak için.
2.  **Local IP:** SS7 ağında sizin kullanacağınız IP adresi (Örn: `10.20.30.5`).
3.  **Remote IP (SCTP Server):** Bağlanacağınız sunucunun IP adresi (Örn: `10.20.30.1`).
4.  **Local Port / Remote Port:** Genelde `2905` (M3UA) kullanılır.
5.  **OPC (Originating Point Code):** Sizin "Kimlik Numaranız". Ağdaki adresiniz.
6.  **DPC (Destination Point Code):** Bağlanacağınız ana santralin (STP) adresi.

## 3. SigPloit ile Gerçek Saldırı
Erişimi aldıktan ve VPN'i açtıktan sonra `sigploit.py` aracını şöyle kullanacaksınız:

1.  Aracı açın: `python sigploit.py`
2.  **SendRoutingInfo** modülüne gelin.
3.  Sorulan sorulara **gerçek** bilgileri girin:
    *   `Local IP`: VPN'den aldığınız IP (Örn: 10.20.30.5)
    *   `Remote IP`: Sağlayıcının IP'si (Örn: 10.20.30.1)
    *   `OPC`: Size verilen kod (Örn: 2045)
    *   `DPC`: Hedef santral kodu (Örn: 4412)
    *   `Target MSISDN`: Hedef telefon numarası (90553xxxxxx)

## Özet
Şu an yaptığımız işlem, bir cep telefonu (SigPloit) üretmek gibiydi. Telefon çalışıyor, tuşlarına basabiliyorsunuz. Ama arama yapabilmek için içine bir **SIM Kart (SS7 Erişimi)** takmanız ve şebekeye bağlanmanız gerekiyor.


## Sıkça Sorulan Sorular (SSS)

### S: Telefonumu (iPhone, Samsung vb.) bilgisayara bağlayıp bu aracı kullanabilir miyim?
**C: Hayır, kullanamazsınız.**

Bunun teknik nedeni şudur:
1.  **Farklı Diller:** Telefonunuz baz istasyonu ile "Radyo Dili" (Air Interface) konuşur. Bu araç ise operatörlerin merkezindeki "Ana Bilgisayar Dili"ni (SS7/Core) konuşur.
2.  **İnternet vs Sinyalizasyon:** Telefonunuzu bilgisayara bağladığınızda (Hotspot/Bloetooth/Kablo), bilgisayarınız sadece **Normal İnternete** çıkar. Operatörün "Sinyalizasyon Ağına" (Yönetim Ağı) erişemez.
3.  **Donanım Farkı:** SS7 ağlarına bağlanmak için operatörlerde milyon dolarlık özel router'lar (STP) bulunur. Bir cep telefonu bu yeteneğe sahip değildir.


### S: Bu yazılımla çevremdeki baz istasyonlarına sinyal gönderebilir miyim?
**C: Hayır.**

*   **SigPloit:** Operatörlerin birbirine bağlı olduğu "kablo" tarafındaki (Core Network) güvenlik açıklarını test eder.
*   **Baz İstasyonu:** Havadan sinyal yayan (Radio Access Network) kısımdır.

Baz istasyonları ile konuşmak veya onlara sahte sinyal göndermek için:
1.  **SDR Cihazı:** HackRF One, BladeRF, USRP gibi özel "Yazılım Tabanlı Radyo" donanımlarına ihtiyacınız vardır.
2.  **Farklı Yazılımlar:** OpenBTS, srsRAN, Osmocom gibi radyo frekansı işleyen yazılımlar gerekir.

Bilgisayarınızın Wi-Fi kartı veya telefonunuzun kendi anteni GSM/LTE frekanslarında **saldırı yapma yeteneğine sahip donanımlar değildir.** Sadece standart bağlantı kurabilirler.
