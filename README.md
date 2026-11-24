# Switch Bulucu

Fluke LinkRunner benzeri basit bir Windows aracı. Ağ kablosunu bilgisayara takıp
çalıştırınca bağlı olduğun switch'in **adını, portunu, IP'sini ve VLAN'ını** gösterir.
Ayrıca bilgisayarın IP, MAC ve gateway bilgisini listeler.

Bilgiyi switch'in yayınladığı **LLDP** ve **CDP** paketlerinden okur.

## Gereksinimler

- Windows
- [Npcap](https://npcap.com) (ağ paketlerini yakalamak için, bir kere kurulur)
- Yönetici izni (exe açılırken ister)

> **Npcap olmadan çalışmaz.** Windows, switch'in gönderdiği bu paketleri normal
> uygulamalara vermiyor, bu yüzden bir paket yakalama sürücüsü gerekiyor. Npcap'in
> lisansı yüzünden kurulum dosyası bu projeye eklenmemiştir, npcap.com'dan indir.
> Npcap kurulu değilse program bunu söyler ve npcap.com sayfasını açmayı önerir.

## Exe oluşturma

1. [Python](https://python.org) kur ("Add Python to PATH" kutusunu işaretle).
2. Npcap kur.
3. `build.bat` dosyasına çift tıkla.
4. `dist\switch_bulucu.exe` oluşur.

Elle yapmak istersen:

```
python -m pip install -r requirements.txt pyinstaller
python -m PyInstaller --onefile --noconsole --uac-admin --name switch_bulucu switch_bulucu.py
```

GitHub'da `Actions` sekmesinden "Exe olustur" iş akışını çalıştırırsan exe'yi
oradan da indirebilirsin.

## Kullanım

1. Exe'yi aç ("Evet" de).
2. Kablolu ağ kartını seç.
3. **Switch'i Bul** butonuna bas.
4. Switch paketini yollayana kadar bekle (30-60 saniye sürebilir).

## Sınırlar

- Switch'te **LLDP ve CDP kapalıysa** bilgi alınamaz. Başka bir program da alamaz.
- Bazı switch'ler (örn. Alcatel OmniSwitch) varsayılan ayarda port adı, switch adı ve
  yönetim IP'sini LLDP'ye koymaz. Switch'te bu TLV'lerin açılması gerekir.
- Wi-Fi'da çalışmaz, kablolu bağlantı gerekir.
- Android'de çalışmaz.
- Kablo testi (kopuk tel, uzunluk) yapmaz.

## Lisans

MIT
