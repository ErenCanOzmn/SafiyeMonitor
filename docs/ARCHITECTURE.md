# Proje Mimarisi (Architecture)

Safiye uygulaması, FastAPI (Backend) ve Frida (Engine) teknolojilerinin bir araya gelmesiyle çalışır.

## 1. Temel Bileşenler

### A. Frontend (Web UI)
HTML/JS tabanlı arayüzdür. WebSocket üzerinden Backend ile gerçek zamanlı konuşur.
- Paketleri listeler, durdurulan paketleri (Trap) düzenlemeye izin verir.

### B. Backend (FastAPI & Frida)
`Backend_Web/safiye_server_prod.py` dosyasıdır. 
- Frida Worker Thread: Hedef süreci yönetir ve kancaları yönetir.
- Queue Processor: Frida'dan gelen mesajları WebSocket istemcilerine güvenli bir şekilde dağıtır.

### C. Frida Hook Script (JavaScript)
Hedef sürecin belleğine enjekte edilen kod kısmıdır. Ağ API'lerini (`ws2_32.dll` vb.) yakalar.

## 2. İletişim Modeli

1. **JavaScript Hook:** Paket yakalar ve `send()` ile Python'a iletir.
2. **Python `frida_on_message`:** Gelen veriyi bir `queue.Queue` içine atar.
3. **Queue Processor:** Kuyruktan veriyi alır ve `broadcast_message` ile bağlı tüm Web tarayıcılarına yollar.

## 3. Gelecek Geliştirmeler için Yol Haritası
- **Tablo Optimizasyonu:** Yoğun paket geldiğinde ekranda bellek şişmesini ve donmayı engellemek için listeleme limitleri (pagination mekanizması).
- **Paket Modifikasyonu:** "Drop" ve "Forward" mekanizmalarının eklenmesi. Bunun için JavaScript script'ine `recv` komutları yollayıp paketin manipüle edilmesini sağlayacak RPC (Remote Procedure Call) yapısının entegrasyonu.
- **Hex Editor:** Saf metin editörü yerine offset tabanlı tam bir hex editörü entegrasyonu.
