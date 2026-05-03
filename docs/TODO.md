# SAFIYE — KALDI BURADAN DEVAM ET

## ❌ Tamamlanmamış / Sorunlu
- **TRAP Modal (intercept)** bitmedi:
  - Modal eklendi (`interceptModal` in `index.html`) ✅
  - `app.js`'de `prompt()` → modal ile değiştirildi ✅
  - Ama gerçek testini yapamadın (sunucu açıkken dene).
  
- **HTTP isteği body/header manipülasyonu tam doğrulanmadı:**
  - Frida script (`safiye_cpp_script.js`) artık `modified_headers` alıyor, ancak manipüle işleminin gerçekten çalıştığını canlı test etmedin.

## 🔜 Devam Edecekler
1. **HTTP TRAP testi:** Web UI'yi kapat/aç, `HOOK BAŞLAT` → Seçenek 4 (HTTP POST) → Yeni TRAP Modal ekranı açılmalı → Headers + Body değiştirip FORWARD de.
2. **SQL Server (Mock):** Local'de sahte bir MS-SQL sunucusu kur (örn: `ncat -lvp 1433`), `test_registry.exe` → Seçenek 5 → 192.168.1.101:1433'e TDS paketi gönderecek, Safiye'nin bunu yakalamasını izle.
3. **SQL intercept testi:** Frida hook (`ws2_32!send`) port 1433'ü zaten dinliyor, ancak `getpeername` sorunları yüzünden beklenmedik davranışlar çıkabilir → Hata ayıklama gerekebilir.

## 📁 Önemli Dosyalar
| Dosya | Açıklama |
|---|---|
| `Safiye_Test_Exeleri\Deserialization_Demos\safiye_cpp_script.js` | Frida hook script — tüm kancalar burada |
| `Safiye_Test_Exeleri\Deserialization_Demos\test_registry.cpp` | C++ test uygulaması (menü 1-5) |
| `Safiye_Web\safiye_server.py` | Python backend sunucu |
| `Safiye_Web\static\js\app.js` | Frontend JS |
| `Safiye_Web\templates\index.html` | Ana HTML (modal'lar burada) |

## ⚡ Sunucuyu Başlatmak İçin
```powershell
cd Safiye\Safiye_Web
python safiye_server.py
```
Tarayıcı: http://127.0.0.1:5000
