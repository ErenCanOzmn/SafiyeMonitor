---
description: Context and Rules for AI Assistants
---
## 1. Proje Kimliği ve Amacı
Bu proje (Safiye), Python (PyQt6) ile yazılmış, Frida kullanarak Windows platformunda çalışan bir **All-in-One Masaüstü Uygulama Pentest Aracıdır**. Başlangıçta sadece TCP trafiğini (ws2_32.dll) incelemek ve manipüle etmek için tasarlanmış olsa da, artık dosya sistemi, DLL yüklemeleri ve diğer işletim sistemi etkileşimlerini de kapsayacak modern bir güvenlik test aracı olarak geliştirilmektedir.
## 2. Kodlama Kuralları ve Kritik Uyarılar

### Threading ve GUI Kilitlenmeleri (Kritik!)
- PyQt6'nın ana döngüsü (Event Loop) hiçbir zaman bloklanmamalıdır (örn: `time.sleep()`, uzun `while` döngüleri arayüzde olamaz).
- Frida'nın `on_message` callback fonksiyonu içerisinde **ASLA** doğrudan bir PyQt sinyali (`emit`) kullanmayın veya GUI nesnelerine (örn: `setText`, `append`) dokunmaya çalışmayın! Bu durum Frida'nın C-thread'i ile Python GIL'i ve Qt Thread'i arasında deadlock yaratır ve yazılımı kilitler.
- Frida mesajları her zaman `self.message_queue.put()` kullanılarak asenkron kuyruğa atılmalı, işlemler kuyruk işleyici (`_process_queue`) thread üzerinden `emit` ile GUI'ye yollanmalıdır.

### Modern Tasarım (Cyberpunk/Synthwave Tema)
- Yeni bir pencere öğesi (Widget) eklendiğinde projenin tasarım diline sadık kalın.
- Ana renkler: Koyu Arka Plan `#0d0e15`, İkincil Ara Katmanlar `#1a1c29`, Aktif ve Neon renkler `#05d9e8` (Cyan/Mavi) ve `#ff2a6d` (Canlı Pembe).
- Basit UI düğmeleri kullanmayın, `setStyleSheet` üzerinden border, hover, border-radius değerlerini mutlaka tanımlayın.

### Frida Script (JavaScript)
- JavaScript tarafındaki kodlar string halinde (`FRIDA_SCRIPT` değişkeninde) yazılmaktadır. Buraya kod eklerken syntax hatası yapmamaya çok dikkat edin çünkü bu çalışma zamanında (Runtime) patlar.
- Yeni `NativeFunction` veya `NativeCallback` eklerken Windows'un Mimari farklılıklarına (x86 / x64 pointer boyutları, stdcall/cdecl calling convention) dikkat edin. Proje şimdilik genelde temel kancalarla ilerlemektedir.

## 3. Test ve Geliştirme Süreci
C++ tabanlı bir test executables'ı bulunmaktadır: `Safiye_Test_Exeleri\test1.cpp`.
Eğer sisteme yeni bir API yakalama metodu eklerseniz (Örneğin `recv` yakalama veya TLS/SSL decrypting), önce `test1.cpp` içerisine bu durumu tetikleyecek bir ağ isteği kodu ekleyin, cpp'yi derleyin ve onun üzerinde test gerçekleştirin.

## 4. Geliştirici Ortamı (Terminal Komutları)
Python exe ve pip kütüphanelerini çağırırken sistem sanal ortamını (eğer varsa) kullanın. Kodda eksik kütüphane olduğunu tespit ederseniz kullanıcıdan izin alarak ya da pro-aktif olarak `pip install` komutlarını projeye zarar vermeyecek şekilde çalıştırın.
