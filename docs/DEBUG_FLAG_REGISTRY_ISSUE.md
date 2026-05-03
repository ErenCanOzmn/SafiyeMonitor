# 🚩 FLAG: Registry Hooking Debug Status

## Mevcut Durum (Current Status)
Safiye'nin "Registry & File Monitor" özelliği için `safiye_frida_script.js` arka plan kancalarını yazdık. Amacımız hedefin (özellikle kalın istemcilerin - thick clients) Windows Kayıt Defterinde (Registry) yaptığı işlemleri yakalamak. 

Özel olarak test etmek için `winreg` modülü kullanan Python scriptleri (`safiye_pentest_dummy.py` ve `reg_test.py`) oluşturduk.

## Ne Denedik?
1. Sadece `advapi32.dll` içindeki `RegOpenKeyExW` ve benzeri fonksiyonları kancalamak yetmediğinden, **A (ANSI)** versiyonlarını ve **`KernelBase.dll`** kütüphanesini de kancaladık.
2. `debug_frida.py` aracılığıyla Python'un registry işlemlerini (örneğin `Software\MyApp_Test` anahtarını oluşturup `Test=Val` değerini atamasını) izledik.
3. Çıktı loglarında (`out.txt`) `RegCreateKeyExW` ve `RegCreateKeyW` çağrılarını **başarıyla gördük**.

## Nerede Kaldık? (Problem)
Kayıt defteri anahtarının *oluşturulduğunu* yakalamamıza rağmen, değerin atandığı **`RegSetValueExW` / `RegSetValueExA` çağrıları (yani asıl verinin yazıldığı anlar) Frida tarafından hala loglanmıyordu.** 
`out.txt` içinde `MyApp_Test` için `RegCreateKeyW` görüldü ama `RegSetValueExW` görünmedi. Bu da demek oluyor ki değer atama işlemi (SetValue) kancaladığımız bu fonksiyonlardan farklı bir API üzerinden veya farklı bir formda gerçekleşiyor olabilir.

Bir sonraki otorumda doğrudan `RegSetValueEx` kancalarının neden tetiklenmediğini veya Python/Windows'un arka planda `NtSetValueKey` (ntdll.dll) gibi çok daha düşük seviyeli bir syscall kullanıp kullanmadığını analiz etmemiz gerekecek.

---
*Not: Bu dosya, kullanıcı "işi çözememişsin buraya bir bayrak dik burada kaldığıma dair seni tekrar açtığımızda hatırla" komutu verdiği için bir sonraki görüşmede problemi anımsamak adına bir yer imi (bookmark) olarak bırakılmıştır.*
