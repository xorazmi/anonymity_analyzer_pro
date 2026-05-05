# Anonymity Analyzer Pro

**Anonymity Analyzer Pro** — bu foydalanuvchining tarmoqdagi anonimlik darajasini tahlil qilish va tizim xavfsizligini tekshirish uchun mo'ljallangan Python dasturi.

## Asosiy funksiyalari
1. Tizim va Tarmoq Tahlili (Analyzers)
Loyiha turli xil texnik parametrlar orqali foydalanuvchi qurilmasini tekshiradi:

IP Analyzer (ip_analyzer.py): Foydalanuvchining ochiq IP manzili, uning geografik joylashuvi (shahar, davlat) va internet provayderi (ISP) haqidagi ma’lumotlarni aniqlaydi.

Network Analyzer (network_analyzer.py): Tarmoq konfiguratsiyasini tahlil qiladi. Ochiq portlarni, DNS oqishlarini (DNS leak) va tarmoq interfeyslari holatini tekshiradi.

System Analyzer (system_analyzer.py): Operatsion tizim haqida batafsil ma’lumot to'playdi (OS versiyasi, qurilma nomi, foydalanuvchi nomi). Bu ma’lumotlar "qurilma barmoq izi" (fingerprinting) orqali foydalanuvchini tanib qolish xavfini baholash uchun ishlatiladi.

Tor & VPN Checker (tor_vpn.py): Foydalanuvchi hozirda Tor tarmog'i yoki VPN orqali ulanganligini tekshiradi. Bu anonimlikning asosiy qatlamlaridan biridir.

2. Xavfsizlikni Baholash va Hisoblash
Dastur shunchaki ma’lumot yig'ish bilan cheklanmay, ularni tahlil qiladi:

Scoring Engine (scoring.py): Barcha tahlil natijalarini jamlab, umumiy "Anonimlik Balli"ni (Anonymity Score) hisoblaydi. Agar tizimda kamchiliklar bo'lsa, ball pasayadi.

Leak Concepts (leak_concepts.py): Mumkin bo'lgan ma’lumotlar sizib chiqish tushunchalarini (masalan, WebRTC leak, IPv6 leak) aniqlaydi va ularning xavflilik darajasini belgilaydi.

Scan Pipeline (scan_pipeline.py): Barcha tahlillarni birma-bir, tartib bilan ishga tushirish jarayonini (konveyer) boshqaradi.

3. Tushuntirish va Foydalanuvchi Interfeysi
Explanations (explanations.py): Texnik natijalarni oddiy foydalanuvchi tushunadigan tilga o'giradi. Har bir aniqlangan xavf yoki ochiq ma’lumot nima uchun xavfli ekanligini tushuntirib beradi.  

Loyihaning ishlash tartibi:
Initsializatsiya: __init__.py orqali barcha modullar yuklanadi.

Ma'lumot yig'ish: IP, Tarmoq va Tizim modullari ishga tushib, barcha ko'rinadigan ma’lumotlarni yig'adi.

Tahlil: Yig'ilgan ma’lumotlar VPN/Tor borligi va sizib chiqishlar (leaks) bo'yicha tekshiriladi.

Baholash: scoring.py ball beradi.

Hisobot: explanations.py orqali foydalanuvchiga yakuniy xulosa va tavsiyalar taqdim etiladi.  

Ushbu loyiha kiberxavfsizlik va OSINT bilan qiziquvchilar uchun o'z raqamli izlarini (digital footprint) nazorat qilishda foydali vositadir.
## O'rnatish va ishga tushirish

1. Repozitoriyani yuklab oling:
```bash
git clone https://github.com/xorazmi/anonymity_analyzer_pro.git
pip install -r requirements.txt
python main.py
