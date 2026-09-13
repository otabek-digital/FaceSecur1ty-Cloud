# FaceSecurity Universal Cloud Management (otabek-digital)

Ushbu markaziy bulut boshqaruv tizimi **FaceSecurity School v2.3** dasturi o'rnatilgan **barcha maktablar** va barcha kompyuterlarni masofadan nazorat qilish, ochish, qulflash, litsenziyalash va aloqa ma'lumotlarini markazlashtirilgan holda boshqarish uchun xizmat qiladi.

---

## 📱 Masofadan Boshqarish Imkoniyatlari:

1. **Barcha kompyuterlarni real-vaqtda boshqarish:**
   - Dastur ishga tushishi bilan o'zining Hardware ID'si, kompyuter nomi va maktabi bilan `devices.json` ro'yxatida avtomatik ko'rinadi.
   
2. **Masofadan Dasturni Ochish (ACTIVE):**
   - Veb-panelda kerakli kompyuter statusini yoki Global siyosatni **ACTIVE** qilib saqlang. Dastur bir necha soniya ichida avtomatik ochiladi.

3. **Masofadan Dasturni Qulflash (BLOCKED / Blacklist):**
   - Kompyuter statusini **BLOCKED** ga o'tkazing yoki `blacklist` ro'yxatiga qo'shing. Dastur darhol qulflanadi va kamerani to'xtatadi.

4. **✈️ Telegram va Aloqa Ma'lumotlarini Masofadan Yangilash:**
   - Veb-panelning **«✈️ Telegram Aloqa»** bo'limidan admin ismi, Telegram niki (masalan: `otabek_digital`) yoki to'liq havolani o'zgartirib saqlang.
   - Barcha maktab kompyuterlaridagi login va qulflash ekranlarida siz ko'rsatgan yangi havola avtomatik paydo bo'ladi.

---

## 🔒 Xavfsizlik va GitHub PAT Token Tavsiyalari:

- **Fine-grained Personal Access Token (PAT):**
  - GitHub PAT yaratayotganda faqat bitta ushbu `FaceSecur1ty-Cloud` repozitoriyasiga va faqat `Contents: Read and write` huquqini bering.
  - Token faqat sizning brauzeringizda (localStorage) xavfsiz saqlanadi.
- **DB Tamper Protection:**
  - Kompyuterlardagi SQLite ma'lumotlar bazasi SHA-256 HMAC MAC zanjiri bilan himoyalangan. Faylni to'g'ridan-to'g'ri o'zgartirish `TAMPERED` signali beradi va dasturni qulflaydi.
- **Audit Jurnali:**
  - Barcha login, aktivatsiya, CLI va masofaviy buyruq urinishlari xavfsizlik audit jurnaliga (`security_audit.log`) yoziladi.
