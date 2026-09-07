# FaceSecurity Cloud Management Server (otabek-digital)

Ushbu repozitoriya **FaceSecurity School v1.3** dasturining masofaviy litsenziya va xavfsizlik nazorati uchun xizmat qiladi.

## 📱 Telefon orqali boshqarish yo'riqnomasi:

### 1. Dasturni ochish (Faollashtirish):
`devices.json` faylini tahrirlab, kerakli kompyuter kodining `status` qiymatini `"ACTIVE"` qilib saqlang:
```json
"FS-XXXX-XXXX": {
  "status": "ACTIVE",
  "school": "41-Maktab"
}
```

### 2. Dasturni masofadan qulflash (Bloklash):
`status` qiymatini `"BLOCKED"` yoki `"EXPIRED"` qilib saqlang:
```json
"FS-XXXX-XXXX": {
  "status": "BLOCKED",
  "school": "41-Maktab"
}
```

### 3. Barcha maktab qurilmalarini bir vaqtda ochish:
`"FS-GLOBAL"` kalitining `status` qiymatini `"ACTIVE"` qilish kifoya.

---
🔒 **Xavfsizlik:** Faqat **otabek-digital** akkaunti ushbu faylni o'zgartira oladi. Begona shaxslar yoki dasturlar ruxsatsiz o'zgartirish kirita olmaydi.
