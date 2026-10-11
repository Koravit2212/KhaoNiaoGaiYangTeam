# Employee Management System (Oracle + Node.js)
1. ติดตั้ง Node.js 18+ และมี Oracle DB (เช่น Oracle XE) พร้อมสร้าง user ที่มีสิทธิ์ CREATE TABLE
2. `npm install` แล้วคัดลอก `.env.example` เป็น `.env` ใส่ค่า DB_USER / DB_PASSWORD / DB_CONNECT
3. `npm run setup` (สร้างตารางจาก schema.sql + ข้อมูลตัวอย่าง) แล้ว `npm start` เปิด http://localhost:3000
บัญชีตัวอย่าง (รหัสผ่าน Passw0rd!): somchai.j@nexus.co.th (HR), manager@nexus.co.th (ผู้บริหาร), dev@nexus.co.th (พนักงาน)
