require('dotenv').config();
const oracledb = require('oracledb'), bcrypt = require('bcryptjs');
const [, , user, pass] = process.argv;
(async () => {
  const c = await oracledb.getConnection({ user: process.env.DB_USER, password: process.env.DB_PASSWORD, connectString: process.env.DB_CONNECT });
  const r = await c.execute("UPDATE accounts SET password=:p, status='active' WHERE username=:u",
    { p: await bcrypt.hash(pass, 10), u: user }, { autoCommit: true });
  console.log(r.rowsAffected ? 'เปลี่ยนรหัสผ่านแล้ว' : 'ไม่พบผู้ใช้นี้');
  await c.close();
})();