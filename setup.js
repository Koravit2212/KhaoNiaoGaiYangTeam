require('dotenv').config();
const oracledb=require('oracledb'),bcrypt=require('bcryptjs'),fs=require('fs');
(async()=>{
 const c=await oracledb.getConnection({user:process.env.DB_USER,password:process.env.DB_PASSWORD,connectString:process.env.DB_CONNECT});
 for(const s of fs.readFileSync('schema.sql','utf8').split(/;\s*\n/).map(x=>x.trim()).filter(Boolean)){
  try{await c.execute(s)}catch(e){if(e.errorNum!==955)throw e}}
 const n=(await c.execute('SELECT COUNT(*) n FROM departments')).rows[0][0];
 if(!n){
  const pw=await bcrypt.hash('Passw0rd!',10),o={autoCommit:false};
  for(const d of['ฝ่ายทรัพยากรบุคคล','ฝ่ายไอที','ฝ่ายบัญชี'])await c.execute('INSERT INTO departments(department_name) VALUES(:d)',[d],o);
  for(const[p,s]of[['HR Officer',28000],['Manager',65000],['Developer',45000],['Accountant',32000]])await c.execute('INSERT INTO positions(position_name,salary_rate) VALUES(:p,:s)',[p,s],o);
  const U=[['somchai.j@nexus.co.th','hr','สมชาย','จันทร์เพ็ญ',1,1],['manager@nexus.co.th','manager','วิภา','สุขสันต์',1,2],['dev@nexus.co.th','employee','นภัส','ใจดี',2,3]];
  for(const[u,r,f,l,d,p]of U){
   const a=await c.execute("INSERT INTO accounts(username,password,role) VALUES(:u,:p,:r) RETURNING account_id INTO :id",{u,p:pw,r,id:{dir:oracledb.BIND_OUT,type:oracledb.NUMBER}},o);
   await c.execute("INSERT INTO employees(account_id,department_id,position_id,first_name,last_name,email,hire_date) VALUES(:a,:d,:p,:f,:l,:u,SYSDATE)",{a:a.outBinds.id[0],d,p,f,l,u},o)}
  await c.commit();console.log('Seeded. Login: somchai.j@nexus.co.th / manager@nexus.co.th / dev@nexus.co.th  password Passw0rd!')}
 console.log('Database ready');await c.close()})().catch(e=>{console.error(e);process.exit(1)});
