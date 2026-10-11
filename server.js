require('dotenv').config();
const express=require('express'),oracledb=require('oracledb'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken');
oracledb.outFormat=oracledb.OUT_FORMAT_OBJECT;oracledb.autoCommit=true;oracledb.fetchAsString=[oracledb.CLOB];
const app=express(),S=process.env.JWT_SECRET||'change-me',HR=['hr','admin'],DEF='Passw0rd!',fails=new Map();
app.use(express.json({limit:'1mb'}));app.use(express.static('public'));
let poolP;const getPool=()=>poolP||(poolP=oracledb.createPool({user:process.env.DB_USER,password:process.env.DB_PASSWORD,connectString:process.env.DB_CONNECT,poolMin:0,poolMax:3}).catch(e=>{poolP=null;throw e}));
const run=async(s,b={})=>{const c=await(await getPool()).getConnection();try{return await c.execute(s,b)}finally{await c.close()}};
const P2=n=>String(n).padStart(2,'0'),ymd=d=>`${d.getFullYear()}-${P2(d.getMonth()+1)}-${P2(d.getDate())}`;
const q=async(s,b)=>(await run(s,b)).rows.map(r=>Object.fromEntries(Object.entries(r).map(([k,v])=>[k.toLowerCase(),v instanceof Date?ymd(v):v])));
const att=r=>{const{data,...o}=r;return{...o,ot_hours:+data||0}};
const h=f=>(req,res)=>f(req,res).catch(e=>{console.error(e);res.status([1,2292].includes(e.errorNum)?409:500).json({error:e.errorNum===1?'ข้อมูลนี้มีอยู่แล้ว (ชื่อ วันที่ หรืออีเมลซ้ำ)':e.errorNum===2292?'ลบไม่ได้ เพราะมีพนักงานหรือคำขอใช้งานอยู่':'ระบบขัดข้อง กรุณาลองใหม่'})});
const auth=(...r)=>(req,res,next)=>{try{req.u=jwt.verify((req.headers.authorization||'').slice(7)||req.query.t,S)}catch{return res.status(401).json({error:'กรุณาเข้าสู่ระบบใหม่'})}
 if(r.length&&!r.includes(req.u.role))return res.status(403).json({error:'ไม่มีสิทธิ์เข้าถึงข้อมูลนี้'});next()};
const okMonth=m=>/^\d{4}-(0[1-9]|1[0-2])$/.test(m||''),span=m=>{const[y,mo]=m.split('-').map(Number);return[m+'-01',m+'-'+P2(new Date(y,mo,0).getDate())]};
const EMP=`SELECT e.employee_id,e.first_name,e.last_name,e.email,e.phone,e.address,e.hire_date,e.day_off,e.employment_status,e.department_id,e.position_id,d.department_name,p.position_name,e.manager_id,m.first_name||' '||m.last_name manager_name FROM employees e LEFT JOIN employees m ON m.employee_id=e.manager_id JOIN departments d ON d.department_id=e.department_id JOIN positions p ON p.position_id=e.position_id`;

app.post('/api/login',h(async(req,res)=>{
 const{username,password}=req.body,[a]=await q('SELECT * FROM accounts WHERE username=:u',{u:username||''});
 if(!a||a.status==='inactive')return res.status(401).json({error:'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง หรือบัญชียังไม่เปิดใช้งาน'});
 if(a.status==='locked')return res.status(423).json({error:'บัญชีถูกล็อก กรุณาติดต่อฝ่าย HR'});
 if(!await bcrypt.compare(password||'',a.password)){const n=(fails.get(a.account_id)||0)+1;fails.set(a.account_id,n);
  if(n>=5)await run("UPDATE accounts SET status='locked' WHERE account_id=:i",{i:a.account_id});
  return res.status(401).json({error:'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง'})}
 fails.delete(a.account_id);
 const[e]=await q('SELECT employee_id,first_name,last_name FROM employees WHERE account_id=:i',{i:a.account_id});
 const name=e?e.first_name+' '+e.last_name:a.username;
 res.json({token:jwt.sign({id:a.account_id,role:a.role,eid:e&&e.employee_id,name},S,{expiresIn:'8h'}),role:a.role,name})}));

app.get('/api/lookups',auth(),h(async(_,res)=>res.json({departments:await q('SELECT department_id,department_name FROM departments ORDER BY 2'),positions:await q('SELECT position_id,position_name FROM positions ORDER BY 2')})));
app.get('/api/me',auth(),h(async(req,res)=>res.json((await q(EMP+' WHERE e.employee_id=:i',{i:req.u.eid||0}))[0]||null)));

app.get('/api/employees',auth(...HR),h(async(req,res)=>res.json(await q(EMP+" WHERE TO_CHAR(e.employee_id)||e.first_name||' '||e.last_name||d.department_name||p.position_name LIKE :s ORDER BY e.employee_id",{s:'%'+(req.query.q||'')+'%'}))));
app.post('/api/employees',auth(...HR),h(async(req,res)=>{
 const b=req.body;if(!['first_name','last_name','email','hire_date','department_id','position_id'].every(k=>b[k]))return res.status(400).json({error:'กรอกข้อมูลให้ครบทุกช่องที่จำเป็น'});
 const c=await(await getPool()).getConnection(),o={autoCommit:false};
 try{const a=await c.execute("INSERT INTO accounts(username,password,role) VALUES(:u,:p,:r) RETURNING account_id INTO :id",{u:b.email,p:await bcrypt.hash(DEF,10),r:b.role||'employee',id:{dir:oracledb.BIND_OUT,type:oracledb.NUMBER}},o);
  const e=await c.execute("INSERT INTO employees(account_id,department_id,position_id,manager_id,first_name,last_name,email,phone,address,hire_date,day_off) VALUES(:a,:d,:p,:mg,:fn,:ln,:em,:ph,:ad,TO_DATE(:hd,'YYYY-MM-DD'),:dof) RETURNING employee_id INTO :id",
   {a:a.outBinds.id[0],d:b.department_id,p:b.position_id,mg:b.manager_id?+b.manager_id:null,fn:b.first_name,ln:b.last_name,em:b.email,ph:b.phone||null,ad:b.address||null,hd:b.hire_date,dof:b.day_off||10,id:{dir:oracledb.BIND_OUT,type:oracledb.NUMBER}},o);
  await c.commit();res.json({id:e.outBinds.id[0]})}catch(x){await c.rollback();throw x}finally{await c.close()}}));
app.put('/api/employees/:id',auth(...HR),h(async(req,res)=>{const b=req.body,id=+req.params.id,mg=b.manager_id?+b.manager_id:null;
 if(mg){if(mg===id)return res.status(400).json({error:'เลือกตัวเองเป็นหัวหน้าไม่ได้'});
  let c=mg;for(let i=0;c&&i<20;i++){const[x]=await q('SELECT manager_id FROM employees WHERE employee_id=:i',{i:c});c=x&&x.manager_id;if(c===id)return res.status(400).json({error:'เลือกไม่ได้ เพราะหัวหน้าคนนั้นเป็นลูกทีมของพนักงานคนนี้อยู่'})}}
 await run('UPDATE employees SET first_name=:fn,last_name=:ln,email=:em,phone=:ph,address=:ad,day_off=:dof,manager_id=:mg WHERE employee_id=:id',{fn:b.first_name,ln:b.last_name,em:b.email,ph:b.phone||null,ad:b.address||null,dof:b.day_off||0,mg,id});res.json({ok:1})}));
app.post('/api/employees/:id/resign',auth(...HR),h(async(req,res)=>{
 const i=req.params.id,[e]=await q('SELECT employment_status,account_id FROM employees WHERE employee_id=:i',{i});
 if(!e)return res.sendStatus(404);if(e.employment_status==='resigned')return res.status(400).json({error:'สถานะนี้ถูกบันทึกไว้แล้ว'});
 if((await q("SELECT data FROM reports WHERE employee_id=:i AND report_type='change_request'",{i})).some(r=>JSON.parse(r.data).status==='pending'))return res.status(400).json({error:'พนักงานมีคำขอที่ยังรออนุมัติ กรุณาดำเนินการให้เสร็จก่อน'});
 await run("INSERT INTO resignations(employee_id,effective_date,reason) VALUES(:i,TO_DATE(:d,'YYYY-MM-DD'),:r)",{i,d:req.body.effective_date,r:req.body.reason||null});
 await run("UPDATE employees SET employment_status='resigned' WHERE employee_id=:i",{i});
 await run('UPDATE employees SET manager_id=NULL WHERE manager_id=:i',{i});
 await run("UPDATE accounts SET status='inactive' WHERE account_id=:a",{a:e.account_id});res.json({ok:1})}));
app.get('/api/resignations',auth(...HR),h(async(_,res)=>res.json(await q("SELECT r.resignation_id,e.first_name||' '||e.last_name emp,r.reason,r.request_date,r.effective_date,r.status FROM resignations r JOIN employees e ON e.employee_id=r.employee_id ORDER BY 1 DESC"))));

const reqs=async()=>{const dn=Object.fromEntries((await q('SELECT department_id,department_name FROM departments')).map(x=>[x.department_id,x.department_name])),pn=Object.fromEntries((await q('SELECT position_id,position_name FROM positions')).map(x=>[x.position_id,x.position_name]));
 return(await q("SELECT r.report_id,r.employee_id,r.created_date,r.data,e.first_name||' '||e.last_name emp FROM reports r JOIN employees e ON e.employee_id=r.employee_id WHERE r.report_type='change_request' ORDER BY r.report_id DESC")).map(r=>{const j=JSON.parse(r.data);return{request_id:r.report_id,employee_id:r.employee_id,emp:r.emp,created_date:r.created_date,status:j.status,reason:j.reason,decision_reason:j.decision_reason,old_dept:dn[j.old_department_id],old_pos:pn[j.old_position_id],new_dept:dn[j.new_department_id],new_pos:pn[j.new_position_id],_j:j}})};
app.get('/api/requests',auth(...HR,'manager'),h(async(_,res)=>res.json((await reqs()).map(({_j,...r})=>r))));
app.post('/api/requests',auth(...HR),h(async(req,res)=>{const b=req.body,[e]=await q('SELECT department_id,position_id FROM employees WHERE employee_id=:i',{i:b.employee_id});
 if(!e)return res.sendStatus(404);
 await run("INSERT INTO reports(employee_id,report_type,data) VALUES(:i,'change_request',:d)",{i:b.employee_id,d:JSON.stringify({status:'pending',reason:b.reason||null,old_department_id:e.department_id,old_position_id:e.position_id,new_department_id:+b.department_id,new_position_id:+b.position_id})});res.json({ok:1})}));
app.post('/api/requests/:id/decide',auth('manager'),h(async(req,res)=>{
 const{approve,reason}=req.body,r=(await reqs()).find(x=>x.request_id==req.params.id&&x.status==='pending');
 if(!r)return res.status(404).json({error:'ไม่พบคำขอที่รออนุมัติ'});if(!approve&&!reason)return res.status(400).json({error:'กรุณาระบุเหตุผลที่ไม่อนุมัติ'});
 const j={...r._j,status:approve?'approved':'rejected',decision_reason:reason||null,decided_date:new Date().toISOString().slice(0,10)};
 await run('UPDATE reports SET data=:d WHERE report_id=:i',{d:JSON.stringify(j),i:r.request_id});
 if(approve)await run('UPDATE employees SET department_id=:d,position_id=:p WHERE employee_id=:e',{d:j.new_department_id,p:j.new_position_id,e:r.employee_id});res.json({ok:1})}));

const TYP=['absent','leave','late','ot'],ATQ="SELECT r.report_id record_id,TRUNC(r.created_date) work_date,r.report_type record_type,r.data,e.first_name||' '||e.last_name emp FROM reports r JOIN employees e ON e.employee_id=r.employee_id WHERE r.report_type IN ('absent','leave','late','ot')";
app.get('/api/attendance',auth(...HR),h(async(req,res)=>res.json((await q(ATQ+" AND TRUNC(r.created_date)=TO_DATE(:d,'YYYY-MM-DD') ORDER BY r.report_id DESC",{d:req.query.date})).map(att))));
app.post('/api/attendance',auth(...HR),h(async(req,res)=>{const b=req.body;if(!TYP.includes(b.record_type))return res.status(400).json({error:'ประเภทไม่ถูกต้อง'});
 await run("INSERT INTO reports(employee_id,report_type,created_date,data) VALUES(:e,:t,TO_TIMESTAMP(:d,'YYYY-MM-DD'),:h)",{e:b.employee_id,t:b.record_type,d:b.work_date,h:String(b.record_type==='ot'?+b.ot_hours||0:0)});res.json({ok:1})}));
app.get('/api/my/records',auth(),h(async(req,res)=>{if(!okMonth(req.query.month))return res.status(400).json({error:'เลือกเดือนก่อน'});const[s,e]=span(req.query.month);
 res.json((await q(ATQ+" AND r.employee_id=:i AND TRUNC(r.created_date) BETWEEN TO_DATE(:s,'YYYY-MM-DD') AND TO_DATE(:e,'YYYY-MM-DD') ORDER BY 2",{i:req.u.eid||0,s,e})).map(att))}));

const pay=async(m,half,eid)=>{const[y,mo]=m.split('-').map(Number),last=new Date(y,mo,0).getDate(),s=`${m}-${half===1?'01':'16'}`,e=`${m}-${half===1?'15':P2(last)}`;
 const emps=await q(`SELECT e.employee_id,e.first_name||' '||e.last_name name,p.salary_rate FROM employees e JOIN positions p ON p.position_id=e.position_id WHERE e.employment_status='active'${eid?' AND e.employee_id=:eid':''} ORDER BY 1`,eid?{eid}:{});
 const recs=await q(`SELECT employee_id,report_type,data FROM reports WHERE report_type IN ('ot','absent') AND TRUNC(created_date) BETWEEN TO_DATE(:s,'YYYY-MM-DD') AND TO_DATE(:e,'YYYY-MM-DD')${eid?' AND employee_id=:eid':''}`,eid?{s,e,eid}:{s,e});
 const r2=x=>Math.round(x*100)/100;
 return{period:[s,e],rows:emps.map(x=>{const mine=recs.filter(r=>r.employee_id===x.employee_id),ot=mine.filter(r=>r.report_type==='ot').reduce((a,r)=>a+(+r.data||0),0),absent=mine.filter(r=>r.report_type==='absent').length,base=x.salary_rate/2,otp=r2(ot*x.salary_rate/240*1.5),ded=r2(absent*x.salary_rate/30);return{...x,ot,absent,base,ot_pay:otp,deduct:ded,net:r2(base+otp-ded)}})}};
app.get('/api/payroll',auth(...HR),h(async(req,res)=>{if(!okMonth(req.query.month))return res.status(400).json({error:'เลือกเดือนก่อน'});res.json(await pay(req.query.month,req.query.half==='2'?2:1))}));
app.get('/api/my/payroll',auth(),h(async(req,res)=>{if(!okMonth(req.query.month))return res.status(400).json({error:'เลือกเดือนก่อน'});res.json(await pay(req.query.month,req.query.half==='2'?2:1,req.u.eid||0))}));

app.get('/api/calendar',auth(),h(async(req,res)=>{if(!okMonth(req.query.month))return res.status(400).json({error:'เลือกเดือนก่อน'});const[s,e]=span(req.query.month),all=HR.includes(req.u.role)||req.u.role==='manager',b={s,e};
 if(!all)b.i=req.u.eid||0;
 res.json({all,records:(await q(`SELECT TRUNC(r.created_date) work_date,r.report_type record_type,r.data,e.first_name||' '||e.last_name emp FROM reports r JOIN employees e ON e.employee_id=r.employee_id WHERE r.report_type IN ('absent','leave','late','ot') AND TRUNC(r.created_date) BETWEEN TO_DATE(:s,'YYYY-MM-DD') AND TO_DATE(:e,'YYYY-MM-DD')${all?'':' AND r.employee_id=:i'} ORDER BY 1`,b)).map(att)})}));

app.get('/api/report',auth(...HR,'manager'),h(async(req,res)=>{
 const W="WHERE e.employment_status='active' GROUP BY ";
 const r={byDept:await q(`SELECT d.department_name name,COUNT(*) total FROM employees e JOIN departments d ON d.department_id=e.department_id ${W}d.department_name ORDER BY 1`),
  byPos:await q(`SELECT p.position_name name,COUNT(*) total FROM employees e JOIN positions p ON p.position_id=e.position_id ${W}p.position_name ORDER BY 1`),
  today:await q("SELECT report_type name,COUNT(*) total FROM reports WHERE report_type IN ('absent','leave','late','ot') AND TRUNC(created_date)=TRUNC(SYSDATE) GROUP BY report_type")};
 if(req.query.save&&req.u.eid)await run("INSERT INTO reports(employee_id,report_type,data) VALUES(:e,'headcount',:d)",{e:req.u.eid,d:JSON.stringify(r)});res.json(r)}));

app.post('/api/backup',auth(...HR),h(async(_,res)=>{const d={};
 for(const t of['departments','positions','employees','resignations'])d[t]=await q('SELECT * FROM '+t);d.reports=await q("SELECT report_id,employee_id,report_type,created_date,data FROM reports WHERE report_type<>'photo'");
 d.accounts=await q('SELECT account_id,username,role,status FROM accounts');
 res.json({file:'backup-'+new Date().toISOString().replace(/[:T]/g,'-').slice(0,19)+'.json',data:d})}));

app.get('/api/org',auth(...HR),h(async(_,res)=>res.json({
 departments:await q("SELECT d.department_id,d.department_name,d.description,COUNT(e.employee_id) total FROM departments d LEFT JOIN employees e ON e.department_id=d.department_id AND e.employment_status<>'resigned' GROUP BY d.department_id,d.department_name,d.description ORDER BY 2"),
 positions:await q("SELECT p.position_id,p.position_name,p.salary_rate,COUNT(e.employee_id) total FROM positions p LEFT JOIN employees e ON e.position_id=p.position_id AND e.employment_status<>'resigned' GROUP BY p.position_id,p.position_name,p.salary_rate ORDER BY 2")})));
for(const[t,[id,nm,vc]]of Object.entries({departments:['department_id','department_name','description'],positions:['position_id','position_name','salary_rate']})){
 const bad=b=>!b.name||(t==='positions'&&!(b.value!==''&&b.value!=null&&+b.value>=0)),val=b=>t==='positions'?+b.value:b.value||null;
 app.post('/api/'+t,auth(...HR),h(async(req,res)=>{const b=req.body;if(bad(b))return res.status(400).json({error:'กรอกข้อมูลให้ครบและถูกต้อง'});
  await run(`INSERT INTO ${t}(${nm},${vc}) VALUES(:n,:v)`,{n:b.name,v:val(b)});res.json({ok:1})}));
 app.put('/api/'+t+'/:id',auth(...HR),h(async(req,res)=>{const b=req.body;if(bad(b))return res.status(400).json({error:'กรอกข้อมูลให้ครบและถูกต้อง'});
  await run(`UPDATE ${t} SET ${nm}=:n,${vc}=:v WHERE ${id}=:i`,{n:b.name,v:val(b),i:req.params.id});res.json({ok:1})}));
 app.delete('/api/'+t+'/:id',auth(...HR),h(async(req,res)=>{await run(`DELETE FROM ${t} WHERE ${id}=:i`,{i:req.params.id});res.json({ok:1})}));
}

app.post('/api/photo/:id',auth(),h(async(req,res)=>{const id=+req.params.id,im=String(req.body.image||''),pre='data:image/jpeg;base64,';
 if(!Number.isInteger(id)||!(HR.includes(req.u.role)||req.u.eid===id))return res.status(403).json({error:'ไม่มีสิทธิ์เปลี่ยนรูปนี้'});
 if(!im.startsWith(pre)||im.length>30000)return res.status(400).json({error:'ไฟล์รูปไม่ถูกต้องหรือใหญ่เกินไป'});
 await run("DELETE FROM reports WHERE employee_id=:i AND report_type='photo'",{i:id});
 await run("INSERT INTO reports(employee_id,report_type,data) VALUES(:i,'photo',:p)",{i:id,p:im.slice(pre.length)});res.json({ok:1})}));
app.get('/api/photo/:id',auth(),h(async(req,res)=>{const id=+req.params.id;if(!Number.isInteger(id)||(req.u.role==='employee'&&req.u.eid!==id))return res.sendStatus(403);
 const[r]=await q("SELECT data FROM reports WHERE employee_id=:i AND report_type='photo'",{i:id});if(!r)return res.sendStatus(404);
 res.set({'Content-Type':'image/jpeg','Cache-Control':'private, max-age=86400'}).send(Buffer.from(r.data,'base64'))}));

if(!process.env.VERCEL)app.listen(3000,()=>console.log('http://localhost:3000'));
module.exports=app;
