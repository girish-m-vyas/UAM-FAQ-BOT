require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const isProd = process.env.NODE_ENV === 'production';
if (isProd) app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '25mb' }));
app.use(session({ name:'uam.sid', secret:process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'), resave:false, saveUninitialized:false, cookie:{httpOnly:true,sameSite:'lax',secure:isProd,maxAge:8*60*60*1000} }));
app.use(express.static(path.join(__dirname, 'public')));

const loginLimiter=rateLimit({windowMs:15*60*1000,max:10,standardHeaders:true,legacyHeaders:false});
const chatLimiter=rateLimit({windowMs:60*1000,max:30,standardHeaders:true,legacyHeaders:false});
const DATA_DIR=process.env.DATA_DIR || path.join(__dirname,'data');
const USERS_FILE=path.join(DATA_DIR,'users.json');
const APP_DATA_FILE=path.join(DATA_DIR,'app-data.json');
const APP_DATA_KEYS=new Set([
  'uam:sops','uam:acm:cols','uam:acm:rows','uam:acm:ts',
  'uam:users:cols','uam:users:rows','uam:users:ts',
  'uam:monthly','uam:monthly:ts','uam:audit:evidence','uam_handover_apps'
]);
fs.mkdirSync(DATA_DIR,{recursive:true});
function loadUsers(){try{return JSON.parse(fs.readFileSync(USERS_FILE,'utf8'));}catch{return[];}}
function saveUsers(users){fs.writeFileSync(USERS_FILE,JSON.stringify(users,null,2));}
function loadAppData(){try{const d=JSON.parse(fs.readFileSync(APP_DATA_FILE,'utf8'));return d&&typeof d==='object'&&!Array.isArray(d)?d:{};}catch{return{};}}
function saveAppData(data){const tmp=APP_DATA_FILE+'.tmp';fs.writeFileSync(tmp,JSON.stringify(data,null,2));fs.renameSync(tmp,APP_DATA_FILE);}
function validAppDataKey(key){return APP_DATA_KEYS.has(String(key||''));}
function canReadAppData(role,key){
  if(role==='admin')return true;
  if(role==='application')return ['uam:sops','uam:acm:cols','uam:acm:rows','uam:acm:ts','uam_handover_apps'].includes(key);
  if(role==='audit')return ['uam:audit:evidence','uam:acm:cols','uam:acm:rows','uam:acm:ts'].includes(key);
  if(role==='viewer')return ['uam:sops','uam:acm:cols','uam:acm:rows','uam:acm:ts','uam:monthly','uam:monthly:ts'].includes(key);
  return false;
}
function canWriteAppData(role,key){
  if(role==='admin')return true;
  if(role==='application')return ['uam:sops','uam:acm:cols','uam:acm:rows','uam:acm:ts','uam_handover_apps'].includes(key);
  return false;
}
function storedFaqData(){
  const d=loadAppData();
  const monthly=Array.isArray(d['uam:monthly'])?d['uam:monthly']:[];
  const rows=Array.isArray(d['uam:users:rows'])?d['uam:users:rows']:[];
  const normType=v=>{const t=String(v||'').trim().toLowerCase();if(t.startsWith('join'))return'Joiner';if(t.startsWith('mov')||t.includes('transfer'))return'Mover';if(t.startsWith('leav')||t.includes('exit')||t.includes('offboard'))return'Leaver';return String(v||'').trim();};
  const typeOf=r=>normType(r?.['Event Type']||r?.Type||r?.['User Type']||'');
  return {monthly,jml:{total:rows.length,joiners:rows.filter(r=>typeOf(r)==='Joiner').length,movers:rows.filter(r=>typeOf(r)==='Mover').length,leavers:rows.filter(r=>typeOf(r)==='Leaver').length},acmCount:Array.isArray(d['uam:acm:rows'])?d['uam:acm:rows'].length:0,sopCount:Array.isArray(d['uam:sops'])?d['uam:sops'].length:0};
}

function hashPassword(password,salt=crypto.randomBytes(16).toString('hex')){const hash=crypto.scryptSync(String(password),salt,64).toString('hex');return `${salt}:${hash}`;}
function verifyPassword(password,stored){try{const [salt,hash]=stored.split(':');const actual=crypto.scryptSync(String(password),salt,64);const expected=Buffer.from(hash,'hex');return actual.length===expected.length&&crypto.timingSafeEqual(actual,expected);}catch{return false;}}
function adminConfig(){return {id:'env-admin',username:process.env.ADMIN_USERNAME||'admin',password:process.env.ADMIN_PASSWORD||'',name:process.env.ADMIN_NAME||'UAM Admin',role:'admin',department:'IAM Team',email:process.env.ADMIN_EMAIL||'',empCode:process.env.ADMIN_EMP_CODE||'',grade:process.env.ADMIN_GRADE||'',designation:process.env.ADMIN_DESIGNATION||'',source:'env'};}
function publicUser(u){return {id:u.id,name:u.name,username:u.username,role:u.role,department:u.department||'',email:u.email||'',empCode:u.empCode||'',grade:u.grade||'',designation:u.designation||'',manager:u.manager||'',joiningDate:u.joiningDate||'',status:u.status||((u.active===false)?'Inactive':'Active'),active:u.active!==false,source:u.source||'local',createdAt:u.createdAt||null,updatedAt:u.updatedAt||null};}
function roleLabel(role){return role==='admin'?'Admin':role==='application'?'Application Team':role==='audit'?'Audit Team':'Viewer';}
function adminDomainEmail(value,username){
  const raw=String(value||'').trim().toLowerCase();
  const fallback=String(username||'user').trim().toLowerCase();
  let local=(raw.includes('@')?raw.split('@')[0]:raw)||fallback;
  local=local.replace(/[^a-z0-9._-]+/g,'.').replace(/^\.+|\.+$/g,'')||fallback.replace(/[^a-z0-9._-]+/g,'.')||'user';
  return `${local}@admin.com`;
}
function lifecycleEvent(type,u,previousDepartment=''){
  const t=String(type||'').trim()||'Update';
  let remarks='User lifecycle updated through User Management.';
  if(t==='Mover') remarks=`Department changed from ${previousDepartment||'previous department'} to ${u.department||'new department'} through User Management.`;
  else if(t==='Joiner') remarks='User created/activated through User Management.';
  else if(t==='Leaver') remarks='User deactivated/deleted through User Management.';
  return {type:t,name:u.name||'',username:u.username||'',email:adminDomainEmail(u.email,u.username),empCode:u.empCode||'',grade:u.grade||'',designation:u.designation||'',manager:u.manager||'',department:u.department||'',previousDepartment,applications:'UAM Portal',accessRole:roleLabel(u.role),remarks,effectiveDate:new Date().toISOString()};
}
function requireAuthenticated(req,res,next){if(!req.session?.user)return res.status(401).json({error:'Authentication required.'});next();}
function requireAdmin(req,res,next){if(req.session?.user?.role!=='admin')return res.status(403).json({error:'Admin access required.'});next();}
function normalizeRole(role){return role==='admin'?'admin':role==='application'?'application':role==='audit'?'audit':'viewer';}
function getLiveUserStats(){
  const all=[publicUser(adminConfig()),...loadUsers().map(publicUser)];
  const isInactive=u=>u.active===false||String(u.status||'').trim().toLowerCase()==='inactive';
  const active=all.filter(u=>!isInactive(u));
  const inactive=all.filter(isInactive);
  const roleCount=r=>all.filter(u=>u.role===r).length;
  const departments=[...new Set(all.map(u=>String(u.department||'').trim()).filter(Boolean))];
  return {all,isInactive,active,inactive,departments,roles:{admin:roleCount('admin'),viewer:roleCount('viewer'),application:roleCount('application'),audit:roleCount('audit')}};
}
function normalizeClientUserStats(raw){
  if(!raw || typeof raw!=='object') return null;
  const n=v=>Number.isFinite(Number(v))?Math.max(0,Math.min(100000,Math.trunc(Number(v)))):null;
  const total=n(raw.total), active=n(raw.active), inactive=n(raw.inactive);
  if(total===null||active===null||inactive===null||active+inactive!==total)return null;
  const roles=raw.roles&&typeof raw.roles==='object'?{
    admin:n(raw.roles.admin)??0,viewer:n(raw.roles.viewer)??0,application:n(raw.roles.application)??0,audit:n(raw.roles.audit)??0
  }:{admin:0,viewer:0,application:0,audit:0};
  return {total,active,inactive,departments:n(raw.departments)??0,roles,source:String(raw.source||'client-ui').slice(0,40)};
}
function directLiveUserAnswer(messages,role,clientStats=null){
  const last=[...messages].reverse().find(m=>m&&m.role==='user');
  const q=String(last?.content||'').toLowerCase().replace(/[^a-z0-9 ]+/g,' ');
  if(!q)return null;
  const asksCount=/\b(how many|count|number of|total)\b/.test(q);
  if(!asksCount)return null;
  const userIntent=/\b(users?|accounts?|employees?|identities|portal user|portal users)\b/.test(q);
  const roleIntent=/\badmins?|viewers?|application team|audit team\b/.test(q);
  if(!userIntent&&!roleIntent)return null;
  const server=getLiveUserStats();
  const s=clientStats||{total:server.all.length,active:server.active.length,inactive:server.inactive.length,departments:server.departments.length,roles:server.roles};
  if(/\binactive\b/.test(q))return `There are **${s.inactive} inactive users** in the current User Management directory.`;
  if(/\bactive\b/.test(q)&&!/inactive/.test(q))return `There are **${s.active} active users** in the current User Management directory.`;
  if(/\badmins?\b/.test(q))return `There are **${s.roles.admin} Admin users** in the current User Management directory.`;
  if(/\bviewers?\b/.test(q))return `There are **${s.roles.viewer} Viewer users** in the current User Management directory.`;
  if(/application team|application users?/.test(q))return `There are **${s.roles.application} Application Team users** in the current User Management directory.`;
  if(/audit team|audit users?/.test(q))return `There are **${s.roles.audit} Audit Team users** in the current User Management directory.`;
  if(/departments?/.test(q))return `There are **${s.departments} departments** represented in the current User Management directory.`;
  if(/\busers?|accounts?|employees?|identities\b/.test(q))return `There are **${s.total} total users** in the current User Management directory: **${s.active} active** and **${s.inactive} inactive**.`;
  return null;
}
function normalizeFaqData(raw){
  if(!raw||typeof raw!=='object')return {monthly:[],jml:null,acmCount:0,sopCount:0};
  const n=v=>Number.isFinite(Number(v))?Number(v):0;
  const kv=a=>Array.isArray(a)?a.slice(0,100).map(x=>({l:String(x?.l||'').slice(0,120),v:n(x?.v)})).filter(x=>x.l):[];
  const monthly=Array.isArray(raw.monthly)?raw.monthly.slice(0,120).map(m=>({month:String(m?.month||'').slice(0,20),year:Math.trunc(n(m?.year)),created:n(m?.created),closed:n(m?.closed),pending:n(m?.pending),slaBreached:n(m?.slaBreached),cats:kv(m?.cats),appCreated:kv(m?.appCreated),appClosed:kv(m?.appClosed),apps:kv(m?.apps)})).filter(m=>m.month&&m.year):[];
  const j=raw.jml&&typeof raw.jml==='object'?{total:n(raw.jml.total),joiners:n(raw.jml.joiners),movers:n(raw.jml.movers),leavers:n(raw.jml.leavers)}:null;
  return {monthly,jml:j,acmCount:Math.max(0,Math.trunc(n(raw.acmCount))),sopCount:Math.max(0,Math.trunc(n(raw.sopCount)))};
}
function findMonthInQuery(q,months){
  const names=['january','february','march','april','may','june','july','august','september','october','november','december'];
  const aliases={jan:'january',feb:'february',mar:'march',apr:'april',jun:'june',jul:'july',aug:'august',sep:'september',sept:'september',oct:'october',nov:'november',dec:'december'};
  let target='';for(const n of names)if(q.includes(n)){target=n;break;}if(!target)for(const [a,n] of Object.entries(aliases))if(new RegExp(`\b${a}\b`).test(q)){target=n;break;}
  const ym=q.match(/\b(20\d{2})\b/);const year=ym?Number(ym[1]):null;
  if(target){const hits=months.filter(m=>m.month.toLowerCase()===target&&(!year||m.year===year));return hits.length?hits[hits.length-1]:null;}
  if(year){const hits=months.filter(m=>m.year===year);return hits.length===1?hits[0]:null;}
  return months.length===1?months[0]:null;
}
function fmtKv(a,suffix=''){return (a||[]).map(x=>`${x.l}: ${x.v}${suffix}`).join(', ');}
function directOperationalAnswer(messages,faq){
  const last=[...messages].reverse().find(m=>m&&m.role==='user');const raw=String(last?.content||'');const q=raw.toLowerCase().replace(/[^a-z0-9% ]+/g,' ');if(!q)return null;
  const m=findMonthInQuery(q,faq.monthly||[]);
  if(m&&/(request|monthly|closed|created|pending|sla|category|closure|application|app)/.test(q)){
    const label=`${m.month} ${m.year}`;
    if(/category/.test(q))return m.cats.length?`Category breakdown for **${label}**: ${fmtKv(m.cats)}.`:`No category breakdown is loaded for ${label}.`;
    if(/app(lication)?\s+created|created\s+request.*app|app.*created/.test(q))return m.appCreated.length?`Application-created requests for **${label}**: ${fmtKv(m.appCreated)}.`:`No application-created request breakdown is loaded for ${label}.`;
    if(/app(lication)?\s+closed|closed\s+request.*app|app.*closed/.test(q))return m.appClosed.length?`Application-closed requests for **${label}**: ${fmtKv(m.appClosed)}.`:`No application-closed request breakdown is loaded for ${label}.`;
    if(/closure\s*%|closure percentage|app.*closure/.test(q))return m.apps.length?`Application closure % for **${label}**: ${fmtKv(m.apps,'%')}.`:`No application closure % is loaded for ${label}.`;
    if(/sla/.test(q)&&/(breach|breached)/.test(q))return `There were **${m.slaBreached} SLA-breached requests** in **${label}**.`;
    if(/pending/.test(q))return `There were **${m.pending} pending requests** in **${label}**.`;
    if(/closed|closure/.test(q))return `A total of **${m.closed} requests were closed** in **${label}**.`;
    if(/created|raised|received/.test(q))return `A total of **${m.created} requests were created** in **${label}**.`;
    if(/total.*request|request.*total/.test(q))return `For **${label}**: **${m.created} created**, **${m.closed} closed**, **${m.pending} pending**, and **${m.slaBreached} SLA breached**.`;
  }
  if(faq.jml&&/\b(how many|count|number of|total)\b/.test(q)){
    if(/joiners?/.test(q))return `There are **${faq.jml.joiners} Joiner records** in the current JML dataset.`;
    if(/movers?/.test(q))return `There are **${faq.jml.movers} Mover records** in the current JML dataset.`;
    if(/leavers?/.test(q))return `There are **${faq.jml.leavers} Leaver records** in the current JML dataset.`;
    if(/jml|lifecycle/.test(q))return `There are **${faq.jml.total} JML records**: **${faq.jml.joiners} Joiners**, **${faq.jml.movers} Movers**, and **${faq.jml.leavers} Leavers**.`;
  }
  if(/\b(how many|count|number of|total)\b/.test(q)&&/acm|applications?/.test(q)&&!m)return `There are **${faq.acmCount} ACM application records** currently loaded.`;
  if(/\b(how many|count|number of|total)\b/.test(q)&&/sops?|standard operating/.test(q))return `There are **${faq.sopCount} SOP documents** currently loaded.`;
  return null;
}
function operationalContext(faq){
  const lines=['=== STRUCTURED OPERATIONAL DATA (AUTHORITATIVE FOR MONTHLY/JML/ACM/SOP COUNTS) ==='];
  for(const m of faq.monthly||[]){lines.push(`${m.month} ${m.year}: Created=${m.created}; Closed=${m.closed}; Pending=${m.pending}; SLA Breached=${m.slaBreached}; Categories=[${fmtKv(m.cats)}]; App Created=[${fmtKv(m.appCreated)}]; App Closed=[${fmtKv(m.appClosed)}]; App Closure %=[${fmtKv(m.apps,'%')}]`);}
  if(faq.jml)lines.push(`JML totals: Total=${faq.jml.total}; Joiners=${faq.jml.joiners}; Movers=${faq.jml.movers}; Leavers=${faq.jml.leavers}`);
  lines.push(`ACM records=${faq.acmCount}; SOP documents=${faq.sopCount}`);return lines.join('\n');
}
function liveUserDirectoryContext(role){
  const all=[publicUser(adminConfig()),...loadUsers().map(publicUser)];
  const isInactive=u=>u.active===false||String(u.status||'').trim().toLowerCase()==='inactive';
  const active=all.filter(u=>!isInactive(u));
  const inactive=all.filter(isInactive);
  const roleCount=r=>all.filter(u=>u.role===r).length;
  const departments=[...new Set(all.map(u=>String(u.department||'').trim()).filter(Boolean))];
  const deptCounts={};for(const u of all){const d=String(u.department||'').trim()||'Unspecified';deptCounts[d]=(deptCounts[d]||0)+1;}
  const summary=[
    '=== LIVE USER MANAGEMENT DIRECTORY (SERVER-SIDE, AUTHORITATIVE) ===',
    `Total portal users: ${all.length}`,
    `Active users: ${active.length}`,
    `Inactive users: ${inactive.length}`,
    `Admins: ${roleCount('admin')}`,
    `Viewers: ${roleCount('viewer')}`,
    `Application Team users: ${roleCount('application')}`,
    `Audit Team users: ${roleCount('audit')}`,
    `Departments: ${departments.length}`,
    'Department counts: '+Object.entries(deptCounts).map(([k,v])=>`${k}=${v}`).join(', '),
    'IMPORTANT: For questions asking the current number of active, inactive, total, admin, viewer, application-team, audit-team, or department users, use these exact figures. This block is newer and more authoritative than uploaded JML snapshots.'
  ];
  if(role==='admin'){
    summary.push('Current user directory:');
    for(const u of all.slice(0,250)){summary.push(`- ${u.name||u.username} | Emp Code: ${u.empCode||'—'} | Username: ${u.username||'—'} | Department: ${u.department||'—'} | Role: ${u.role||'viewer'} | Status: ${isInactive(u)?'Inactive':'Active'} | Designation: ${u.designation||'—'}`);}
  }
  return summary.join('\n');
}

app.get('/api/session',(req,res)=>res.json({authenticated:!!req.session?.user,user:req.session?.user||null}));
app.post('/api/login',loginLimiter,(req,res)=>{
  const username=String(req.body?.username||'').trim().toLowerCase(), password=String(req.body?.password||'');
  const admin=adminConfig(); let found=null;
  if(admin.password && username===admin.username.toLowerCase() && password===admin.password) found=admin;
  if(!found){const u=loadUsers().find(x=>String(x.username).toLowerCase()===username&&x.active!==false);if(u&&verifyPassword(password,u.passwordHash))found=u;}
  if(!found)return res.status(401).json({error:'Invalid username or password.'});
  req.session.regenerate(err=>{if(err)return res.status(500).json({error:'Could not create session.'});req.session.user=publicUser(found);res.json({ok:true,user:req.session.user});});
});
app.post('/api/logout',(req,res)=>req.session.destroy(()=>{res.clearCookie('uam.sid');res.json({ok:true});}));

app.get('/api/users',requireAdmin,(req,res)=>{const admin=adminConfig();res.json({users:[publicUser(admin),...loadUsers().map(publicUser)]});});
app.post('/api/users',requireAdmin,(req,res)=>{
  const name=String(req.body?.name||'').trim(), username=String(req.body?.username||'').trim(), password=String(req.body?.password||''), role=normalizeRole(req.body?.role), department=String(req.body?.department||'').trim(), email=adminDomainEmail(req.body?.email,username), empCode=String(req.body?.empCode||'').trim(), grade=String(req.body?.grade||'').trim(), designation=String(req.body?.designation||'').trim(), manager=String(req.body?.manager||'').trim(), joiningDate=String(req.body?.joiningDate||'').trim(), status=String(req.body?.status||'Active').trim();
  if(!name||!/^[a-zA-Z0-9._-]{3,50}$/.test(username)||password.length<8||!email||!empCode||!department)return res.status(400).json({error:'Name, valid username, password (8+), email, emp code and department are required.'});
  const users=loadUsers(); if(username.toLowerCase()===adminConfig().username.toLowerCase()||users.some(u=>u.username.toLowerCase()===username.toLowerCase()))return res.status(409).json({error:'Username already exists.'});
  if(users.some(u=>String(u.empCode||'').toLowerCase()===empCode.toLowerCase()))return res.status(409).json({error:'Emp code already exists.'});
  const user={id:crypto.randomUUID(),name,username,role,department,email,empCode,grade,designation,manager,joiningDate,status,passwordHash:hashPassword(password),active:status.toLowerCase()!=='inactive',createdAt:new Date().toISOString()}; users.push(user);saveUsers(users);res.status(201).json({ok:true,user:publicUser(user),lifecycleEvent:lifecycleEvent('Joiner',user)});
});
app.post('/api/users/bulk',requireAdmin,(req,res)=>{
  const rows=Array.isArray(req.body?.users)?req.body.users:[]; if(!rows.length)return res.status(400).json({error:'No users supplied.'}); if(rows.length>500)return res.status(400).json({error:'Maximum 500 users per bulk upload.'});
  const users=loadUsers(), errors=[], created=[], lifecycleEvents=[]; const reserved=new Set([adminConfig().username.toLowerCase(),...users.map(u=>u.username.toLowerCase())]); const empCodes=new Set(users.map(u=>String(u.empCode||'').toLowerCase()).filter(Boolean));
  rows.forEach((r,i)=>{const name=String(r?.name||'').trim(),username=String(r?.username||'').trim(),password=String(r?.password||''),role=normalizeRole(String(r?.role||'viewer').toLowerCase()),department=String(r?.department||'').trim(),email=adminDomainEmail(r?.email,username),empCode=String(r?.empCode||'').trim(),grade=String(r?.grade||'').trim(),designation=String(r?.designation||'').trim(),manager=String(r?.manager||'').trim(),joiningDate=String(r?.joiningDate||'').trim(),status=String(r?.status||'Active').trim();let error='';if(!name)error='Name is required.';else if(!/^[a-zA-Z0-9._-]{3,50}$/.test(username))error='Invalid username.';else if(password.length<8)error='Password must be at least 8 characters.';else if(!email||!empCode||!department)error='Email, emp code and department are required.';else if(reserved.has(username.toLowerCase()))error='Username already exists.';else if(empCodes.has(empCode.toLowerCase()))error='Emp code already exists.';if(error){errors.push({row:i+2,username,error});return;}const user={id:crypto.randomUUID(),name,username,role,department,email,empCode,grade,designation,manager,joiningDate,status,passwordHash:hashPassword(password),active:status.toLowerCase()!=='inactive',createdAt:new Date().toISOString()};users.push(user);created.push(publicUser(user));lifecycleEvents.push(lifecycleEvent('Joiner',user));reserved.add(username.toLowerCase());empCodes.add(empCode.toLowerCase());});
  if(created.length)saveUsers(users); res.status(created.length?201:400).json({ok:created.length>0,created:created.length,failed:errors.length,users:created,errors,lifecycleEvents});
});
app.patch('/api/users/:id',requireAdmin,(req,res)=>{
  const users=loadUsers(),idx=users.findIndex(u=>u.id===req.params.id);
  if(idx<0)return res.status(404).json({error:'User not found.'});
  const old=users[idx], previousDepartment=old.department||'', wasActive=old.active!==false&&String(old.status||'Active').toLowerCase()!=='inactive';
  const updated={...old,
    name:String(req.body?.name||old.name).trim(),email:adminDomainEmail(req.body?.email||old.email,old.username),empCode:String(req.body?.empCode||old.empCode||'').trim(),
    grade:String(req.body?.grade??old.grade??'').trim(),designation:String(req.body?.designation??old.designation??'').trim(),manager:String(req.body?.manager??old.manager??'').trim(),
    joiningDate:String(req.body?.joiningDate??old.joiningDate??'').trim(),status:String(req.body?.status||old.status||'Active').trim(),department:String(req.body?.department||old.department||'').trim(),
    role:normalizeRole(req.body?.role),source:'portal-edit',updatedAt:new Date().toISOString()
  };
  updated.active=updated.status.toLowerCase()!=='inactive';
  if(!updated.name||!updated.email||!updated.empCode||!updated.department)return res.status(400).json({error:'Name, email, emp code and department are required.'});
  if(users.some((u,i)=>i!==idx&&String(u.empCode||'').toLowerCase()===updated.empCode.toLowerCase()))return res.status(409).json({error:'Emp code already exists.'});
  if(String(req.body?.password||'').length){if(String(req.body.password).length<8)return res.status(400).json({error:'Password must be at least 8 characters.'});updated.passwordHash=hashPassword(req.body.password);}
  users[idx]=updated;saveUsers(users);
  const moved=previousDepartment.trim().toLowerCase()!==updated.department.trim().toLowerCase();
  const nowActive=updated.active!==false;
  let evt=null;
  if(wasActive&&!nowActive)evt=lifecycleEvent('Leaver',updated,previousDepartment);
  else if(!wasActive&&nowActive)evt=lifecycleEvent('Joiner',updated,previousDepartment);
  else if(moved)evt=lifecycleEvent('Mover',updated,previousDepartment);
  res.json({ok:true,user:publicUser(updated),lifecycleEvent:evt});
});
app.delete('/api/users/:id',requireAdmin,(req,res)=>{const users=loadUsers(),found=users.find(u=>u.id===req.params.id);if(!found)return res.status(404).json({error:'User not found.'});saveUsers(users.filter(u=>u.id!==req.params.id));res.json({ok:true,lifecycleEvent:lifecycleEvent('Leaver',found)});});


app.post('/api/users/import-jml',requireAdmin,(req,res)=>{
  const rows=Array.isArray(req.body?.rows)?req.body.rows:[];if(!rows.length)return res.status(400).json({error:'No JML rows supplied.'});if(rows.length>1000)return res.status(400).json({error:'Maximum 1000 JML rows per import.'});
  const users=loadUsers();let created=0,updated=0,deactivated=0,skipped=0;
  const clean=v=>String(v||'').trim();const slug=v=>clean(v).toLowerCase().replace(/[^a-z0-9._-]+/g,'.').replace(/^\.+|\.+$/g,'').slice(0,45);
  for(const r of rows){
    const empCode=clean(r['Employee ID']||r['Emp Code']||r['Employee Code']);const name=clean(r['Employee Name']||r.Name);let username=clean(r['Portal Username']||r.Username);let email=clean(r['Email ID']||r.Email);const department=clean(r.Department);const grade=clean(r.Grade);const designation=clean(r.Designation);const manager=clean(r.Manager);const joiningDate=clean(r['Effective Date']);const type=clean(r['Event Type']||r.Type).toLowerCase();
    if(!empCode&&!name&&!username){skipped++;continue;}
    if(!username)username=slug((email.split('@')[0]||name||empCode))||('emp.'+crypto.randomBytes(3).toString('hex'));email=adminDomainEmail(email,username);
    let idx=users.findIndex(u=>(empCode&&clean(u.empCode).toLowerCase()===empCode.toLowerCase())||(email&&clean(u.email).toLowerCase()===email.toLowerCase())||(username&&clean(u.username).toLowerCase()===username.toLowerCase()));
    if(type.startsWith('leav')||type.includes('exit')||type.includes('offboard')){
      if(idx>=0){users[idx]={...users[idx],name:name||users[idx].name,email,empCode:empCode||users[idx].empCode,department:department||users[idx].department,grade:grade||users[idx].grade,designation:designation||users[idx].designation,manager:manager||users[idx].manager,status:'Inactive',active:false,source:users[idx].source||'jml-import',updatedAt:new Date().toISOString()};deactivated++;}
      else{let base=username,n=1;while(users.some(u=>clean(u.username).toLowerCase()===username.toLowerCase())||username===adminConfig().username.toLowerCase())username=`${base}.${n++}`;email=adminDomainEmail(email,username);users.push({id:crypto.randomUUID(),name:name||username,username,role:'viewer',department,email,empCode,grade,designation,manager,joiningDate,status:'Inactive',passwordHash:hashPassword(crypto.randomBytes(32).toString('hex')),active:false,source:'jml-import',createdAt:new Date().toISOString()});deactivated++;}continue;
    }
    if(idx>=0){users[idx]={...users[idx],name:name||users[idx].name,email,empCode:empCode||users[idx].empCode,department:department||users[idx].department,grade:grade||users[idx].grade,designation:designation||users[idx].designation,manager:manager||users[idx].manager,joiningDate:users[idx].joiningDate||joiningDate,status:'Active',active:true,updatedAt:new Date().toISOString()};updated++;}
    else{let base=username,n=1;while(users.some(u=>clean(u.username).toLowerCase()===username.toLowerCase())||username===adminConfig().username.toLowerCase())username=`${base}.${n++}`;email=adminDomainEmail(email,username);users.push({id:crypto.randomUUID(),name:name||username,username,role:'viewer',department,email,empCode,grade,designation,manager,joiningDate,status:'Active',passwordHash:hashPassword(crypto.randomBytes(32).toString('hex')),active:true,source:'jml-import',createdAt:new Date().toISOString()});created++;}
  }
  saveUsers(users);res.json({ok:true,created,updated,deactivated,skipped,total:users.length});
});


app.get('/api/app-data/:key',requireAuthenticated,(req,res)=>{
  const key=decodeURIComponent(req.params.key||'');
  if(!validAppDataKey(key))return res.status(400).json({error:'Unsupported data key.'});
  const role=req.session.user.role;
  if(!canReadAppData(role,key))return res.status(403).json({error:'Access denied for this dataset.'});
  const data=loadAppData();
  res.json({ok:true,exists:Object.prototype.hasOwnProperty.call(data,key),value:data[key]??null});
});
app.put('/api/app-data/:key',requireAuthenticated,(req,res)=>{
  const key=decodeURIComponent(req.params.key||'');
  if(!validAppDataKey(key))return res.status(400).json({error:'Unsupported data key.'});
  const role=req.session.user.role;
  if(!canWriteAppData(role,key))return res.status(403).json({error:'Write access denied for this dataset.'});
  const data=loadAppData();data[key]=req.body?.value??null;saveAppData(data);
  res.json({ok:true,key});
});
app.delete('/api/app-data/:key',requireAuthenticated,(req,res)=>{
  const key=decodeURIComponent(req.params.key||'');
  if(!validAppDataKey(key))return res.status(400).json({error:'Unsupported data key.'});
  const role=req.session.user.role;
  if(!canWriteAppData(role,key))return res.status(403).json({error:'Delete access denied for this dataset.'});
  const data=loadAppData();delete data[key];saveAppData(data);res.json({ok:true,key});
});

app.post('/api/chat',chatLimiter,async(req,res)=>{
  const {system,messages,max_tokens=1000,live_user_stats,faq_data}=req.body||{};if(!Array.isArray(messages)||!messages.length)return res.status(400).json({error:'A message is required.'});
  const role=req.session?.user?.role||'public';
  const clientStats=normalizeClientUserStats(live_user_stats);
  const clientFaq=normalizeFaqData(faq_data);
  const persistedFaq=normalizeFaqData(storedFaqData());
  const faq={
    monthly:clientFaq.monthly.length?clientFaq.monthly:persistedFaq.monthly,
    jml:(clientFaq.jml&&clientFaq.jml.total)?clientFaq.jml:persistedFaq.jml,
    acmCount:clientFaq.acmCount||persistedFaq.acmCount,
    sopCount:clientFaq.sopCount||persistedFaq.sopCount
  };
  const operationalAnswer=directOperationalAnswer(messages,faq);
  if(operationalAnswer)return res.json({choices:[{message:{role:'assistant',content:operationalAnswer}}],source:'structured-operational-data'});
  const directAnswer=directLiveUserAnswer(messages,role,clientStats);
  if(directAnswer)return res.json({choices:[{message:{role:'assistant',content:directAnswer}}],source:clientStats?'ui-user-directory':'server-user-directory'});
  const apiKey=process.env.GROQ_API_KEY;if(!apiKey)return res.status(503).json({error:'Groq is not configured. Set GROQ_API_KEY in .env.'});
  const serverStats=getLiveUserStats();
  const aggregate=clientStats||{total:serverStats.all.length,active:serverStats.active.length,inactive:serverStats.inactive.length,departments:serverStats.departments.length,roles:serverStats.roles};
  const aggregateCtx=`=== CURRENT USER MANAGEMENT COUNTS ===\nTotal users: ${aggregate.total}\nActive users: ${aggregate.active}\nInactive users: ${aggregate.inactive}\nAdmins: ${aggregate.roles.admin}\nViewers: ${aggregate.roles.viewer}\nApplication Team users: ${aggregate.roles.application}\nAudit Team users: ${aggregate.roles.audit}\nDepartments: ${aggregate.departments}`;
  const liveUsers=role==='admin'?liveUserDirectoryContext(role):aggregateCtx;
  const opsCtx=operationalContext(faq);
  const publicBase=`You are UAM-GPT, the RBL Bank User Access Management FAQ assistant. Give concise, helpful UAM guidance. You may use the aggregate User Management counts supplied below. Do not claim access to detailed employee records when the requester is not authenticated.`;
  const clientSystem=role==='public'?publicBase:String(system||'').slice(0,24000);
  const mergedSystem=`${clientSystem}\n\n${liveUsers}\n\n${opsCtx}\n\nResponse rule: For current portal-user counts/status, use the CURRENT USER MANAGEMENT COUNTS or LIVE USER MANAGEMENT DIRECTORY above as authoritative. Never say those counts are unavailable when they are present.`;
  const groqMessages=[{role:'system',content:mergedSystem.slice(0,30000)}];for(const m of messages.slice(-12)){if(m&&['user','assistant','system'].includes(m.role))groqMessages.push({role:m.role,content:String(m.content||'').slice(0,30000)});}
  try{const response=await fetch('https://api.groq.com/openai/v1/chat/completions',{method:'POST',headers:{'Content-Type':'application/json','Authorization':`Bearer ${apiKey}`},body:JSON.stringify({model:process.env.GROQ_MODEL||'openai/gpt-oss-120b',messages:groqMessages,max_completion_tokens:Math.min(Number(max_tokens)||1000,2000),temperature:.3})});const data=await response.json().catch(()=>({}));if(!response.ok)return res.status(response.status).json({error:data?.error?.message||`Groq API error (${response.status}).`});res.json(data);}catch(err){console.error('Groq proxy error:',err.message);res.status(502).json({error:'Unable to reach Groq. Check your internet/network and try again.'});}
});
app.get('/health',(_req,res)=>res.json({ok:true,provider:'groq',aiConfigured:!!process.env.GROQ_API_KEY,model:process.env.GROQ_MODEL||'openai/gpt-oss-120b',userStore:USERS_FILE}));
app.get('*',(_req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
const PORT=process.env.PORT||3000;app.listen(PORT,()=>console.log(`RBL UAM Hub running on port ${PORT} · AI provider: Groq`));
