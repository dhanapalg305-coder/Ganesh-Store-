require('dotenv').config();
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const multer = require('multer');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const DATA_DIR = path.resolve(ROOT, 'data');
const DB_FILE = path.resolve(ROOT, process.env.DATABASE_FILE || './data/ganesh.sqlite');
const UPLOAD_DIR = path.resolve(ROOT, process.env.UPLOAD_DIR || './data/uploads');
fs.mkdirSync(path.dirname(DB_FILE), {recursive:true});
fs.mkdirSync(UPLOAD_DIR, {recursive:true});

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  throw new Error('SESSION_SECRET must be set and at least 32 characters long.');
}
if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD || process.env.ADMIN_PASSWORD.length < 12) {
  throw new Error('Set ADMIN_EMAIL and a strong ADMIN_PASSWORD (12+ characters).');
}

app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({contentSecurityPolicy:false, crossOriginEmbedderPolicy:false}));
app.use(express.json({limit:'1mb'}));
app.use(express.urlencoded({extended:false, limit:'100kb'}));



const db = new Database(DB_FILE);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS admins (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS products (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 slug TEXT NOT NULL UNIQUE,
 category TEXT NOT NULL DEFAULT 'GANESH',
 description TEXT NOT NULL DEFAULT '',
 price INTEGER NOT NULL DEFAULT 0 CHECK(price>=0),
 market_price INTEGER NOT NULL DEFAULT 0 CHECK(market_price>=0),
 image TEXT NOT NULL DEFAULT '',
 active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS settings (
 key TEXT PRIMARY KEY,
 value TEXT NOT NULL
);
`);

function seed(){
 const admin=db.prepare('SELECT id FROM admins WHERE email=?').get(process.env.ADMIN_EMAIL.toLowerCase());
 if(!admin){
   const hash=bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);
   db.prepare('INSERT INTO admins(email,password_hash) VALUES(?,?)').run(process.env.ADMIN_EMAIL.toLowerCase(),hash);
 }
 const count=db.prepare('SELECT COUNT(*) c FROM products').get().c;
 if(count===0){
  const products=[
   ['Wooden Serving Plates','wooden-serving-plates','GANESH','Natural wooden serving plates for dining and gifting',899,899,'/images/product-1.jpg'],
   ['Brass / Gold Serving Plate','brass-gold-serving-plate','GANESH','Traditional brass-finish serving and pooja plate',1880,1880,'/images/product-2.jpg'],
   ['Custom Engraved Steel Plates','custom-engraved-steel-plates','GANESH','Personalized engraved stainless-steel plates',1200,1200,'/images/product-3.jpg'],
   ['Stainless Steel Dinner Set','stainless-steel-dinner-set','GANESH','Stainless-steel plates, bowls, tumblers and serving ware',2650,2650,'/images/product-4.jpg'],
   ['Stainless Steel Cookware','stainless-steel-cookware','GANESH','Everyday stainless-steel cookware and vessel collection',1999,1999,'/images/product-5.jpg'],
   ['Wicker Hanging Chair','wicker-hanging-chair','GANESH','Wicker swing chair with cushion',4999,4999,'/images/product-6.jpg'],
   ['Wooden Bed','wooden-bed','GANESH','Modern wooden double bed frame',24999,24999,'/images/product-7.jpg'],
   ['Crockery & Dinnerware','crockery-dinnerware','GANESH','Ceramic and porcelain plates, bowls and serving sets',1999,1999,'/images/product-8.jpg'],
   ['Stainless Steel Storage & Kitchenware','stainless-steel-storage-kitchenware','GANESH','Steel containers, jars and kitchen storage collection',2499,2499,'/images/product-9.jpg']
  ];
  const ins=db.prepare('INSERT INTO products(name,slug,category,description,price,market_price,image) VALUES(?,?,?,?,?,?,?)');
  const tx=db.transaction(rows=>rows.forEach(r=>ins.run(...r))); tx(products);
 }
 const defaults={storeName:'GANESH',heroTitle:'Kitchen essentials for every home.',heroDesc:'Shop cookware and kitchenware from Ganesh. Add products to your cart and send your order directly to us on WhatsApp.',heroImage:'/images/product-4.jpg',whatsapp:'918681841392',upi:'aadhia378-3@okicici',location:'Srirangam, Trichy',currency:'INR'};
 const ins=db.prepare('INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)');
 for(const [k,v] of Object.entries(defaults)) ins.run(k,String(v));
}
seed();

class SQLiteSessionStore extends session.Store {
  constructor(database){ super(); this.db=database; this.db.exec(`CREATE TABLE IF NOT EXISTS sessions (sid TEXT PRIMARY KEY, expires INTEGER NOT NULL, data TEXT NOT NULL)`); }
  get(sid, cb){ try { const r=this.db.prepare('SELECT data,expires FROM sessions WHERE sid=?').get(sid); if(!r) return cb(null,null); if(r.expires<=Date.now()){ this.db.prepare('DELETE FROM sessions WHERE sid=?').run(sid); return cb(null,null); } cb(null,JSON.parse(r.data)); } catch(e){cb(e)} }
  set(sid,sess,cb){ try { const expires=sess.cookie?.expires ? new Date(sess.cookie.expires).getTime() : Date.now()+86400000; this.db.prepare('INSERT INTO sessions(sid,expires,data) VALUES(?,?,?) ON CONFLICT(sid) DO UPDATE SET expires=excluded.expires,data=excluded.data').run(sid,expires,JSON.stringify(sess)); cb&&cb(null); } catch(e){cb&&cb(e)} }
  destroy(sid,cb){ try{this.db.prepare('DELETE FROM sessions WHERE sid=?').run(sid);cb&&cb(null)}catch(e){cb&&cb(e)} }
  touch(sid,sess,cb){ try{const expires=sess.cookie?.expires ? new Date(sess.cookie.expires).getTime() : Date.now()+86400000; this.db.prepare('UPDATE sessions SET expires=? WHERE sid=?').run(expires,sid);cb&&cb(null)}catch(e){cb&&cb(e)} }
  clear(cb){try{this.db.prepare('DELETE FROM sessions').run();cb&&cb(null)}catch(e){cb&&cb(e)}}
}

const sessionStore = new SQLiteSessionStore(db);
app.use(session({
  store: sessionStore,
  secret: process.env.SESSION_SECRET,
  resave:false,
  saveUninitialized:false,
  cookie:{httpOnly:true, secure:process.env.NODE_ENV==='production', sameSite:'lax', maxAge:1000*60*60*8}
}));
const loginLimiter=rateLimit({windowMs:15*60*1000,max:10,standardHeaders:true,legacyHeaders:false,message:{error:'Too many login attempts. Try again later.'}});
const apiLimiter=rateLimit({windowMs:60*1000,max:120,standardHeaders:true,legacyHeaders:false});

function csrfToken(req){
 if(!req.session.csrf) req.session.csrf=crypto.randomBytes(32).toString('hex');
 return req.session.csrf;
}
function requireCsrf(req,res,next){
 const token=req.get('x-csrf-token');
 if(!token || token!==req.session.csrf) return res.status(403).json({error:'Invalid CSRF token'});
 next();
}
function requireAdmin(req,res,next){
 if(!req.session.adminId) return res.status(401).json({error:'Authentication required'});
 next();
}
function cleanText(v,max=500){return String(v??'').trim().slice(0,max)}
function money(v){const n=Number(v); if(!Number.isInteger(n)||n<0||n>100000000) throw new Error('Invalid price'); return n;}
function slugify(s){return cleanText(s,120).toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-+|-+$/g,'') || crypto.randomUUID();}
function publicProduct(r){return {...r,active:Boolean(r.active),price:Number(r.price),marketPrice:Number(r.market_price),image:r.image};}
function getSettings(){const rows=db.prepare('SELECT key,value FROM settings').all();return Object.fromEntries(rows.map(r=>[r.key,r.value]));}
function saveSetting(k,v){db.prepare('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(k,cleanText(v,1000));}
function safeImageName(name){return path.basename(name).replace(/[^a-zA-Z0-9._-]/g,'_');}

const allowedTypes=new Set(['image/jpeg','image/png','image/webp','image/gif']);
const upload=multer({storage:multer.memoryStorage(),limits:{fileSize:5*1024*1024},fileFilter:(req,file,cb)=>{ if(!allowedTypes.has(file.mimetype)) return cb(new Error('Only JPG, PNG, WEBP or GIF images are allowed')); cb(null,true); }});
async function saveImage(file){
 if(!file) return null;
 if(!allowedTypes.has(file.mimetype)) throw new Error('Only JPG, PNG, WEBP or GIF images are allowed');
 const {fileTypeFromBuffer}=await import('file-type');
 const detected=await fileTypeFromBuffer(file.buffer);
 if(!detected || !['image/jpeg','image/png','image/webp','image/gif'].includes(detected.mime)) throw new Error('Invalid image file');
 const ext={ 'image/jpeg':'jpg','image/png':'png','image/webp':'webp','image/gif':'gif'}[detected.mime];
 const name=crypto.randomUUID()+'.'+ext;
 fs.writeFileSync(path.join(UPLOAD_DIR,name),file.buffer,{flag:'wx'});
 return '/uploads/'+name;
}
function deleteUpload(image){if(!image || !image.startsWith('/uploads/')) return; const p=path.join(UPLOAD_DIR,safeImageName(image.split('/').pop())); if(fs.existsSync(p)) fs.unlinkSync(p);}

app.get('/health',(_,res)=>res.json({ok:true}));
app.get('/api/store',apiLimiter,(req,res)=>{
 const products=db.prepare('SELECT id,name,slug,category,description,price,market_price,image,active FROM products WHERE active=1 ORDER BY id DESC').all().map(publicProduct);
 res.json({settings:getSettings(),products});
});
app.get('/api/admin/csrf',requireAdmin,(req,res)=>res.json({token:csrfToken(req)}));
app.post('/api/admin/login',loginLimiter,async(req,res)=>{
 try{
  const email=cleanText(req.body.email,200).toLowerCase(); const password=String(req.body.password||'');
  const admin=db.prepare('SELECT id,email,password_hash FROM admins WHERE email=?').get(email);
  const ok=admin && await bcrypt.compare(password,admin.password_hash);
  if(!ok) return res.status(401).json({error:'Invalid email or password'});
  await new Promise((resolve,reject)=>req.session.regenerate(err=>err?reject(err):resolve()));
  req.session.adminId=admin.id; req.session.adminEmail=admin.email; req.session.csrf=crypto.randomBytes(32).toString('hex');
  res.json({ok:true,email:admin.email,csrf:req.session.csrf});
 }catch(e){res.status(500).json({error:'Login failed'});}
});
app.post('/api/admin/logout',requireAdmin,requireCsrf,(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/api/admin/me',requireAdmin,(req,res)=>res.json({id:req.session.adminId,email:req.session.adminEmail}));
app.get('/api/admin/products',requireAdmin,(req,res)=>res.json(db.prepare('SELECT id,name,slug,category,description,price,market_price,image,active FROM products ORDER BY id DESC').all().map(publicProduct)));
app.post('/api/admin/products',requireAdmin,requireCsrf,upload.single('image'),async(req,res)=>{
 try{
  const name=cleanText(req.body.name,120); if(!name) return res.status(400).json({error:'Product name is required'});
  const slug=slugify(req.body.slug||name); const image=await saveImage(req.file) || '/images/product-1.jpg';
  const result=db.prepare('INSERT INTO products(name,slug,category,description,price,market_price,image,active,updated_at) VALUES(?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)').run(name,slug,cleanText(req.body.category,80)||'GANESH',cleanText(req.body.description,1000),money(req.body.price||0),money(req.body.marketPrice||req.body.price||0),image,req.body.active==='false'?0:1);
  res.status(201).json(publicProduct(db.prepare('SELECT id,name,slug,category,description,price,market_price,image,active FROM products WHERE id=?').get(result.lastInsertRowid)));
 }catch(e){if(req.file){} res.status(400).json({error:e.message||'Could not create product'});}
});
app.put('/api/admin/products/:id',requireAdmin,requireCsrf,upload.single('image'),async(req,res)=>{
 try{
  const id=Number(req.params.id); const old=db.prepare('SELECT * FROM products WHERE id=?').get(id); if(!old) return res.status(404).json({error:'Product not found'});
  const name=cleanText(req.body.name,120); if(!name) return res.status(400).json({error:'Product name is required'});
  let image=old.image; if(req.file){image=await saveImage(req.file); deleteUpload(old.image);}
  db.prepare('UPDATE products SET name=?,slug=?,category=?,description=?,price=?,market_price=?,image=?,active=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(name,slugify(req.body.slug||name),cleanText(req.body.category,80)||'GANESH',cleanText(req.body.description,1000),money(req.body.price||0),money(req.body.marketPrice||req.body.price||0),image,req.body.active==='false'?0:1,id);
  res.json(publicProduct(db.prepare('SELECT id,name,slug,category,description,price,market_price,image,active FROM products WHERE id=?').get(id)));
 }catch(e){res.status(400).json({error:e.message||'Could not update product'});}
});
app.delete('/api/admin/products/:id',requireAdmin,requireCsrf,(req,res)=>{
 const id=Number(req.params.id); const p=db.prepare('SELECT image FROM products WHERE id=?').get(id); if(!p) return res.status(404).json({error:'Product not found'});
 db.prepare('DELETE FROM products WHERE id=?').run(id); deleteUpload(p.image); res.json({ok:true});
});
app.post('/api/admin/password',requireAdmin,requireCsrf,async(req,res)=>{
 try{ const current=String(req.body.currentPassword||''); const next=String(req.body.newPassword||''); if(next.length<12) return res.status(400).json({error:'New password must be at least 12 characters'}); const a=db.prepare('SELECT password_hash FROM admins WHERE id=?').get(req.session.adminId); if(!a || !(await bcrypt.compare(current,a.password_hash))) return res.status(401).json({error:'Current password is incorrect'}); const hash=await bcrypt.hash(next,12); db.prepare('UPDATE admins SET password_hash=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(hash,req.session.adminId); req.session.regenerate(err=>{ if(err) return res.status(500).json({error:'Password changed; session reset. Please sign in again.'}); res.json({ok:true}); }); }catch(e){res.status(500).json({error:'Could not change password'});}
});
app.get('/api/admin/settings',requireAdmin,(req,res)=>res.json(getSettings()));
app.put('/api/admin/settings',requireAdmin,requireCsrf,(req,res)=>{
 const allowed=['storeName','heroTitle','heroDesc','whatsapp','upi','location','currency'];
 for(const k of allowed) if(k in req.body) saveSetting(k,req.body[k]);
 res.json(getSettings());
});
app.post('/api/admin/settings/hero-image',requireAdmin,requireCsrf,upload.single('image'),async(req,res)=>{
 try{const image=await saveImage(req.file); if(!image) return res.status(400).json({error:'Image required'}); const old=getSettings().heroImage; saveSetting('heroImage',image); deleteUpload(old); res.json({heroImage:image});}
 catch(e){res.status(400).json({error:e.message});}
});

app.use('/uploads',express.static(UPLOAD_DIR,{fallthrough:false,maxAge:'7d',setHeaders:(res)=>res.setHeader('X-Content-Type-Options','nosniff')}));
app.use(express.static(path.join(ROOT,'public'),{extensions:['html'],maxAge:process.env.NODE_ENV==='production'?'1h':0}));
app.get('/admin',(req,res)=>res.sendFile(path.join(ROOT,'public','admin.html')));
app.use((req,res)=>res.status(404).send('Not found'));

app.listen(PORT,()=>console.log(`Ganesh Cookware running on http://localhost:${PORT}`));
