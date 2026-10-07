import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import Database from 'better-sqlite3';
import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';
import multer from 'multer';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

dotenv.config();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(__dirname, '..');
const dbDir = path.join(root, 'db');
fs.mkdirSync(dbDir, { recursive: true });
const db = new Database(path.join(dbDir, 'aushadhi.db'));
db.pragma('foreign_keys = ON');
db.exec(fs.readFileSync(path.join(dbDir, 'schema.sql'), 'utf8'));

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-change-me';
if (process.env.NODE_ENV === 'production' && JWT_SECRET === 'dev-only-change-me') throw new Error('JWT_SECRET must be set in production');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '200kb' }));
const uploadDir = path.join(root, 'public', 'uploads');
fs.mkdirSync(uploadDir, { recursive: true });
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 }, fileFilter: (req,file,cb) => cb(null, ['image/jpeg','image/png','image/webp'].includes(file.mimetype)) });
app.use(cookieParser());
app.use(rateLimit({ windowMs: 15*60*1000, limit: 300, standardHeaders: true, legacyHeaders: false }));

const hash = p => bcrypt.hashSync(p, 12);
function ensureAdmin(){
  const username = process.env.ADMIN_USERNAME || 'admin';
  const password = process.env.ADMIN_PASSWORD || 'change-me-now';
  const existing = db.prepare("SELECT id FROM users WHERE role='ADMIN' LIMIT 1").get();
  if(!existing){ db.prepare("INSERT INTO users(role,username,password_hash,verified) VALUES('ADMIN',?,?,1)").run(username, hash(password)); }
}
function seedProducts(){
  if(db.prepare('SELECT COUNT(*) c FROM products').get().c) return;
  const rows = [
    ['Livonac-Zyme-DS Syrup','Ayurvedic polyherbal liver corrective syrup','Liver Care','225 ml',349,0,'',1,0,'',0,'/images/livonac-zyme-ds-225ml.jpg']
  ];
  const s=db.prepare(`INSERT INTO products(name,salt,category,packing,mrp,wholesale_price,scheme,moq,stock,hsn,gst_rate,image_url) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`);
  const tx=db.transaction(()=>rows.forEach(r=>s.run(...r))); tx();
}
ensureAdmin(); seedProducts();

function sign(user){ return jwt.sign({id:user.id,role:user.role}, JWT_SECRET, {expiresIn:'12h'}); }
function setAuthCookie(res,user){ res.cookie('ap_token', sign(user), { httpOnly:true, sameSite:'lax', secure:process.env.NODE_ENV==='production', maxAge:12*60*60*1000, path:'/' }); }
function auth(req,res,next){
  const token=req.cookies.ap_token || (req.headers.authorization||'').replace(/^Bearer /,'');
  if(!token) return res.status(401).json({error:'Authentication required'});
  try{ req.user=jwt.verify(token,JWT_SECRET); next(); }catch{ return res.status(401).json({error:'Session expired'}); }
}
function role(r){ return (req,res,next)=>req.user?.role===r?next():res.status(403).json({error:'Forbidden'}); }

app.get('/api/config',(req,res)=>res.json({business:{name:process.env.BUSINESS_NAME||'Aushadhi Pharma',phone:process.env.BUSINESS_PHONE||'',email:process.env.BUSINESS_EMAIL||'',address:process.env.BUSINESS_ADDRESS||'',whatsapp:process.env.WHATSAPP_NUMBER||''}}));
app.get('/api/products',(req,res)=>{
  const q=(req.query.q||'').trim(); const cat=(req.query.category||'').trim();
  let sql='SELECT * FROM products WHERE active=1'; const args=[];
  if(q){sql+=' AND (name LIKE ? OR salt LIKE ? OR category LIKE ?)'; const x='%'+q+'%'; args.push(x,x,x);}
  if(cat){sql+=' AND category=?'; args.push(cat);}
  sql+=' ORDER BY name'; res.json(db.prepare(sql).all(...args));
});

app.post('/api/auth/register', async (req,res)=>{
  const {storeName,ownerName,mobile,email,password,gstin,drugLicense,address}=req.body||{};
  if(!storeName||!mobile||!password) return res.status(400).json({error:'Store name, mobile and password are required'});
  if(password.length<8) return res.status(400).json({error:'Password must be at least 8 characters'});
  try{
    const info=db.prepare(`INSERT INTO users(role,store_name,owner_name,mobile,email,password_hash,gstin,drug_license,address) VALUES('RETAILER',?,?,?,?,?,?,?,?)`).run('RETAILER',storeName,ownerName||'',mobile,email||null,hash(password),gstin||'',drugLicense||'',address||'');
    const u=db.prepare('SELECT id,role,store_name,owner_name,mobile,email,gstin,drug_license,address,verified FROM users WHERE id=?').get(info.lastInsertRowid);
    setAuthCookie(res,u); res.status(201).json({user:u});
  }catch(e){ res.status(409).json({error:'Mobile or email may already be registered'}); }
});
app.post('/api/auth/login',(req,res)=>{
  const {username,password}=req.body||{};
  const u=db.prepare("SELECT * FROM users WHERE username=? OR mobile=? OR email=? LIMIT 1").get(username||'',username||'',username||'');
  if(!u || !bcrypt.compareSync(password||'',u.password_hash)) return res.status(401).json({error:'Invalid login'});
  const safe={id:u.id,role:u.role,store_name:u.store_name,owner_name:u.owner_name,mobile:u.mobile,email:u.email,gstin:u.gstin,drug_license:u.drug_license,address:u.address,verified:u.verified};
  setAuthCookie(res,safe); res.json({user:safe});
});
app.post('/api/auth/logout',(req,res)=>{res.clearCookie('ap_token');res.json({ok:true});});
app.get('/api/me',auth,(req,res)=>{ const u=db.prepare('SELECT id,role,store_name,owner_name,mobile,email,gstin,drug_license,address,verified FROM users WHERE id=?').get(req.user.id); res.json(u); });

app.post('/api/orders',auth,(req,res)=>{
  const {items,storeName,mobile,address,notes}=req.body||{};
  if(!Array.isArray(items)||!items.length) return res.status(400).json({error:'Order must contain items'});
  const get=db.prepare('SELECT id,name,wholesale_price,stock,moq,active FROM products WHERE id=?');
  const normalized=[];
  let subtotal=0;
  for(const i of items){ const p=get.get(Number(i.productId)); const qty=Math.floor(Number(i.qty)); if(!p||!p.active||qty<1) return res.status(400).json({error:'Invalid product or quantity'}); if(p.stock>0&&qty>p.stock) return res.status(400).json({error:`Insufficient stock for ${p.name}`}); if(qty<p.moq) return res.status(400).json({error:`Minimum order for ${p.name} is ${p.moq}`}); const line=p.wholesale_price*qty; subtotal+=line; normalized.push({p,qty,line}); }
  const orderNo='AP'+Date.now().toString().slice(-10);
  const tx=db.transaction(()=>{
    const o=db.prepare(`INSERT INTO orders(order_no,retailer_id,store_name,mobile,address,subtotal,total,notes) VALUES(?,?,?,?,?,?,?,?)`).run(orderNo,req.user.id,storeName||'',mobile||'',address||'',subtotal,subtotal,notes||'');
    const ins=db.prepare('INSERT INTO order_items(order_id,product_id,product_name,qty,unit_price,line_total) VALUES(?,?,?,?,?,?)');
    normalized.forEach(x=>{ ins.run(o.lastInsertRowid,x.p.id,x.p.name,x.qty,x.p.wholesale_price,x.line); if(x.p.stock>0) db.prepare('UPDATE products SET stock=stock-?, updated_at=CURRENT_TIMESTAMP WHERE id=? AND stock>=?').run(x.qty,x.p.id,x.qty); });
    return o.lastInsertRowid;
  });
  const id=tx(); res.status(201).json(db.prepare('SELECT * FROM orders WHERE id=?').get(id));
});
app.get('/api/orders',auth,(req,res)=>{
  const rows=req.user.role==='ADMIN'?db.prepare('SELECT * FROM orders ORDER BY id DESC').all():db.prepare('SELECT * FROM orders WHERE retailer_id=? ORDER BY id DESC').all(req.user.id);
  res.json(rows);
});
app.get('/api/orders/:id',auth,(req,res)=>{ const o=db.prepare('SELECT * FROM orders WHERE id=?').get(req.params.id); if(!o|| (req.user.role!=='ADMIN'&&o.retailer_id!==req.user.id)) return res.status(404).json({error:'Not found'}); o.items=db.prepare('SELECT * FROM order_items WHERE order_id=?').all(o.id); res.json(o); });

app.use('/api/admin',auth,role('ADMIN'));
app.get('/api/admin/stats',(req,res)=>res.json({products:db.prepare('SELECT COUNT(*) c FROM products WHERE active=1').get().c,orders:db.prepare('SELECT COUNT(*) c FROM orders').get().c,retailers:db.prepare("SELECT COUNT(*) c FROM users WHERE role='RETAILER'").get().c,pending:db.prepare("SELECT COUNT(*) c FROM orders WHERE status='PENDING'").get().c}));
app.get('/api/admin/products',(req,res)=>res.json(db.prepare('SELECT * FROM products ORDER BY active DESC, name').all()));
app.post('/api/admin/uploads/image', (req,res)=>{ upload.single('image')(req,res,(err)=>{ if(err) return res.status(400).json({error:err.code==='LIMIT_FILE_SIZE'?'Image must be 5MB or smaller':'Only JPG, PNG and WEBP images are allowed'}); if(!req.file) return res.status(400).json({error:'Image file is required'}); const ext={ 'image/jpeg':'.jpg','image/png':'.png','image/webp':'.webp' }[req.file.mimetype]; const filename=`${crypto.randomUUID()}${ext}`; fs.writeFileSync(path.join(uploadDir,filename),req.file.buffer); res.status(201).json({url:`/uploads/${filename}`}); }); });
function productInput(x){ const mrp=Number(x.mrp), wholesale=Number(x.wholesalePrice), moq=Math.floor(Number(x.moq)||1), stock=Math.floor(Number(x.stock)||0), gst=Number(x.gstRate)||0; if(!String(x.name||'').trim()) throw new Error('Product name is required'); if(!Number.isFinite(mrp)||mrp<0||!Number.isFinite(wholesale)||wholesale<0) throw new Error('MRP and wholesale price must be valid non-negative numbers'); if(moq<1||stock<0||gst<0) throw new Error('MOQ, stock or GST rate is invalid'); return {name:String(x.name).trim(),salt:String(x.salt||'').trim(),category:String(x.category||'').trim(),packing:String(x.packing||'').trim(),mrp,wholesale,scheme:String(x.scheme||'').trim(),moq,stock,hsn:String(x.hsn||'').trim(),gst,imageUrl:String(x.imageUrl||'').trim()}; }
app.post('/api/admin/products',(req,res)=>{try{const x=productInput(req.body||{}); const r=db.prepare(`INSERT INTO products(name,salt,category,packing,mrp,wholesale_price,scheme,moq,stock,hsn,gst_rate,image_url) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).run(x.name,x.salt,x.category,x.packing,x.mrp,x.wholesale,x.scheme,x.moq,x.stock,x.hsn,x.gst,x.imageUrl); res.status(201).json(db.prepare('SELECT * FROM products WHERE id=?').get(r.lastInsertRowid));}catch(e){res.status(400).json({error:e.message})}});
app.put('/api/admin/products/:id',(req,res)=>{try{const x=productInput(req.body||{}); const r=db.prepare(`UPDATE products SET name=?,salt=?,category=?,packing=?,mrp=?,wholesale_price=?,scheme=?,moq=?,stock=?,hsn=?,gst_rate=?,image_url=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`).run(x.name,x.salt,x.category,x.packing,x.mrp,x.wholesale,x.scheme,x.moq,x.stock,x.hsn,x.gst,x.imageUrl,req.params.id); if(!r.changes)return res.status(404).json({error:'Product not found'}); res.json(db.prepare('SELECT * FROM products WHERE id=?').get(req.params.id));}catch(e){res.status(400).json({error:e.message})}});
app.delete('/api/admin/products/:id',(req,res)=>{db.prepare('UPDATE products SET active=0 WHERE id=?').run(req.params.id);res.json({ok:true});});
app.patch('/api/admin/orders/:id/status',(req,res)=>{const allowed=['PENDING','CONFIRMED','DISPATCHED','DELIVERED','CANCELLED']; if(!allowed.includes(req.body.status)) return res.status(400).json({error:'Invalid status'}); db.prepare('UPDATE orders SET status=? WHERE id=?').run(req.body.status,req.params.id); res.json(db.prepare('SELECT * FROM orders WHERE id=?').get(req.params.id));});
app.get('/api/admin/retailers',(req,res)=>res.json(db.prepare("SELECT id,store_name,owner_name,mobile,email,gstin,drug_license,address,verified,created_at FROM users WHERE role='RETAILER' ORDER BY id DESC").all()));

app.use(express.static(path.join(root,'public')));
app.get('*',(req,res)=>res.sendFile(path.join(root,'public','index.html')));
app.listen(PORT,()=>console.log(`Aushadhi Pharma running on http://localhost:${PORT}`));
