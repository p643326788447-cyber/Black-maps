import { getStore } from "@netlify/blobs";

const data = getStore("black-maps-data", { region: "eu-central-1" });
const media = getStore("black-maps-media", { region: "eu-central-1" });
const security = getStore("black-maps-security", { region: "eu-central-1" });
const MAX_IMAGE = 8 * 1024 * 1024;
const COOKIE = "blackmaps_admin";
const REMEMBER_DEVICE_SECONDS = 7 * 24 * 60 * 60;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_ATTEMPTS = 5;

function json(body, status=200, extra={}) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type":"application/json; charset=utf-8", "cache-control":"no-store", ...extra } });
}
function fail(message,status=400,extra={}){ return json({error:message},status,extra); }
function enc(bytes){ let s=""; for(const b of bytes)s+=String.fromCharCode(b); return btoa(s).replaceAll("+","-").replaceAll("/","_").replace(/=+$/,""); }
function dec(s){ const v=s.replaceAll("-","+").replaceAll("_","/"); const raw=atob(v+"=".repeat((4-v.length%4)%4)); return Uint8Array.from(raw,c=>c.charCodeAt(0)); }
async function sign(value){const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(process.env.SESSION_SECRET||""),{name:"HMAC",hash:"SHA-256"},false,["sign"]);return enc(new Uint8Array(await crypto.subtle.sign("HMAC",key,new TextEncoder().encode(value))));}
async function tokenFor(user){const payload=enc(new TextEncoder().encode(JSON.stringify({sub:user,exp:Date.now()+REMEMBER_DEVICE_SECONDS*1000})));return `${payload}.${await sign(payload)}`;}
async function isAdmin(req){try{const token=(req.headers.get("cookie")||"").split(";").map(x=>x.trim()).find(x=>x.startsWith(COOKIE+"="))?.slice(COOKIE.length+1);if(!token||!process.env.SESSION_SECRET||!(process.env.ADMIN_USER || process.env.ADMIN_USERNAME))return false;const [payload,sig]=token.split(".");if(!payload||!sig||await sign(payload)!==sig)return false;const p=JSON.parse(new TextDecoder().decode(dec(payload)));return p.sub===(process.env.ADMIN_USER || process.env.ADMIN_USERNAME)&&p.exp>Date.now()}catch{return false}}
function cookie(value,maxAge=REMEMBER_DEVICE_SECONDS){return `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;}
function id(){return crypto.randomUUID();}
function clean(s,n=500){return String(s??"").trim().slice(0,n);}
function validLink(s){if(!s)return "";try{const u=new URL(s);return u.protocol==="https:"?u.href:""}catch{return ""}}
async function list(prefix){const {blobs=[]}=await data.list({prefix});const out=await Promise.all(blobs.map(b=>data.get(b.key,{type:"json"})));return out.filter(Boolean).sort((a,b)=>(b.createdAt||"").localeCompare(a.createdAt||""));}
async function getRecord(type,key){return data.get(`${type}:${key}`,{type:"json"});}
async function requireAdmin(req){
  if (!await isAdmin(req)) return false;
  if (["GET","HEAD","OPTIONS"].includes(req.method)) return true;
  const origin = req.headers.get("origin");
  if (!origin) return false;
  try { return new URL(origin).origin === new URL(req.url).origin; } catch { return false; }
}
async function loginRateKey(req){
  const ip = req.headers.get("x-nf-client-connection-ip") || req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "unknown";
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(ip));
  return "login:" + enc(new Uint8Array(digest));
}
async function loginBlocked(req){
  const key = await loginRateKey(req);
  const state = await security.get(key, {type:"json"});
  if (!state || state.resetAt <= Date.now()) return {blocked:false,key,attempts:0};
  return {blocked:state.attempts >= LOGIN_MAX_ATTEMPTS,key,attempts:state.attempts,resetAt:state.resetAt};
}
async function recordLoginFailure(key, attempts){
  const now = Date.now();
  const state = await security.get(key, {type:"json"});
  const active = state && state.resetAt > now;
  const next = {attempts:(active ? state.attempts : 0) + 1, resetAt:active ? state.resetAt : now + LOGIN_WINDOW_MS};
  await security.setJSON(key,next);
  return next;
}
export default async (req) => {
  try {
    const u=new URL(req.url), action=u.searchParams.get("action")||"", method=req.method;
    if(action==="login"&&method==="POST"){
      const origin=req.headers.get("origin");
      try { if (!origin || new URL(origin).origin !== u.origin) return fail("درخواست ورود نامعتبر است.",403); } catch { return fail("درخواست ورود نامعتبر است.",403); }
      const rate=await loginBlocked(req);
      if(rate.blocked) return fail("تعداد تلاش‌های ورود بیش از حد مجاز است. ۱۵ دقیقه بعد دوباره تلاش کن.",429,{"retry-after":String(Math.max(1,Math.ceil((rate.resetAt-Date.now())/1000)))});
      const b=await req.json().catch(()=>({}));
      if(!(process.env.ADMIN_USER || process.env.ADMIN_USERNAME)||!process.env.ADMIN_PASSWORD||!process.env.SESSION_SECRET)return fail("تنظیمات مدیر روی هاست کامل نشده است.",503);
      if(clean(b.username,100)!==(process.env.ADMIN_USER || process.env.ADMIN_USERNAME)||clean(b.password,200)!==process.env.ADMIN_PASSWORD){
        await recordLoginFailure(rate.key,rate.attempts);
        return fail("نام کاربری یا رمز عبور اشتباه است.",401);
      }
      await security.delete(rate.key);
      return json({ok:true},200,{"set-cookie":cookie(await tokenFor((process.env.ADMIN_USER || process.env.ADMIN_USERNAME)))});
    }
    if(action==="logout"&&method==="POST")return json({ok:true},200,{"set-cookie":cookie("",0)});
    if(action==="me"&&method==="GET")return isAdmin(req)?json({ok:true}):fail("نیاز به ورود مدیر است.",401);

    if(action==="image"&&method==="GET"){
      const key=clean(u.searchParams.get("id"),80);if(!/^[a-f0-9-]{36}$/i.test(key))return fail("تصویر پیدا نشد.",404);
      const blob=await media.get(`image:${key}`,{type:"blob"});if(!blob)return fail("تصویر پیدا نشد.",404);
      const meta=await media.getMetadata(`image:${key}`);const type=meta?.metadata?.contentType||"image/jpeg";
      return new Response(blob,{headers:{"content-type":type,"cache-control":"public, max-age=3600","x-content-type-options":"nosniff"}});
    }

    if(action==="maps"&&method==="GET"){
      const maps=await list("map:");return json({maps:maps.map(m=>({...m,image:m.hasImage?`/.netlify/functions/api?action=image&id=${m.id}`:""}))});
    }
    if(action==="maps"&&method==="POST"){
      if(!await requireAdmin(req))return fail("نیاز به ورود مدیر است.",401);
      const form=await req.formData();const title=clean(form.get("title"),90),th=clean(form.get("th"),2),category=clean(form.get("category"),30),description=clean(form.get("description"),180),link=validLink(form.get("link"));
      const image=form.get("image");const validTh=["14","15","16","17","18","19"].includes(th);
      if(!title||!validTh||!["جنگی","فارمینگ","جام‌گیری","ضد سه‌ستاره"].includes(category))return fail("عنوان، تاون‌هال یا دسته‌بندی معتبر نیست.");
      const hasImage=image&&typeof image.arrayBuffer==="function"&&image.size>0;
      if(hasImage&&(image.size>MAX_IMAGE||!["image/jpeg","image/png","image/webp"].includes(image.type)))return fail("تصویر باید JPG، PNG یا WEBP و حداکثر ۸ مگابایت باشد.");
      if(!hasImage&&!link)return fail("لطفاً تصویر یا لینک نقشه وارد کن.");
      const key=id();if(hasImage)await media.set(`image:${key}`,image,{metadata:{contentType:image.type}});
      const item={id:key,title,th,category,description,link,hasImage:!!hasImage,createdAt:new Date().toISOString()};
      await data.setJSON(`map:${key}`,item);return json({ok:true,map:item},201);
    }
    if(action==="maps"&&method==="PUT"){
      if(!await requireAdmin(req))return fail("نیاز به ورود مدیر است.",401);
      const b=await req.json().catch(()=>({})),key=clean(b.id,80),item=await getRecord("map",key);if(!item)return fail("نقشه پیدا نشد.",404);
      const title=clean(b.title,90),th=clean(b.th,2),category=clean(b.category,30),description=clean(b.description,180),link=validLink(b.link);
      if(!title||!["14","15","16","17","18","19"].includes(th)||!["جنگی","فارمینگ","جام‌گیری","ضد سه‌ستاره"].includes(category)||(!link&&!item.hasImage))return fail("اطلاعات نقشه معتبر نیست.");
      Object.assign(item,{title,th,category,description,link,updatedAt:new Date().toISOString()});await data.setJSON("map:"+key,item);return json({ok:true,map:item});
    }
    if(action==="maps"&&method==="DELETE"){
      if(!await requireAdmin(req))return fail("نیاز به ورود مدیر است.",401);
      const key=clean(u.searchParams.get("id"),80);const item=await getRecord("map",key);if(!item)return fail("نقشه پیدا نشد.",404);
      if(item.hasImage)await media.delete(`image:${key}`);await data.delete(`map:${key}`);return json({ok:true});
    }

    if(action==="comments"&&method==="GET"){
      const mapId=clean(u.searchParams.get("mapId"),80);
      if(mapId){const comments=await list(`comment:${mapId}:`);return json({comments});}
      if(!await requireAdmin(req))return fail("نیاز به ورود مدیر است.",401);
      const comments=await list("comment:");const maps=await list("map:");const titles=Object.fromEntries(maps.map(m=>[m.id,m.title]));return json({comments:comments.map(c=>({...c,mapTitle:titles[c.mapId]||""}))});
    }
    if(action==="comments"&&method==="POST"){
      const b=await req.json().catch(()=>({})),mapId=clean(b.mapId,80),name=clean(b.name,40)||"کاربر",text=clean(b.text,800);
      if(!mapId||!text)return fail("متن نظر خالی است.");if(!await getRecord("map",mapId))return fail("نقشه پیدا نشد.",404);
      const item={id:id(),mapId,name,text,reply:"",createdAt:new Date().toISOString()};await data.setJSON(`comment:${mapId}:${item.id}`,item);return json({ok:true,comment:item},201);
    }
    if(action==="comments"&&method==="PATCH"){
      if(!await requireAdmin(req))return fail("نیاز به ورود مدیر است.",401);
      const b=await req.json().catch(()=>({})),commentId=clean(b.id,80),reply=clean(b.reply,800);const all=await list("comment:");const item=all.find(x=>x.id===commentId);if(!item)return fail("نظر پیدا نشد.",404);item.reply=reply;await data.setJSON(`comment:${item.mapId}:${item.id}`,item);return json({ok:true});
    }
    if(action==="comments"&&method==="PUT"){
      if(!await requireAdmin(req))return fail("نیاز به ورود مدیر است.",401);
      const b=await req.json().catch(()=>({})),commentId=clean(b.id,80),all=await list("comment:"),item=all.find(x=>x.id===commentId);if(!item)return fail("نظر پیدا نشد.",404);
      const name=clean(b.name,40)||"کاربر",text=clean(b.text,800);if(!text)return fail("متن نظر خالی است.");
      item.name=name;item.text=text;item.editedAt=new Date().toISOString();await data.setJSON("comment:"+item.mapId+":"+item.id,item);return json({ok:true,comment:item});
    }
    if(action==="comments"&&method==="DELETE"){
      if(!await requireAdmin(req))return fail("نیاز به ورود مدیر است.",401);
      const commentId=clean(u.searchParams.get("id"),80),all=await list("comment:");const item=all.find(x=>x.id===commentId);if(!item)return fail("نظر پیدا نشد.",404);await data.delete(`comment:${item.mapId}:${item.id}`);return json({ok:true});
    }

    if(action==="support"&&method==="POST"){
      const b=await req.json().catch(()=>({})),name=clean(b.name,40)||"کاربر",subject=clean(b.subject,90),message=clean(b.message,1500);
      if(!subject||!message)return fail("موضوع و متن پیام الزامی است.");const item={id:id(),name,subject,message,reply:"",createdAt:new Date().toISOString()};await data.setJSON(`support:${item.id}`,item);return json({ok:true},201);
    }
    if(action==="support"&&method==="GET"){
      if(!await requireAdmin(req))return fail("نیاز به ورود مدیر است.",401);return json({messages:await list("support:")});
    }
    if(action==="support"&&method==="PUT"){
      if(!await requireAdmin(req))return fail("نیاز به ورود مدیر است.",401);
      const b=await req.json().catch(()=>({})),item=await getRecord("support",clean(b.id,80));if(!item)return fail("پیام پیدا نشد.",404);
      const subject=clean(b.subject,90),message=clean(b.message,1500);if(!subject||!message)return fail("موضوع و متن پیام الزامی است.");
      item.subject=subject;item.message=message;item.editedAt=new Date().toISOString();await data.setJSON("support:"+item.id,item);return json({ok:true,message:item});
    }
    if(action==="support"&&method==="DELETE"){
      if(!await requireAdmin(req))return fail("نیاز به ورود مدیر است.",401);
      const key=clean(u.searchParams.get("id"),80);if(!await getRecord("support",key))return fail("پیام پیدا نشد.",404);await data.delete("support:"+key);return json({ok:true});
    }
    if(action==="support"&&method==="PATCH"){
      if(!await requireAdmin(req))return fail("نیاز به ورود مدیر است.",401);
      const b=await req.json().catch(()=>({})),item=await getRecord("support",clean(b.id,80));if(!item)return fail("پیام پیدا نشد.",404);item.reply=clean(b.reply,1200);item.repliedAt=new Date().toISOString();await data.setJSON(`support:${item.id}`,item);return json({ok:true});
    }

    if(action==="announcements"&&method==="GET")return json({announcements:await list("announcement:")});
    if(action==="announcements"&&method==="POST"){
      if(!await requireAdmin(req))return fail("نیاز به ورود مدیر است.",401);const b=await req.json().catch(()=>({})),title=clean(b.title,90),text=clean(b.text,1200);if(!title||!text)return fail("عنوان و متن اطلاعیه الزامی است.");const item={id:id(),title,text,createdAt:new Date().toISOString()};await data.setJSON(`announcement:${item.id}`,item);return json({ok:true,announcement:item},201);
    }
    if(action==="announcements"&&method==="PUT"){
      if(!await requireAdmin(req))return fail("نیاز به ورود مدیر است.",401);
      const b=await req.json().catch(()=>({})),key=clean(b.id,80),item=await getRecord("announcement",key);if(!item)return fail("اطلاعیه پیدا نشد.",404);
      const title=clean(b.title,90),text=clean(b.text,1200);if(!title||!text)return fail("عنوان و متن اطلاعیه الزامی است.");
      item.title=title;item.text=text;item.updatedAt=new Date().toISOString();await data.setJSON("announcement:"+key,item);return json({ok:true,announcement:item});
    }
    if(action==="announcements"&&method==="DELETE"){
      if(!await requireAdmin(req))return fail("نیاز به ورود مدیر است.",401);const key=clean(u.searchParams.get("id"),80);if(!await getRecord("announcement",key))return fail("اطلاعیه پیدا نشد.",404);await data.delete(`announcement:${key}`);return json({ok:true});
    }
    return fail("مسیر درخواست پیدا نشد.",404);
  } catch (error) {
    console.error("BLACK MAPS API error:",error);
    return fail("خطای داخلی سرور. لطفاً کمی بعد دوباره تلاش کن.",500);
  }
};
