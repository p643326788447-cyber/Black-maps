function dec(s){s=s.replaceAll("-","+").replaceAll("_","/");const raw=atob(s+"=".repeat((4-s.length%4)%4));return Uint8Array.from(raw,c=>c.charCodeAt(0))}
export default async function handler(request){
 const h={"cache-control":"no-store, no-cache, must-revalidate","pragma":"no-cache","x-robots-tag":"noindex, nofollow"};
 try{
  const token=(request.headers.get("cookie")||"").split(";").map(v=>v.trim()).find(v=>v.startsWith("blackmaps_admin="))?.slice("blackmaps_admin=".length);
  const secret=Netlify.env.get("SESSION_SECRET")||"",user=Netlify.env.get("ADMIN_USER")||Netlify.env.get("ADMIN_USERNAME")||"";
  if(!token||!secret||!user)throw 0;
  const [payload,sig,...rest]=token.split(".");if(!payload||!sig||rest.length)throw 0;
  const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(secret),{name:"HMAC",hash:"SHA-256"},false,["verify"]);
  if(!await crypto.subtle.verify("HMAC",key,dec(sig),new TextEncoder().encode(payload)))throw 0;
  const p=JSON.parse(new TextDecoder().decode(dec(payload)));if(p.sub!==user||!Number.isFinite(p.exp)||p.exp<=Date.now())throw 0;
  return;
 }catch{return new Response(null,{status:302,headers:{...h,location:"/admin-login.html"}})}
}
export const config={path:"/admin.html"};