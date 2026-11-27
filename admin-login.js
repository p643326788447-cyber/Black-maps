const API="/.netlify/functions/api";
const $=s=>document.querySelector(s);
async function api(action,options={}){
  const r=await fetch(API+"?action="+action,{...options,cache:"no-store"});
  let d={};
  try{d=await r.json()}catch{}
  if(!r.ok)throw Error(d.error||"ارتباط با سرور برقرار نشد.");
  return d;
}
$("#login-form").onsubmit=async e=>{
  e.preventDefault();
  const f=new FormData(e.currentTarget),s=$("#login-status");
  s.textContent="در حال بررسی…";
  try{
    await api("login",{
      method:"POST",
      headers:{"content-type":"application/json"},
      body:JSON.stringify({username:f.get("username"),password:f.get("password")})
    });
    location.href="/admin.html";
  }catch(err){
    s.textContent=err.message;
  }
};