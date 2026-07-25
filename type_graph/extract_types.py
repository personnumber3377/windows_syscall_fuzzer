#!/usr/bin/env python3
"""Extract a compact, serializer-oriented type graph from Clang AST JSON."""
from __future__ import annotations
import argparse, json, re, sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

DECL_KINDS={"RecordDecl","TypedefDecl","EnumDecl","FunctionDecl"}
INTEGER_ATOMS={
"_Bool":(1,False),"bool":(1,False),"char":(1,True),"signed char":(1,True),"unsigned char":(1,False),
"short":(2,True),"short int":(2,True),"signed short":(2,True),"signed short int":(2,True),"unsigned short":(2,False),"unsigned short int":(2,False),
"int":(4,True),"signed":(4,True),"signed int":(4,True),"unsigned":(4,False),"unsigned int":(4,False),
"long":(4,True),"long int":(4,True),"signed long":(4,True),"signed long int":(4,True),"unsigned long":(4,False),"unsigned long int":(4,False),
"long long":(8,True),"long long int":(8,True),"signed long long":(8,True),"signed long long int":(8,True),"unsigned long long":(8,False),"unsigned long long int":(8,False),
"__int8":(1,True),"unsigned __int8":(1,False),"__int16":(2,True),"unsigned __int16":(2,False),"__int32":(4,True),"unsigned __int32":(4,False),"__int64":(8,True),"unsigned __int64":(8,False)}
FLOAT_ATOMS={"float":4,"double":8}
HANDLE_NAME_RE=re.compile(r"^(?:H[A-Z0-9_]+|HANDLE|HWND|HDC|HGDIOBJ|HSURF|DHSURF|DHPDEV)$")
QUALIFIER_RE=re.compile(r"\b(?:const|volatile|restrict|__restrict|__restrict__|_Atomic)\b")
ATTRIBUTE_RE=re.compile(r"__attribute__\s*\(\(.*?\)\)")
CALLING_RE=re.compile(r"\b(?:__cdecl|__stdcall|__fastcall|__thiscall|WINAPI|APIENTRY|CALLBACK|NTAPI)\b")
ARRAY_RE=re.compile(r"^(.*?)\s*\[\s*(\d*)\s*\]\s*$")
FUNCTION_POINTER_RE=re.compile(r"\(\s*\*\s*(?:[A-Za-z_]\w*)?\s*\)")
TAG_PREFIX_RE=re.compile(r"^(struct|union|enum)\s+")
DEFAULT_OVERRIDES={
("SURFOBJ","pvBits"):{"kind":"buffer","length_field":"cjBits","format_field":"iBitmapFormat","description":"Serializer-owned bitmap or compressed-image bytes."},
("_SURFOBJ","pvBits"):{"kind":"buffer","length_field":"cjBits","format_field":"iBitmapFormat","description":"Serializer-owned bitmap or compressed-image bytes."}}

def normpath(v:str)->str:return str(Path(v).expanduser().resolve(strict=False))
def clean(t:str)->str:
 t=ATTRIBUTE_RE.sub(" ",t);t=CALLING_RE.sub(" ",t);t=QUALIFIER_RE.sub(" ",t);t=re.sub(r"\s+"," ",t).strip();t=t.replace(" *","*").replace("*"," * ");return re.sub(r"\s+"," ",t).strip()
def decl_file(n:dict[str,Any])->Optional[str]:
 loc=n.get("loc") or {}
 for obj in (loc,loc.get("spellingLoc") or {},loc.get("expansionLoc") or {}):
  if isinstance(obj.get("file"),str):return obj["file"]
 begin=(n.get("range") or {}).get("begin") or {}
 for obj in (begin,begin.get("spellingLoc") or {},begin.get("expansionLoc") or {}):
  if isinstance(obj.get("file"),str):return obj["file"]
 for obj in (loc.get("includedFrom") or {},begin.get("includedFrom") or {}):
  if isinstance(obj.get("file"),str):return obj["file"]
 return None
def source(n:dict[str,Any])->dict[str,Any]:
 loc=n.get("loc") or {};p=loc
 if not isinstance(p.get("line"),int):p=loc.get("spellingLoc") or loc.get("expansionLoc") or loc
 r={};f=decl_file(n)
 if f:r["file"]=f
 if isinstance(p.get("line"),int):r["line"]=p["line"]
 if isinstance(p.get("col"),int):r["column"]=p["col"]
 return r

@dataclass
class HeaderFilter:
 roots:list[str];exact:set[str]
 @classmethod
 def build(cls,roots:Iterable[str],exact:Iterable[str]):return cls([normpath(x) for x in roots],{normpath(x) for x in exact})
 def accepts(self,f:Optional[str])->bool:
  return True # Always return true here maybe???
  if not f:return False
  c=normpath(f)
  if c in self.exact:return True
  for root in self.roots:
   try:Path(c).relative_to(root);return True
   except ValueError:pass
  return False

@dataclass
class Graph:
 records:dict[str,dict[str,Any]]=field(default_factory=dict);typedefs:dict[str,dict[str,Any]]=field(default_factory=dict);enums:dict[str,dict[str,Any]]=field(default_factory=dict);functions:dict[str,dict[str,Any]]=field(default_factory=dict)

class Extractor:
 def __init__(self,hf:HeaderFilter):self.hf=hf;self.g=Graph()
 def run(self,ast:dict[str,Any])->Graph:
  for n in ast.get("inner",[]):
   if isinstance(n,dict) and n.get("kind") in DECL_KINDS and self.hf.accepts(decl_file(n)):self.one(n)
  return self.g
 def one(self,n):
  k=n.get("kind")
  if k=="RecordDecl":self.record(n)
  elif k=="TypedefDecl":self.typedef(n)
  elif k=="EnumDecl":self.enum(n)
  elif k=="FunctionDecl":self.function(n)
 def record(self,n):
  if not n.get("completeDefinition") or not n.get("name"):return
  fs=[]
  for c in n.get("inner",[]):
   if c.get("kind")!="FieldDecl":continue
   q=(c.get("type") or {}).get("qualType")
   if not c.get("name") or not q:continue
   e={"name":c["name"],"type":clean(q)}
   d=(c.get("type") or {}).get("desugaredQualType")
   if d:e["desugared_type"]=clean(d)
   if c.get("isBitfield"):e["bitfield"]=True
   fs.append(e)
  name=n["name"];e={"kind":"union" if n.get("tagUsed")=="union" else "struct","name":name,"fields":fs,"source":source(n)}
  old=self.g.records.get(name)
  if old is None or len(fs)>len(old.get("fields",[])):self.g.records[name]=e
 def typedef(self,n):
  name=n.get("name");t=n.get("type") or {};q=t.get("qualType")
  if not name or not q:return
  e={"kind":"typedef","name":name,"target":clean(q),"source":source(n)}
  if t.get("desugaredQualType"):e["desugared_target"]=clean(t["desugaredQualType"])
  self.g.typedefs[name]=e
 def enum(self,n):
  name=n.get("name")
  if not name:return
  vals=[]
  for c in n.get("inner",[]):
   if c.get("kind")!="EnumConstantDecl":continue
   x={"name":c.get("name","")};v=self.enumval(c)
   if v is not None:x["value"]=v
   vals.append(x)
  self.g.enums[name]={"kind":"enum","name":name,"values":vals,"source":source(n)}
 def enumval(self,n):
  stack=[n]
  while stack:
   c=stack.pop();v=c.get("value")
   if c.get("kind") in {"EnumConstantDecl","ConstantExpr","IntegerLiteral"} and isinstance(v,str):
    try:return int(v,0)
    except ValueError:pass
   stack.extend(c.get("inner",[]))
  return None
 def function(self,n):
  name=n.get("name");sig=(n.get("type") or {}).get("qualType")
  if not name or not sig:return
  ps=[]
  for c in n.get("inner",[]):
   if c.get("kind")=="ParmVarDecl" and (c.get("type") or {}).get("qualType"):
    ps.append({"name":c.get("name") or f"arg{len(ps)}","type":clean(c["type"]["qualType"])})
  self.g.functions[name]={"kind":"function","name":name,"return_type":clean(sig.split("(",1)[0]),"parameters":ps,"source":source(n)}

class Resolver:
 def __init__(self,g:Graph,pointer_size:int,overrides):
  self.g=g;self.ps=pointer_size;self.ov=overrides;self.cache={};self.warnings=[];self.aliases={}
  for n,t in g.typedefs.items():
   b=TAG_PREFIX_RE.sub("",t["target"]).strip()
   if b in g.records:self.aliases.setdefault(b,[]).append(n)
 def all(self):
  types={}
  for n in sorted(self.g.typedefs):types[n]=self.resolve(n,[n])
  for n,r in sorted(self.g.records.items()):types.setdefault(f"{r['kind']} {n}",self.resolve(f"{r['kind']} {n}",[n]))
  for n in sorted(self.g.enums):types.setdefault(f"enum {n}",self.resolve(f"enum {n}",[n]))
  funcs={}
  for n,f in sorted(self.g.functions.items()):
   ps=[];ok=True
   for p in f["parameters"]:
    rr=self.resolve(p["type"],[f"{n}.{p['name']}"]);ok&=bool(rr.get("representable"));ps.append({**p,"resolved":rr})
   ret=self.resolve(f["return_type"],[f"{n}.return"]);ok&=bool(ret.get("representable"));funcs[n]={**f,"return_resolved":ret,"parameters":ps,"representable":ok}
  return {"types":types,"functions":funcs,"warnings":self.warnings}
 def resolve(self,t,path,active=None):
  n=clean(t);active=set() if active is None else set(active)
  m=ARRAY_RE.match(n)
  if m:
   elem=clean(m.group(1));cnt=m.group(2)
   if not cnt:return self.bad(n,"flexible_array",path,"Flexible array needs a containing-record override.")
   rr=self.resolve(elem,path+["[]"],active);c=int(cnt);return {"kind":"array","spelling":n,"count":c,"element":rr,"size":c*rr["size"] if rr.get("representable") and isinstance(rr.get("size"),int) else None,"representable":bool(rr.get("representable"))}
  if FUNCTION_POINTER_RE.search(n) or re.search(r"\)\s*\(",n):return self.bad(n,"function_pointer",path,"Function pointer needs a callback policy.")
  if "*" in n:
   p=clean(n.replace("*"," "))
   if p.replace(" ","") in {"void","PVOID","LPVOID","LPCVOID","PCVOID","constvoid"}:return self.bad(n,"void_pointer",path,"Resolved to PVOID/void*. Add a field or parameter override.")
   return self.bad(n,"typed_pointer",path,f"Pointer to {p!r} has no allocation/length/ownership policy.")
  tag=TAG_PREFIX_RE.match(n);tagkind=tag.group(1) if tag else None;bare=TAG_PREFIX_RE.sub("",n).strip()
  if HANDLE_NAME_RE.match(bare):return {"kind":"handle","spelling":n,"handle_type":bare,"size":self.ps,"representable":True}
  if n in INTEGER_ATOMS:
   size,signed=INTEGER_ATOMS[n];return {"kind":"integer","spelling":n,"size":size,"signed":signed,"representable":True}
  if n in FLOAT_ATOMS:return {"kind":"float","spelling":n,"size":FLOAT_ATOMS[n],"representable":True}
  if bare=="void":return {"kind":"void","spelling":n,"size":0,"representable":True}
  if n in self.cache:return self.cache[n]
  if n in active:return self.bad(n,"recursive_type",path,"Recursive by-value type encountered.")
  active.add(n)
  if n in self.g.typedefs:
   td=self.g.typedefs[n];rr=self.resolve(td.get("desugared_target") or td["target"],path+[n],active);out={"kind":"typedef","spelling":n,"target":td["target"],"resolved":rr,"size":rr.get("size"),"representable":bool(rr.get("representable"))};self.cache[n]=out;return out
  if bare in self.g.records and tagkind in {None,"struct","union"}:
   out=self.record(self.g.records[bare],path,active);self.cache[n]=out;return out
  if bare in self.g.enums and tagkind in {None,"enum"}:
   out={"kind":"enum","spelling":n,"name":bare,"size":4,"signed":True,"values":self.g.enums[bare]["values"],"representable":True};self.cache[n]=out;return out
  if bare!=n and bare in self.g.typedefs:return self.resolve(bare,path,active)
  return self.bad(n,"unknown_type",path,"No extracted declaration or atomic mapping exists.")
 def record(self,r,path,active):
  names=[r["name"],*self.aliases.get(r["name"],[])];fields=[];ok=True;total=0;mx=0
  for f in r["fields"]:
   ov=next((self.ov.get((x,f["name"])) for x in names if self.ov.get((x,f["name"]))),None)
   if ov:rr={**ov,"spelling":f["type"],"representable":True,"field_storage_size":self.ps};size=self.ps
   else:rr=self.resolve(f["type"],path+[f"{r['name']}.{f['name']}"],active);size=rr.get("size") if isinstance(rr.get("size"),int) else None
   fok=bool(rr.get("representable")) and size is not None;ok&=fok;fields.append({**f,"resolved":rr,"representable":fok})
   if size is not None:
    if r["kind"]=="union":mx=max(mx,size)
    else:total+=size
  return {"kind":r["kind"],"spelling":f"{r['kind']} {r['name']}","name":r["name"],"aliases":self.aliases.get(r["name"],[]),"fields":fields,"logical_serialized_size":(mx if r["kind"]=="union" else total) if ok else None,"size_note":"Logical size excludes ABI padding; obtain Clang record layouts before constructing native structs.","representable":ok}
 def bad(self,t,reason,path,msg):
  w={"severity":"warning","reason":reason,"path":" -> ".join(path),"type":t,"message":msg}
  if w not in self.warnings:self.warnings.append(w)
  return {"kind":"unsupported","spelling":t,"reason":reason,"message":msg,"size":None,"representable":False}

def overrides(path):
 out=dict(DEFAULT_OVERRIDES)
 if path:
  raw=json.load(open(path,encoding="utf-8"))
  for k,v in raw.items():
   if "." not in k or not isinstance(v,dict) or "kind" not in v:raise ValueError(f"Bad override {k!r}; expected Record.field -> object with kind")
   out[tuple(k.rsplit(".",1))]=v
 return out

def args():
 p=argparse.ArgumentParser();p.add_argument("ast");p.add_argument("-o","--output",default="-");p.add_argument("--header-root",action="append",default=[]);p.add_argument("--header",action="append",default=[]);p.add_argument("--overrides");p.add_argument("--pointer-size",type=int,choices=(4,8),default=8);p.add_argument("--pretty",action="store_true");p.add_argument("--fail-on-warning",action="store_true");return p.parse_args()
def main():
 a=args()
 if not a.header_root and not a.header:print("error: provide --header-root and/or --header",file=sys.stderr);return 1
 ast=json.load(open(a.ast,encoding="utf-8"));g=Extractor(HeaderFilter.build(a.header_root,a.header)).run(ast);res=Resolver(g,a.pointer_size,overrides(a.overrides)).all()
 out={"schema_version":1,"target":{"pointer_size":a.pointer_size,"endianness":"little","integer_model":"Windows LLP64"},"summary":{"records":len(g.records),"typedefs":len(g.typedefs),"enums":len(g.enums),"functions":len(g.functions),"warnings":len(res["warnings"])},"declarations":{"records":dict(sorted(g.records.items())),"typedefs":dict(sorted(g.typedefs.items())),"enums":dict(sorted(g.enums.items())),"functions":dict(sorted(g.functions.items()))},"resolved":res}
 text=json.dumps(out,ensure_ascii=False,indent=2 if a.pretty else None,sort_keys=a.pretty)
 if a.output=="-":print(text)
 else:Path(a.output).write_text(text+"\n",encoding="utf-8")
 for w in res["warnings"]:print(f"warning: {w['path']}: {w['type']}: {w['message']}",file=sys.stderr)
 return 2 if a.fail_on_warning and res["warnings"] else 0
if __name__=="__main__":raise SystemExit(main())
