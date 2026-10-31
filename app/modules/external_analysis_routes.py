"""Tenant-scoped advisory external analysis API."""
from datetime import datetime, timedelta
import json, os, uuid
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from app.database import ExternalAnalysisJob
from app.modules.external_analysis import run_aift, PROFILES, ARTIFACTS
class CreateJob(BaseModel):
 profile:str=Field(default="triage",max_length=32)
 selected_artifacts:list[str]=Field(default_factory=lambda:["summary","findings"],max_length=20)
 external_ai_opt_in:bool=False

def register_external_analysis_routes(app,*,get_user,get_db,resolve_company,hunting_store,write_audit):
 router=APIRouter()
 def public(j):
  return {"id":j.id,"company_id":j.company_id,"result_id":j.result_id,"status":j.status,"created_at":j.created_at,"started_at":j.started_at,"finished_at":j.finished_at,"provider":j.provider,"tool":j.tool,"version":j.version,"profile":j.profile,"input_sha256":j.input_sha256,"output_sha256":j.output_sha256,"selected_artifacts":json.loads(j.selected_artifacts or "[]"),"errors":json.loads(j.errors or "[]"),"gaps":json.loads(j.gaps or "[]"),"report_path":bool(j.report_path),"expires_at":j.expires_at,"external_ai_opt_in":bool(j.external_ai_opt_in)}
 def owned(db,company_id,job_id):
  j=db.query(ExternalAnalysisJob).filter_by(id=job_id,company_id=company_id).first()
  if not j: raise HTTPException(404,"Задание не найдено")
  return j
 @router.post("/api/threat-hunting/external-analysis/jobs")
 def create(company_id:int,result_id:str,payload:CreateJob,user=Depends(get_user),db=Depends(get_db)):
  company=resolve_company(user,db,company_id)
  if not payload.external_ai_opt_in: raise HTTPException(400,"Явное согласие на внешний AI обязательно")
  if payload.profile not in PROFILES or not payload.selected_artifacts or any(x not in ARTIFACTS for x in payload.selected_artifacts): raise HTTPException(422,"Недопустимый профиль или артефакт")
  from app.modules.hunting_results import get_result
  if not get_result(hunting_store(),company.id,result_id): raise HTTPException(404,"Импортированный результат не найден")
  old=db.query(ExternalAnalysisJob).filter_by(company_id=company.id,result_id=result_id,profile=payload.profile,status="queued").first()
  if old: return public(old)
  j=ExternalAnalysisJob(id=uuid.uuid4().hex,company_id=company.id,result_id=result_id,status="queued",provider="AIFT",tool="aift_cli",profile=payload.profile,selected_artifacts=json.dumps(list(dict.fromkeys(payload.selected_artifacts))),external_ai_opt_in=True,expires_at=datetime.utcnow()+timedelta(days=1))
  db.add(j); db.commit(); db.refresh(j); return public(j)
 @router.get("/api/threat-hunting/external-analysis/jobs")
 def listing(company_id:int,result_id:str|None=None,user=Depends(get_user),db=Depends(get_db)):
  company=resolve_company(user,db,company_id); q=db.query(ExternalAnalysisJob).filter_by(company_id=company.id)
  if result_id:q=q.filter_by(result_id=result_id)
  return {"items":[public(j) for j in q.order_by(ExternalAnalysisJob.created_at.desc()).limit(100).all()]}
 @router.get("/api/threat-hunting/external-analysis/jobs/{job_id}")
 def get(job_id:str,company_id:int,user=Depends(get_user),db=Depends(get_db)): return public(owned(db,resolve_company(user,db,company_id).id,job_id))
 @router.post("/api/threat-hunting/external-analysis/jobs/{job_id}/cancel")
 def cancel(job_id:str,company_id:int,user=Depends(get_user),db=Depends(get_db)):
  j=owned(db,resolve_company(user,db,company_id).id,job_id)
  if j.status in {"queued","running"}: j.status="cancelled"; j.finished_at=datetime.utcnow(); db.commit()
  return public(j)
 @router.get("/api/threat-hunting/external-analysis/jobs/{job_id}/report")
 def report(job_id:str,company_id:int,user=Depends(get_user),db=Depends(get_db)):
  j=owned(db,resolve_company(user,db,company_id).id,job_id)
  if j.status!="succeeded" or not j.report_path: raise HTTPException(409,"Отчёт ещё не готов")
  path=Path(j.report_path); root=Path(hunting_store())/"external-analysis-staging"/j.id
  if path.is_symlink() or root not in path.parents or not path.is_file(): raise HTTPException(404,"Отчёт недоступен")
  return FileResponse(path,media_type="application/json",filename=f"aift-{j.id}.json",headers={"Cache-Control":"no-store","X-Content-Type-Options":"nosniff"})
 @router.post("/api/threat-hunting/external-analysis/jobs/{job_id}/run")
 def run(job_id:str,company_id:int,user=Depends(get_user),db=Depends(get_db)):
  company=resolve_company(user,db,company_id); j=owned(db,company.id,job_id)
  if j.status!="queued": return public(j)
  from app.modules.hunting_results import analyze_result
  try:
   j.status="running"; j.started_at=datetime.utcnow(); db.commit()
   analysis=analyze_result(hunting_store(),hunting_store()/"keys",company.id,j.result_id)
   result=run_aift(hunting_store(),j.id,analysis,j.profile,json.loads(j.selected_artifacts or "[]"))
  except (ValueError,OSError,KeyError) as e: result={"status":"failed","error":str(e)}
  j.status=result.get("status","failed"); j.finished_at=datetime.utcnow(); j.input_sha256=result.get("input_sha256",""); j.output_sha256=result.get("output_sha256",""); j.version=result.get("version",""); j.errors=json.dumps([result["error"]],ensure_ascii=False) if result.get("error") else "[]"; j.report_path=result.get("report_path",""); j.gaps=json.dumps(["advisory output is not verified"] if j.status=="succeeded" else [],ensure_ascii=False); db.commit(); return public(j)
 app.include_router(router)
