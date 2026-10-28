"""In-memory, tenant-authorized export of an unreviewed host AI answer."""
import json
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field, StrictStr
from app.modules.hunting_reports import (build_ai_markdown, build_ai_pdf, build_group_ai_markdown, build_group_ai_pdf, validate_ai_answer)


class AIReportIn(BaseModel):
    answer: StrictStr = Field(min_length=1, max_length=100_000)


def register_ai_report_routes(app, *, get_user, get_db, resolve_company, hunting_store, write_audit):
    router = APIRouter()

    class CorrelationIn(BaseModel):
        result_ids: list[StrictStr] = Field(min_length=1, max_length=20)

    @router.post("/api/threat-hunting/correlations")
    def correlate(payload: CorrelationIn, company_id: int,
                  user=Depends(get_user), db=Depends(get_db)):
        from app.modules.hunting_correlation import correlate_results, CorrelationLimitError
        company = resolve_company(user, db, company_id)
        base = hunting_store()
        try:
            result = correlate_results(base, base / "keys", company.id, payload.result_ids)
        except KeyError as exc:
            raise HTTPException(404, "Result not found") from exc
        except CorrelationLimitError as exc:
            raise HTTPException(413, "Correlation input budget exceeded (20 archives, 256 MiB, 200000 rows)") from exc
        except (ValueError, OSError) as exc:
            raise HTTPException(422, "Invalid IDs or evidence integrity verification failed") from exc
        write_audit(db, user, "hunting_correlation", f"results={len(payload.result_ids)}", company.id)
        db.commit()
        return Response(json.dumps(result, ensure_ascii=False),
                        media_type="application/json", headers={"Cache-Control": "no-store"})


    class GroupAIReportIn(BaseModel):
        result_ids: list[StrictStr] = Field(min_length=2, max_length=20)
        answer: StrictStr = Field(min_length=1, max_length=100_000)

    @router.post("/api/threat-hunting/correlations/ai-report")
    def export_group_ai_report(company_id: int, format: Literal["md", "pdf"],
                               payload: GroupAIReportIn, user=Depends(get_user), db=Depends(get_db)):
        from app.modules.hunting_correlation import correlate_results, CorrelationLimitError
        from app.modules.hunting_results import get_result
        company = resolve_company(user, db, company_id)
        try:
            correlation = correlate_results(hunting_store(), hunting_store() / "keys", company.id, payload.result_ids)
            items = [get_result(hunting_store(), company.id, rid) for rid in correlation["result_ids"]]
            if any(item is None for item in items):
                raise KeyError("Result not found")
            data = (build_group_ai_markdown if format == "md" else build_group_ai_pdf)(company.id, items, correlation, payload.answer)
        except KeyError as exc:
            raise HTTPException(404, "Result not found") from exc
        except CorrelationLimitError as exc:
            raise HTTPException(413, "Correlation input budget exceeded") from exc
        except (ValueError, OSError) as exc:
            raise HTTPException(422, "Invalid IDs, AI answer, or evidence integrity verification failed") from exc
        write_audit(db, user, "hunting_group_ai_report_export", f"results={len(items)}; format={format}", company.id)
        db.commit()
        return Response(data, media_type="text/markdown" if format == "md" else "application/pdf", headers={
            "Content-Disposition": f'attachment; filename="ai-group-report.{format}"',
            "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})

    @router.post("/api/threat-hunting/results/{result_id}/ai-report")
    def export_ai_report(result_id: str, company_id: int, format: Literal["md", "pdf"],
                         payload: AIReportIn, user=Depends(get_user), db=Depends(get_db)):
        from app.modules.hunting_results import get_result, analyze_result
        company = resolve_company(user, db, company_id)
        try:
            validate_ai_answer(payload.answer)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        base = hunting_store()
        item = get_result(base, company.id, result_id)
        if item is None:
            raise HTTPException(404, "Result not found")
        # analyze_result hashes this exact archive and validates/decrypts its container.
        # Unlike tenant-wide integrity scans, this cannot omit older results.
        try:
            analysis = analyze_result(base, base / "keys", company.id, result_id)
        except KeyError as exc:
            raise HTTPException(404, "Result not found") from exc
        except (ValueError, OSError) as exc:
            raise HTTPException(409, "Evidence integrity/analysis verification failed") from exc
        # Summary hostnames may contain /etc/hosts or DNS aliases, not host identities.
        # This route is scoped to one archive; it never claims group investigation.
        try:
            data = (build_ai_markdown if format == "md" else build_ai_pdf)(company.id, item, analysis, payload.answer)
        except (ValueError, OSError) as exc:
            raise HTTPException(422, "Unable to render AI report (Unicode font required for PDF)") from exc
        write_audit(db, user, "hunting_ai_report_export", f"result={item['id']}; format={format}", company.id)
        db.commit()
        # Never persist answers or report files. Safe fixed filename avoids header injection.
        return Response(data, media_type="text/markdown" if format == "md" else "application/pdf", headers={
            "Content-Disposition": f'attachment; filename="ai-host-report.{format}"',
            "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})

    app.include_router(router)
