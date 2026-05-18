from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel, field_validator
from typing import Optional

from core.database import get_db
from core.timezone import now_kst
from api.dependencies import get_current_user, get_current_active_admin
from models.user import User
from models.faq_question import FaqQuestion

router = APIRouter()


# ── Schemas ──────────────────────────────────────────────────

class FaqQuestionCreate(BaseModel):
    question: str

    @field_validator("question")
    @classmethod
    def question_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("질문 내용을 입력해주세요.")
        if len(v) > 500:
            raise ValueError("질문은 500자 이내로 작성해주세요.")
        return v


class FaqAnswerCreate(BaseModel):
    answer: str

    @field_validator("answer")
    @classmethod
    def answer_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("답변 내용을 입력해주세요.")
        return v


class FaqQuestionResponse(BaseModel):
    id: int
    user_email: str
    question: str
    answer: Optional[str] = None
    answered_at: Optional[str] = None
    created_at: str

    class Config:
        from_attributes = True


# ── Endpoints ────────────────────────────────────────────────

@router.get("", response_model=list[FaqQuestionResponse])
async def get_faq_questions(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """FAQ 질문 목록 조회 — 본인 질문만 (관리자는 전체)"""
    from models.user import UserRole

    if current_user.role == UserRole.ADMIN:
        questions = db.query(FaqQuestion).order_by(FaqQuestion.created_at.desc()).all()
    else:
        questions = (
            db.query(FaqQuestion)
            .filter(FaqQuestion.user_id == current_user.id)
            .order_by(FaqQuestion.created_at.desc())
            .all()
        )

    return [
        FaqQuestionResponse(
            id=q.id,
            user_email=q.user.email if q.user else "",
            question=q.question,
            answer=q.answer,
            answered_at=q.answered_at.isoformat() if q.answered_at else None,
            created_at=q.created_at.isoformat(),
        )
        for q in questions
    ]


@router.post("", response_model=FaqQuestionResponse)
async def create_faq_question(
    body: FaqQuestionCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """FAQ 질문 등록"""
    faq = FaqQuestion(
        user_id=current_user.id,
        question=body.question,
    )
    db.add(faq)
    db.commit()
    db.refresh(faq)
    return FaqQuestionResponse(
        id=faq.id,
        user_email=current_user.email,
        question=faq.question,
        answer=None,
        answered_at=None,
        created_at=faq.created_at.isoformat(),
    )


@router.put("/{question_id}/answer", response_model=FaqQuestionResponse)
async def answer_faq_question(
    question_id: int,
    body: FaqAnswerCreate,
    admin: User = Depends(get_current_active_admin),
    db: Session = Depends(get_db),
):
    """FAQ 질문에 답변 (관리자 전용)"""
    faq = db.query(FaqQuestion).filter(FaqQuestion.id == question_id).first()
    if not faq:
        raise HTTPException(status_code=404, detail="질문을 찾을 수 없습니다.")

    faq.answer = body.answer
    faq.answered_at = now_kst()
    db.commit()
    db.refresh(faq)

    return FaqQuestionResponse(
        id=faq.id,
        user_email=faq.user.email if faq.user else "",
        question=faq.question,
        answer=faq.answer,
        answered_at=faq.answered_at.isoformat() if faq.answered_at else None,
        created_at=faq.created_at.isoformat(),
    )


@router.delete("/{question_id}")
async def delete_faq_question(
    question_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """FAQ 질문 삭제 (본인 또는 관리자)"""
    from models.user import UserRole

    faq = db.query(FaqQuestion).filter(FaqQuestion.id == question_id).first()
    if not faq:
        raise HTTPException(status_code=404, detail="질문을 찾을 수 없습니다.")

    if current_user.role != UserRole.ADMIN and faq.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="삭제 권한이 없습니다.")

    db.delete(faq)
    db.commit()
    return {"message": "질문이 삭제되었습니다."}
