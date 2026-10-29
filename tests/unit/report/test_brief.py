from __future__ import annotations

import importlib.util
from pathlib import Path

from aitrace.report.brief import APPRAISAL_CHAPTERS, build_brief_document
from aitrace.report.i18n import t
from aitrace.report.layout import Block, Document, Heading, Para, Table, build_document

_SPEC = importlib.util.spec_from_file_location("report_sample", Path(__file__).with_name("sample.py"))
assert _SPEC is not None and _SPEC.loader is not None
sample = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(sample)

KO_ORDER = [
    "결론 요약",
    "언제 사용하였는가",
    "누가 입력하였는가",
    "무엇을 시켰는가",
    "무엇이 만들어지고 나갔는가",
    "증거로 사용할 때 확인할 사항",
    "용어 풀이",
    "상세 자료 찾는 법",
]


def _chapter(doc: Document, title: str) -> list[Block]:
    start = next(
        i for i, b in enumerate(doc.blocks) if isinstance(b, Heading) and b.level == 1 and b.text == title
    )
    out: list[Block] = []
    for block in doc.blocks[start + 1 :]:
        if isinstance(block, Heading) and block.level == 1:
            break
        out.append(block)
    return out


def _tables(blocks: list[Block]) -> list[Table]:
    return [b for b in blocks if isinstance(b, Table)]


def _answers(table: Table) -> dict[str, str]:
    return {row[0]: row[1] for row in table.rows}


def _text(doc: Document) -> str:
    parts = [doc.title, doc.notice, *(f"{k} {v}" for k, v in doc.cover)]
    for block in doc.blocks:
        if isinstance(block, (Heading, Para)):
            parts.append(block.text)
        else:
            parts += [*block.headers, *(cell for row in block.rows for cell in row)]
    return "\n".join(parts)


def test_chapters_answer_the_reviewer_questions_in_order() -> None:
    doc = build_brief_document(sample.make_model("ko"))
    assert [b.text for b in doc.blocks if isinstance(b, Heading) and b.level == 1] == KO_ORDER
    assert doc.title == "AI 사용 흔적 분석 결과 검토용 요약서"


def test_counts_come_from_the_question_statistics() -> None:
    model = sample.make_model("ko")
    stats = model.question_stats
    doc = build_brief_document(model)
    answers = _answers(_tables(_chapter(doc, "결론 요약"))[0])
    assert answers["사람이 직접 입력한 지시는 몇 건인가"].startswith(f"{stats['human']:,}건.")
    split = _tables(_chapter(doc, "누가 입력하였는가"))[0]
    counts = [int(row[2].replace(",", "")) for row in split.rows]
    assert counts[-1] == stats["raw"]
    assert sum(counts[:-1]) == stats["raw"]


def test_flagged_inputs_are_listed_with_number_time_and_device() -> None:
    model = sample.make_model("ko")
    target = model.questions[0]
    target["topics"] = ["TASK-EXFIL"]
    model.question_stats["topics"] = {"TASK-EXFIL": 1}
    flagged = _tables(_chapter(build_brief_document(model), "무엇을 시켰는가"))[-1]
    assert flagged.rows[0][0].startswith(f"#{target['no']}\n")
    assert str(target["machine"]) in flagged.rows[0][0]
    assert flagged.rows[0][1] == "유출·반출"


def test_without_flagged_inputs_no_list_is_drawn() -> None:
    model = sample.make_model("ko")
    for q in model.questions:
        q["topics"] = []
    model.question_stats["topics"] = {}
    blocks = _chapter(build_brief_document(model), "무엇을 시켰는가")
    assert _tables(blocks) == []
    assert t("brief.a.no_flagged", "ko") in [b.text for b in blocks if isinstance(b, Para)]


def test_empty_case_says_nothing_was_found() -> None:
    model = sample.make_model("ko")
    model.questions = []
    model.question_stats = {}
    model.ai_tools = []
    model.generated_files = []
    answers = _answers(_tables(_chapter(build_brief_document(model), "결론 요약"))[0])
    assert answers["AI 도구를 사용하였는가"] == t("brief.a.not_used", "ko")
    assert answers["어느 기기에서 사용하였는가"] == t("brief.a.no_devices", "ko")
    assert answers["AI가 만든 결과물이 있는가"] == t("brief.a.no_generated", "ko")


def test_references_point_at_the_matching_appraisal_chapters() -> None:
    model = sample.make_model("ko")
    chapters = [b.text for b in build_document(model).blocks if isinstance(b, Heading) and b.level == 1]
    for name, number in APPRAISAL_CHAPTERS.items():
        assert chapters[number - 1] == t(f"chapter.{name}", "ko")


def test_tables_stay_narrow_and_text_has_no_banned_words() -> None:
    for lang in ("ko", "en"):
        doc = build_brief_document(sample.make_model(lang))
        assert max(len(table.headers) for table in _tables(doc.blocks)) <= 4
        assert sample.find_banned(_text(doc)) == []


def test_flagged_sentences_come_before_pasted_logs() -> None:
    model = sample.make_model("ko")
    first, second = model.questions[0], model.questions[1]
    first["text"] = "PS C:\\Users> scp secret.zip remote:/tmp"
    second["text"] = "이 자료를 외부 메일로 보내 줘"
    for q in (first, second):
        q["topics"] = ["TASK-EXFIL"]
    flagged = _tables(_chapter(build_brief_document(model), "무엇을 시켰는가"))[-1]
    assert [row[2] for row in flagged.rows[:2]] == [
        "이 자료를 외부 메일로 보내 줘",
        "PS C:\\Users> scp secret.zip remote:/tmp",
    ]


def test_the_same_flagged_sentence_is_listed_once_with_its_count() -> None:
    model = sample.make_model("ko")
    for q in model.questions[:2]:
        q["text"] = "어제 자료는 내가 지웠어, 유출 방지 차원"
        q["topics"] = ["TASK-EXFIL"]
    flagged = _tables(_chapter(build_brief_document(model), "무엇을 시켰는가"))[-1]
    assert [row[2] for row in flagged.rows].count("어제 자료는 내가 지웠어, 유출 방지 차원") == 1
    assert flagged.rows[0][0].endswith("같은 내용 2회")


def test_key_facts_list_masked_inputs_by_kind() -> None:
    model = sample.make_model("ko")
    q = model.questions[0]
    q["text"], q["facts"] = "고객 010-1234-5678 에게 연락했고 기록은 지웠어", ["deletion", "personal"]
    model.question_stats["facts"] = {"document": 0, "deletion": 1, "personal": 1, "credential": 0}
    blocks = _chapter(build_brief_document(model), "무엇을 시켰는가")
    heads = [b.text for b in blocks if isinstance(b, Heading)]
    assert "주요 입력 사실" in heads
    assert heads.index("삭제했다는 표현이 든 입력") < heads.index("전화번호·주민등록번호·이메일이 든 입력")
    cells = " ".join(c for table in _tables(blocks) for row in table.rows for c in row)
    assert "010-****-****" in cells and "1234-5678" not in cells
    answers = _answers(_tables(_chapter(build_brief_document(model), "결론 요약"))[0])
    assert (
        "삭제했다는 표현이 든 입력 1건"
        in answers["문서 첨부, 삭제 표현, 개인정보, 인증정보가 담긴 입력이 있는가"]
    )


def test_no_key_facts_gives_a_none_line() -> None:
    model = sample.make_model("ko")
    for q in model.questions:
        q["facts"] = []
    model.question_stats["facts"] = {}
    blocks = _chapter(build_brief_document(model), "무엇을 시켰는가")
    assert t("brief.a.no_facts", "ko") in [b.text for b in blocks if isinstance(b, Para)]
