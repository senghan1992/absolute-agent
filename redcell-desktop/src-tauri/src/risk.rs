//! 파괴적 지시문 가드레일 — 자유 문장 지시를 평가해 위험도를 매긴다.
//!
//! ## 가이드라인 (등급 기준)
//!
//! | 등급 | 기준 | 처리 |
//! |---|---|---|---|
//! | Safe | 읽기·조회·추출·정리·리포트·진단 (상태 불변) | 진행 |
//! | Caution | 모호한 실행·대량 조회 (부하 가능, 상태 불변) | 진행 + 주의 노트 |
//! | High | 상태 변경 (파일·설정·서비스·배포·업로드·쓰기 쿼리·공격 실행) | 모달 동의 필요 |
//! | Critical | 데이터 손실·시스템 중단·비가역 파괴 (삭제·드롭·포맷·셧다운) | 모달 동의 필요 (강한 경고) |
//!
//! 모달에는 등급·근거·예상 영향·복구 가능 여부·서비스 중단 가능성을 표시하고,
//! 체크박스 확인 후 세션 동의를 받아 재시도한다. 미동의면 실행하지 않는다.
//!
//! 오탐 방지: 짧은 영문 토큰(rm 등)은 단어 경계로 매칭하고, 부정 표현
//! ("~하지 마", "don't", "without" 등) window 안의 매칭은 제외한다.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Safe,
    Caution,
    High,
    Critical,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Safe => "safe",
            RiskLevel::Caution => "caution",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
        }
    }
    pub fn label_ko(&self) -> &'static str {
        match self {
            RiskLevel::Safe => "안전",
            RiskLevel::Caution => "주의",
            RiskLevel::High => "위험",
            RiskLevel::Critical => "치명",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Concern {
    pub id: &'static str,
    pub matched: String,
    pub title: String,
    pub impact: String,
    pub reversible: bool,
    pub level: RiskLevel,
}

#[derive(Debug, Clone, Serialize)]
pub struct RiskReport {
    pub level: RiskLevel,
    pub level_ko: String,
    pub concerns: Vec<Concern>,
    pub summary: String,
    pub shutdown_risk: bool,
    pub data_loss_risk: bool,
    pub irreversible: bool,
    pub needs_consent: bool,
}

struct Rule {
    id: &'static str,
    level: RiskLevel,
    /// 매칭 패턴 (소문자 기준, 긴 구문 우선).
    pats: &'static [&'static str],
    title: &'static str,
    impact: &'static str,
    reversible: bool,
    shutdown: bool,
    data_loss: bool,
}

const RULES: &[Rule] = &[
    Rule { id: "db-drop", level: RiskLevel::Critical,
        pats: &["drop table", "drop database", "truncate table", "delete from", "테이블 삭제", "테이블 드롭", "테이블 날려", "db 삭제", "db 날려", "db 지워", "데이터베이스 삭제", "데이터베이스 날려", "디비 날려", "디비 삭제"],
        title: "데이터베이스 삭제", impact: "데이터 영구 손실 — 백업 없으면 복구 불가", reversible: false, shutdown: false, data_loss: true },
    Rule { id: "os-destroy", level: RiskLevel::Critical,
        pats: &["rm -rf /", "rm -rf ~", "mkfs", "dd if=", "포맷해", "포멧해", "디스크 밀어", "디스크 날려", "공장 초기화", "팩토리 리셋", "factory reset"],
        title: "OS·디스크 파괴", impact: "시스템 전체 손실 — 재설치 필요", reversible: false, shutdown: true, data_loss: true },
    Rule { id: "shutdown", level: RiskLevel::Critical,
        pats: &["shutdown", "poweroff", "halt", "reboot", "셧다운", "재부팅", "리부팅", "전원 꺼", "전원 차단", "전원꺼"],
        title: "시스템 중단·재기동", impact: "서비스 전체 중단 (재기동 전까지)", reversible: true, shutdown: true, data_loss: false },
    Rule { id: "kill-all", level: RiskLevel::Critical,
        pats: &["kill -9", "killall", "pkill", "전체 프로세스 죽", "전체 프로세스 종료", "프로세스 다 죽", "전부 죽여"],
        title: "프로세스 전체 종료", impact: "실행 중 서비스 전체 중단", reversible: true, shutdown: true, data_loss: false },
    Rule { id: "file-delete", level: RiskLevel::High,
        pats: &["rm ", "rm\t", "rm", "del /", "삭제", "지워", "지우", "제거", "없애", "폴더 삭제", "디렉터리 삭제", "delete file", "remove file"],
        title: "파일 삭제", impact: "파일 손실 — 휴지통·백업 없으면 복구 불가", reversible: false, shutdown: false, data_loss: true },
    Rule { id: "service-control", level: RiskLevel::High,
        pats: &["systemctl stop", "systemctl restart", "service 재시작", "서비스 재시작", "서비스 중단", "서비스 중지", "서버 재시작", "도커 재시작", "docker restart", "docker stop", "컨테이너 삭제", "docker rm", "nginx 재시작", "재시작해줘"],
        title: "서비스 제어 (중단·재시작)", impact: "해당 서비스 순간 중단", reversible: true, shutdown: false, data_loss: false },
    Rule { id: "config-change", level: RiskLevel::High,
        pats: &["설정 바꿔", "설정 수정", "설정 적용", "config 수정", "방화벽 열어", "방화벽 막아", "iptables", "포트 열어", "포트 닫아", "포트 막아", "dns 바꿔", "dns 변경", "hosts 수정"],
        title: "설정 변경", impact: "동작 변경 — 오설정 시 장애 가능", reversible: true, shutdown: false, data_loss: false },
    Rule { id: "deploy", level: RiskLevel::High,
        pats: &["배포해", "deploy", "롤아웃", "rollout", "릴리스해", "운영 반영"],
        title: "배포·운영 반영", impact: "운영 환경 변경 — 롤백 필요할 수 있음", reversible: true, shutdown: false, data_loss: false },
    Rule { id: "db-write", level: RiskLevel::High,
        pats: &["update 문", "delete 문", "insert 문", "update문", "db 넣어", "db 바꿔", "db 수정", "디비 넣어", "디비 수정", "쿼리 날려", "쿼리 실행해", "update ", "insert into"],
        title: "DB 쓰기", impact: "데이터 변경 — 오기입 시 정합성 훼손", reversible: true, shutdown: false, data_loss: false },
    Rule { id: "upload", level: RiskLevel::High,
        pats: &["업로드해", "서버에 올려", "대상에 올려", "거기에 올려", "파일 올려", "파일 넣어줘", "웹셸 올려", "webshell"],
        title: "파일 업로드 (대상에 쓰기)", impact: "대상에 파일 생성 — 악용 시 거점화", reversible: true, shutdown: false, data_loss: false },
    Rule { id: "overwrite", level: RiskLevel::High,
        pats: &["덮어써", "덮어씌워", "overwrite", "덮어쓰기"],
        title: "덮어쓰기", impact: "기존 내용 손실", reversible: false, shutdown: false, data_loss: true },
    Rule { id: "account", level: RiskLevel::High,
        pats: &["비밀번호 바꿔", "비밀번호 변경", "비번 바꿔", "계정 만들어", "계정 삭제", "계정 추가", "chmod", "chown", "권한 바꿔", "권한 수정"],
        title: "계정·권한 변경", impact: "접근 통제 변경 — 잠금·노출 가능", reversible: true, shutdown: false, data_loss: false },
    Rule { id: "exploit-run", level: RiskLevel::High,
        pats: &["익스플로잇 실행", "익스플로잇 날려", "페이로드 실행", "페이로드 날려", "공격 실행", "공격해봐", "metasploit", "msfconsole", "터뜨려", "뚫어봐"],
        title: "공격 페이로드 실행", impact: "서비스 충돌·장애 가능 (인가 대상 한정)", reversible: true, shutdown: false, data_loss: false },
    Rule { id: "stress-test", level: RiskLevel::High,
        pats: &["스트레스 테스트", "부하 테스트", "dos 테스트", "ddos", "과부하 걸어", "트래픽 폭탄"],
        title: "부하·DoS 테스트", impact: "서비스 응답 저하·중단 가능", reversible: true, shutdown: false, data_loss: false },
    Rule { id: "mass-scan", level: RiskLevel::Caution,
        pats: &["전체 스캔", "대량 스캔", "풀스캔", "전수 스캔", "대량 조회", "전수 조회"],
        title: "대량 스캔·조회", impact: "대상 부하 가능 (상태 불변)", reversible: true, shutdown: false, data_loss: false },
];

/// 부정 표현 — 앞(영문) / 뒤(국문) window 안에 있으면 매칭 제외.
const NEG_BEFORE: &[&str] = &["don't", "do not", "without", "never", "not ", "no ", " 말고"];
const NEG_AFTER: &[&str] = &["하지", " 말고", " 금지", " 없이", " 마라", " 말아", "안마", "지마", "된", "될"];

/// 패턴 매칭 — 짧은 영문 토큰은 단어 경계 요구, 그 외 부분 일치.
/// 반환: 매칭된 패턴 (부정 window·엄격 끝 경계 제외 후 첫 매칭).
fn match_rule(text_low: &str, rule: &Rule) -> Option<String> {
    for pat in rule.pats {
        let short = pat.len() <= 4 && pat.bytes().all(|b| b.is_ascii_alphanumeric() || b == b' ' || b == b'\t');
        let mut from = 0;
        while let Some(i) = text_low[from..].find(pat) {
            let s = from + i;
            let e = s + pat.len();
            let mut ok = true;
            if short {
                let before_ok = s == 0 || !text_low.as_bytes()[s - 1].is_ascii_alphanumeric();
                let after_ok = e >= text_low.len() || !text_low.as_bytes()[e].is_ascii_alphanumeric();
                ok = before_ok && after_ok;
            }
            // "rm -rf /" 는 뒤에 경로가 이어지면 범위 삭제(High 규칙에 양보).
            if ok && *pat == "rm -rf /" && e < text_low.len() {
                let c = text_low.as_bytes()[e];
                if c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-' | b'~') {
                    ok = false;
                }
            }
            if ok && !negated(text_low, s, e) {
                return Some(pat.to_string());
            }
            from = e;
        }
    }
    None
}

fn negated(text: &str, s: usize, e: usize) -> bool {
    // 앞 최대 12자 (문자 경계 보존).
    let mut bs = s.min(text.len());
    let mut n = 0;
    while bs > 0 && n < 12 {
        bs -= 1;
        while bs > 0 && !text.is_char_boundary(bs) {
            bs -= 1;
        }
        n += 1;
    }
    let before = &text[bs..s.min(text.len())];
    // 뒤 최대 12자.
    let mut ae = e.min(text.len());
    n = 0;
    while ae < text.len() && n < 12 {
        ae += 1;
        while ae < text.len() && !text.is_char_boundary(ae) {
            ae += 1;
        }
        n += 1;
    }
    let after = &text[e.min(text.len())..ae];
    NEG_BEFORE.iter().any(|x| before.contains(x)) || NEG_AFTER.iter().any(|x| after.contains(x))
}

/// 지시문 평가 — 매칭된 규칙 중 최고 등급 + 근거 목록.
pub fn assess(instruction: &str) -> RiskReport {
    let low = instruction.to_lowercase();
    let mut concerns: Vec<Concern> = Vec::new();
    let mut level = RiskLevel::Safe;
    for rule in RULES {
        if let Some(matched) = match_rule(&low, rule) {
            if rule.level > level {
                level = rule.level;
            }
            concerns.push(Concern {
                id: rule.id,
                matched,
                title: rule.title.to_string(),
                impact: rule.impact.to_string(),
                reversible: rule.reversible,
                level: rule.level,
            });
            if concerns.len() >= 6 {
                break;
            }
        }
    }
    // 등급순 정렬 (치명 우선).
    concerns.sort_by(|a, b| b.level.cmp(&a.level));
    let shutdown_risk = concerns.iter().any(|c| RULES.iter().any(|r| r.id == c.id && r.shutdown));
    let data_loss_risk = concerns.iter().any(|c| RULES.iter().any(|r| r.id == c.id && r.data_loss));
    let irreversible = concerns.iter().any(|c| !c.reversible);
    let summary = match level {
        RiskLevel::Safe => "읽기·조회 범위로 판단됨 — 추가 확인 없이 진행합니다.".to_string(),
        RiskLevel::Caution => format!("주의 {}건 — 상태 변경은 없으나 부하 가능.", concerns.len()),
        RiskLevel::High => format!("위험 {}건 — 상태 변경 포함, 동의 후 진행.", concerns.len()),
        RiskLevel::Critical => "치명 — 데이터 손실·시스템 중단 가능, 동의 후 진행.".to_string(),
    };
    RiskReport {
        level_ko: level.label_ko().to_string(),
        needs_consent: level >= RiskLevel::High,
        level,
        concerns,
        summary,
        shutdown_risk,
        data_loss_risk,
        irreversible,
    }
}

/// 실행 게이트 — 동의 필요 시 CONSENT_REQUIRED:<json> 에러.
pub const CONSENT_MARKER: &str = "CONSENT_REQUIRED:";

pub fn gate_instruction(goal: &str, danger_consent: bool) -> Result<RiskReport, String> {
    let rep = assess(goal);
    if rep.needs_consent && !danger_consent {
        let body = serde_json::to_string(&rep).unwrap_or_else(|_| "{\"level\":\"high\"}".to_string());
        return Err(format!("{CONSENT_MARKER}{body}"));
    }
    Ok(rep)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lvl(t: &str) -> RiskLevel {
        assess(t).level
    }

    #[test]
    fn safe_reads_pass() {
        for t in [
            "하반기 합격자 목록을 파일로 뽑아줘",
            "이 서비스의 보안 진단을 해줘",
            "헤더 보여줘",
            "show me the login page",
            "리포트로 정리해줘",
            "",
        ] {
            assert_eq!(lvl(t), RiskLevel::Safe, "{t}");
        }
    }

    #[test]
    fn destructive_ko_detected() {
        assert_eq!(lvl("로그 파일 삭제해줘"), RiskLevel::High);
        assert_eq!(lvl("DB 테이블 날려봐"), RiskLevel::Critical);
        assert_eq!(lvl("서버 재부팅해줘"), RiskLevel::Critical);
        assert_eq!(lvl("설정 바꿔서 적용해줘"), RiskLevel::High);
        assert_eq!(lvl("새 버전 배포해줘"), RiskLevel::High);
        assert_eq!(lvl("웹셸 올려줘"), RiskLevel::High);
        assert_eq!(lvl("SQLi 페이로드 날려봐"), RiskLevel::High);
        assert_eq!(lvl("전체 스캔 돌려줘"), RiskLevel::Caution);
    }

    #[test]
    fn destructive_en_detected() {
        assert_eq!(lvl("drop table users"), RiskLevel::Critical);
        assert_eq!(lvl("please shutdown the server"), RiskLevel::Critical);
        assert_eq!(lvl("rm -rf /tmp/junk"), RiskLevel::High);
        assert_eq!(lvl("rm -rf /"), RiskLevel::Critical);
        assert_eq!(lvl("deploy the new build"), RiskLevel::High);
        // 짧은 토큰 단어 경계 — format 안의 rm 등은 오탐 금지.
        assert_eq!(lvl("show the platform info"), RiskLevel::Safe);
        assert_eq!(lvl("perform the check"), RiskLevel::Safe);
    }

    #[test]
    fn negation_skips() {
        assert_eq!(lvl("삭제하지 말고 조회만 해줘"), RiskLevel::Safe);
        assert_eq!(lvl("don't delete file x, just read"), RiskLevel::Safe);
        assert_eq!(lvl("재부팅 없이 확인해줘"), RiskLevel::Safe);
        assert_eq!(lvl("삭제된 파일 복구해줘"), RiskLevel::Safe);
    }

    #[test]
    fn flags_and_gate() {
        let r = assess("서버 셧다운해줘");
        assert!(r.shutdown_risk && r.needs_consent);
        let r2 = assess("drop table t");
        assert!(r2.data_loss_risk && r2.irreversible);
        assert!(gate_instruction("파일 지워줘", false).is_err());
        assert!(gate_instruction("파일 지워줘", true).is_ok());
        assert!(gate_instruction("조회해줘", false).is_ok());
        let e = gate_instruction("rm -rf /", false).unwrap_err();
        assert!(e.starts_with(CONSENT_MARKER));
        let body: serde_json::Value = serde_json::from_str(e.trim_start_matches(CONSENT_MARKER)).unwrap();
        assert_eq!(body["level"], "critical");
    }
}
