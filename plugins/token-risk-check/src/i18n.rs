//! Minimal 8-locale strings for user-facing plugin output.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Locale {
    En,
    Fr,
    Es,
    Pt,
    De,
    Ru,
    Ja,
    Zh,
}

impl Locale {
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "fr" | "fra" | "french" => Self::Fr,
            "es" | "spa" | "spanish" => Self::Es,
            "pt" | "por" | "portuguese" | "pt-br" | "pt_br" => Self::Pt,
            "de" | "deu" | "german" => Self::De,
            "ru" | "rus" | "russian" => Self::Ru,
            "ja" | "jpn" | "japanese" => Self::Ja,
            "zh" | "zho" | "chinese" | "zh-cn" | "zh_cn" => Self::Zh,
            _ => Self::En,
        }
    }
}

pub fn risk_label(locale: Locale, level: &str) -> &'static str {
    match (locale, level) {
        (Locale::Fr, "green") => "VERT",
        (Locale::Fr, "amber") => "ORANGE",
        (Locale::Fr, "red") => "ROUGE",
        (Locale::Es, "green") => "VERDE",
        (Locale::Es, "amber") => "AMBAR",
        (Locale::Es, "red") => "ROJO",
        (Locale::Pt, "green") => "VERDE",
        (Locale::Pt, "amber") => "AMARELO",
        (Locale::Pt, "red") => "VERMELHO",
        (Locale::De, "green") => "GRUEN",
        (Locale::De, "amber") => "GELB",
        (Locale::De, "red") => "ROT",
        (Locale::Ru, "green") => "ZELENYJ",
        (Locale::Ru, "amber") => "ZHELTYJ",
        (Locale::Ru, "red") => "KRASNYJ",
        (Locale::Ja, "green") => "MIDORI",
        (Locale::Ja, "amber") => "KIIRO",
        (Locale::Ja, "red") => "AKA",
        (Locale::Zh, "green") => "LU",
        (Locale::Zh, "amber") => "CHENG",
        (Locale::Zh, "red") => "HONG",
        (_, "green") => "GREEN",
        (_, "amber") => "AMBER",
        (_, "red") => "RED",
        _ => "UNKNOWN",
    }
}

pub fn refused_inject(locale: Locale) -> &'static str {
    match locale {
        Locale::Fr => "Refuse: consigne adversariale detectee (fail-closed).",
        Locale::Es => "Rechazado: instruccion adversaria detectada (fail-closed).",
        Locale::Pt => "Recusado: instrucao adversaria detectada (fail-closed).",
        Locale::De => "Abgelehnt: adversariale Anweisung erkannt (fail-closed).",
        Locale::Ru => "Otkaz: adversarial'naja instrukcija (fail-closed).",
        Locale::Ja => "Kyozetsu: tekitaitekina shiji (fail-closed).",
        Locale::Zh => "Jujue: jiancedao didui zhiling (fail-closed).",
        Locale::En => "Refused: adversarial instruction detected (fail-closed).",
    }
}
