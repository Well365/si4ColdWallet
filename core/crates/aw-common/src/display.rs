//! 与链无关的审查结果（P2 通用显示模型，见 docs/06）。
//!
//! Rust 决定"显示什么、警告什么"，Swift 只负责按行渲染：签名机界面不必为每条链各写一套，
//! 也就不会出现"某条链的界面漏显示了某个字段"这类问题。

use crate::json::Json;

/// 一行的显示方式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    /// 普通文本
    Text,
    /// 地址：等宽字体、分组显示，便于逐段核对
    Address,
    /// 金额：醒目显示
    Amount,
    /// 原始数据（十六进制等）：等宽、可折叠
    Data,
}

/// 警告级别
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// 提示
    Info,
    /// 需要用户留意
    Caution,
    /// 高风险：界面要求额外确认
    Danger,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub label: String,
    pub value: String,
    pub style: Style,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    pub level: Level,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Display {
    /// 链名，如 "Ethereum"、"BNB Smart Chain"
    pub chain: String,
    /// 网络说明，如 "主网"、"Sepolia 测试网"
    pub network: String,
    /// 一句话标题，如 "发送 ETH"、"代币授权"
    pub title: String,
    pub rows: Vec<Row>,
    pub warnings: Vec<Warning>,
}

impl Display {
    pub fn new(chain: &str, network: &str, title: &str) -> Self {
        Self {
            chain: chain.to_owned(),
            network: network.to_owned(),
            title: title.to_owned(),
            rows: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn row(&mut self, label: &str, value: impl Into<String>, style: Style) {
        self.rows.push(Row {
            label: label.to_owned(),
            value: value.into(),
            style,
        });
    }

    pub fn warn(&mut self, level: Level, text: impl Into<String>) {
        self.warnings.push(Warning {
            level,
            text: text.into(),
        });
    }

    /// 是否含高风险警告（界面据此要求额外确认）
    pub fn has_danger(&self) -> bool {
        self.warnings.iter().any(|w| w.level == Level::Danger)
    }

    pub fn to_json(&self) -> Json {
        let rows = self
            .rows
            .iter()
            .map(|r| {
                Json::obj(vec![
                    ("label", Json::str(r.label.as_str())),
                    ("value", Json::str(r.value.as_str())),
                    ("style", Json::str(style_name(r.style))),
                ])
            })
            .collect();
        let warnings = self
            .warnings
            .iter()
            .map(|w| {
                Json::obj(vec![
                    ("level", Json::str(level_name(w.level))),
                    ("text", Json::str(w.text.as_str())),
                ])
            })
            .collect();
        Json::obj(vec![
            ("chain", Json::str(self.chain.as_str())),
            ("network", Json::str(self.network.as_str())),
            ("title", Json::str(self.title.as_str())),
            ("rows", Json::Array(rows)),
            ("warnings", Json::Array(warnings)),
        ])
    }
}

fn style_name(s: Style) -> &'static str {
    match s {
        Style::Text => "text",
        Style::Address => "address",
        Style::Amount => "amount",
        Style::Data => "data",
    }
}

fn level_name(l: Level) -> &'static str {
    match l {
        Level::Info => "info",
        Level::Caution => "caution",
        Level::Danger => "danger",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_shape_is_stable() {
        let mut d = Display::new("Ethereum", "主网", "发送 ETH");
        d.row("金额", "1.5 ETH", Style::Amount);
        d.warn(Level::Danger, "无限额授权");
        assert!(d.has_danger());
        assert_eq!(
            d.to_json().to_string_compact(),
            r#"{"chain":"Ethereum","network":"主网","title":"发送 ETH","rows":[{"label":"金额","value":"1.5 ETH","style":"amount"}],"warnings":[{"level":"danger","text":"无限额授权"}]}"#
        );
    }
}
