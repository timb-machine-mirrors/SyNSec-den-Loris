use std::fmt::{self, Formatter};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttrExpr {
    Number(usize),
    Literal(Vec<u8>),
    Attr {
        ident: String,
        name: AttrName,
    },
    BinOp {
        lhs: Box<AttrExpr>,
        op: AttrOp,
        rhs: Box<AttrExpr>,
    }
}

impl AttrExpr {
    pub fn lhs_ident(&self) -> Result<String, String> {
        match self {
            AttrExpr::BinOp {lhs, ..} => lhs.lhs_ident(),
            AttrExpr::Attr {ident, .. } => Ok(ident.clone()),
            _ => Err("no ident available".to_string()),
        }
    }

    pub fn writes_self(&self) -> bool {
        match self {
            AttrExpr::BinOp {op, lhs, ..} => {
                match op {
                    AttrOp::Assign |
                    AttrOp::AssignByAnd |
                    AttrOp::AssignByOr |
                    AttrOp::AssignByXor |
                    AttrOp::AssignByLsh |
                    AttrOp::AssignByRsh => lhs.writes_self(),
                    _ => false,
                }
            },
            AttrExpr::Attr {ident, ..} => ident == "self",
            _ => false,
        }
    }

    pub fn reads_ident(&self, ident_: &str) -> bool {
        match self {
            AttrExpr::BinOp {rhs, op, lhs} => {
                match op {
                    AttrOp::Assign => rhs.reads_ident(ident_),
                    _ => lhs.reads_ident(ident_) | rhs.reads_ident(ident_),
                }
            },
            AttrExpr::Attr {ident, ..} => ident == ident_,
            _ => false,
        }
    }

    pub fn writes_ident(&self, ident_: &str) -> bool {
        match self {
            AttrExpr::BinOp {op, lhs, .. } => {
                match op {
                    AttrOp::Assign |
                    AttrOp::AssignByAnd |
                    AttrOp::AssignByOr |
                    AttrOp::AssignByXor |
                    AttrOp::AssignByLsh |
                    AttrOp::AssignByRsh => lhs.writes_ident(ident_),
                    _ => false,
                }
            },
            AttrExpr::Attr {ident, ..} => ident == ident_,
            _ => false,
        }
    }

    pub fn updates_ident(&self, ident_: &str) -> bool {
        self.reads_ident(ident_) & self.writes_ident(ident_)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttrName {
    Value,
    Length,
    Reps,
}

impl fmt::Display for AttrName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            AttrName::Length => write!(f, "length"),
            AttrName::Value => write!(f, "value"),
            AttrName::Reps => write!(f, "reps"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttrOp {
    Assign,
    AssignByRsh,
    AssignByLsh,
    AssignByAnd,
    AssignByOr,
    AssignByXor,
    Rsh,
    Lsh,
    And,
    Or,
    Xor,
    Sub,
}

impl fmt::Display for AttrOp {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            AttrOp::Assign => write!(f, "="),
            AttrOp::AssignByRsh => write!(f, ">>="),
            AttrOp::AssignByLsh => write!(f, "<<="),
            AttrOp::AssignByAnd => write!(f, "&="),
            AttrOp::AssignByOr => write!(f, "|="),
            AttrOp::AssignByXor => write!(f, "^="),
            AttrOp::Rsh => write!(f, ">>"),
            AttrOp::Lsh => write!(f, "<<"),
            AttrOp::And => write!(f, "&"),
            AttrOp::Or => write!(f, "|"),
            AttrOp::Xor => write!(f, "^"),
            AttrOp::Sub => write!(f, "-"),
        }
    }
}
