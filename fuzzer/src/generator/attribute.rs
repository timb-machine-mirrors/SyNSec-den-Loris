#[derive(Clone, Debug)]
pub enum Attribute {
    Number(usize, bool),
    String(Vec<u8>, bool),
}
