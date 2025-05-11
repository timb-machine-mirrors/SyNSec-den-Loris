use core::cmp::min;
use std::collections::HashMap;
use libafl::{
    corpus::CorpusId,
    inputs::{BytesInput, HasBytesVec},
    mutators::mutations::rand_range,
    state::{HasRand, HasMaxSize, StdState, UsesState},
};
use libafl_bolts::{HasLen, rands::{StdRand, Rand}, Error};

use crate::generator::attribute::Attribute;
use crate::grammar::attribute::{AttrExpr, AttrOp};
use crate::input::rule::RulePath;

/// Mem move in the own vec
#[inline]
pub(crate) unsafe fn buffer_self_copy<T>(data: &mut [T], from: usize, to: usize, len: usize) {
    debug_assert!(!data.is_empty());
    debug_assert!(from + len <= data.len());
    debug_assert!(to + len <= data.len());
    if len != 0 && from != to {
        let ptr = data.as_mut_ptr();
        unsafe {
            core::ptr::copy(ptr.add(from), ptr.add(to), len);
        }
    }
}

/// Mem move between vecs
#[inline]
pub(crate) unsafe fn buffer_copy<T>(dst: &mut [T], src: &[T], from: usize, to: usize, len: usize) {
    debug_assert!(!dst.is_empty());
    debug_assert!(!src.is_empty());
    debug_assert!(from + len <= src.len());
    debug_assert!(to + len <= dst.len());
    let dst_ptr = dst.as_mut_ptr();
    let src_ptr = src.as_ptr();
    if len != 0 {
        unsafe {
            core::ptr::copy(src_ptr.add(from), dst_ptr.add(to), len);
        }
    }
}

fn verify_len_eq(a: &Vec<u8>, b: &Vec<u8>) -> Result<(), String> {
    if a.len() != b.len() {
        return Err(format!("{} != {}", a.len(), b.len()));
    }
    Ok(())
}

fn shift_left(a: &Attribute, b: &Attribute) -> Attribute {
    use Attribute::*;
    match (a, b) {
        (Number(v, m1), Number(n, m2)) => Number(v<<n, m1 | m2),
        (String(v, m1), Number(n, m2)) => {
            let n = *n;
            let len = v.len();
            let mut c = v.clone();
            if len * 8 <= n {
                c.fill(0);
            } else {
                if n >= 8 {
                    let q = n / 8;
                    c.rotate_left(q);
                    for i in len - q..len {
                        c[i] = 0;
                    }
                }
                let r = n % 8;
                for i in 0..len - 1 {
                    c[i] = c[i] << r | c[i + 1] >> 8 - r;
                }
                c[len - 1] <<= r;
            }
            String(c, m1 | m2)
        }
        _ => unimplemented!("{:?} << {:?}", a, b),
    }
}

fn shift_right(a: &Attribute, b: &Attribute) -> Attribute {
    use Attribute::*;
    match (a, b) {
        (Number(v, m1), Number(n, m2)) => Number(v>>n, m1 | m2),
        (String(v, m1), Number(n, m2)) => {
            let n = *n;
            let len = v.len();
            let mut c = v.clone();
            if len * 8 <= n {
                c.fill(0);
            } else {
                if n >= 8 {
                    let q = n / 8;
                    c.rotate_right(q);
                    for i in 0..q {
                        c[i] = 0;
                    }
                }
                let r = n % 8;
                for i in 0..len - 1 {
                    c[i + 1] = c[i] << 8 - r | c[i + 1] >> r;
                }
                c[0] >>= r
            }
            String(c, m1 | m2)
        },
        _ => unimplemented!("{:?} >> {:?}", a, b),
    }
}

fn and(v: &Attribute, w: &Attribute) -> Result<Attribute, String> {
    use Attribute::*;
    let res = match (v, w) {
        (Number(n1, m1), Number(n2, m2)) => Number(n1 & n2, m1 | m2),
        (String(v1, m1), String(v2, m2)) => {
            verify_len_eq(v1, v2)?;
            String(v1.iter().zip(v2).map(|(a, b)| a & b).collect(), m1 | m2)
        }
        _ => unimplemented!("{:?} & {:?}", v, w),
    };

    Ok(res)
}

fn xor(v: &Attribute, w: &Attribute) -> Result<Attribute, String> {
    use Attribute::*;
    let res = match (v, w) {
        (Number(n1, m1), Number(n2, m2)) => Number(n1 ^ n2, m1 | m2),
        (String(v1, m1), String(v2, m2)) => {
            verify_len_eq(v1, v2)?;
            String(v1.iter().zip(v2).map(|(a, b)| a ^ b).collect(), m1 | m2)
        }
        _ => unimplemented!("{:?} ^ {:?}", v, w),
    };

    Ok(res)
}

fn or(v: &Attribute, w: &Attribute) -> Result<Attribute, String> {
    use Attribute::*;
    let res = match (v, w) {
        (Number(n1, m1), Number(n2, m2)) => Number(n1 | n2, m1 | m2),
        (String(v1, m1), String(v2, m2)) => {
            verify_len_eq(v1, v2)?;
            String(v1.iter().zip(v2).map(| (a, b) | a | b).collect(), m1 | m2)
        }
        (String(v1, m1), Number(v2, m2)) => {
            if v1.len() != 1 {
                unimplemented!("{:?} | {:?}", v, w)
            }
            // TODO: check for int truncation
            let v2_str = v2.to_le_bytes();
            let (v2_str, _) = v2_str.split_at(1);
            let v2_vec = v2_str.to_vec();
            String(v1.iter().zip(&v2_vec).map(|(a, b)| a | b).collect(), m1 | m2)
        }
        (Number(v1, m1), String(v2, m2)) => {
            if v2.len() != 1 {
                unimplemented!("{:?} | {:?}", v, w)
            }
            // TODO: check for int truncation
            let v1_str = v1.to_le_bytes();
            let (v1_str, _) = v1_str.split_at(1);
            let v1_vec = v1_str.to_vec();
            String(v2.iter().zip(&v1_vec).map(|(a, b)| a | b).collect(), m1 | m2)
        }
    };

    Ok(res)
}

fn sub(a: &Attribute, b: &Attribute) -> Attribute {
    use Attribute::*;
    let res = match (a, b) {
        (Number(n1, m1), Number(n2, m2)) => Number(n1 - n2,m1 | m2),
        _ => unimplemented!("{:?} - {:?}", a, b),
    };

    res
}

pub fn process_attribute_assignment(
    lhs_name: String,
    op: AttrOp,
    rhs: &Attribute,
    attributes: &HashMap<String, Attribute>,
) -> Result<Attribute, String> {
    use AttrOp::*;
    // println!("{:?}, {:?}, {:?}", lhs_name, op, rhs);
    let res = match op {
        Assign => rhs.clone(),
        AssignByAnd => {
            let lhs = attributes.get(&lhs_name)
                .ok_or(format!("{}: no such attribute is provided", lhs_name))?;
            and(lhs, rhs)?
        },
        AssignByOr => {
            let lhs = attributes.get(&lhs_name)
                .ok_or(format!("{}: no such attribute is provided", lhs_name))?;
            or(lhs, rhs)?
        },
        AssignByXor => {
            let lhs = attributes.get(&lhs_name)
                .ok_or(format!("{}: no such attribute is provided", lhs_name))?;
            xor(lhs, rhs)?
        },
        AssignByLsh => {
            let lhs = attributes.get(&lhs_name)
                .ok_or(format!("{}: no such attribute is provided", lhs_name))?;
            shift_left(lhs, rhs)
        },
        AssignByRsh => {
            let lhs = attributes.get(&lhs_name)
                .ok_or(format!("{}: no such attribute is provided", lhs_name))?;
            shift_right(lhs, rhs)
        },
        op => unreachable!("Expected AttrOp::Assign* got {:?}", op)
    };

    Ok(res)
}

fn process_bin_op(op: AttrOp, lhs: &Attribute, rhs: &Attribute) -> Result<Attribute, String> {
    use AttrOp::*;
    let res = match op {
        Rsh => shift_right(lhs, rhs),
        Lsh => shift_left(lhs, rhs),
        And => and(lhs, rhs)?,
        Xor => xor(lhs, rhs)?,
        Or => or(lhs, rhs)?,
        Sub => sub(lhs, rhs),
        _ => unimplemented!("{:?}", op),
    };

    Ok(res)
}

pub fn process_attribute_rhs(
    base_path: RulePath,
    rhs: AttrExpr,
    attributes: &HashMap<String, Attribute>,
) -> Result<Attribute, String> {
    use AttrExpr::*;
    let res = match rhs {
        Number(n) => Attribute::Number(n, false),
        Literal(string) => Attribute::String(string, false),
        Attr {ident, name} => {
            let attr_name = base_path.append(&ident).append(&name.to_string().to_owned()).get_full();
            attributes.get(&attr_name)
                .ok_or(format!("{}: no such attribute is provided", attr_name))?.clone()
        },
        BinOp {lhs, op, rhs} => {
            let lhs = process_attribute_rhs(base_path.clone(), *lhs, attributes)?;
            let rhs = process_attribute_rhs(base_path, *rhs, attributes)?;
            process_bin_op(op, &lhs, &rhs)?
        },
    };

    Ok(res)
}

pub fn toss_biased_coin<E, EM, Z>(percent: u64) -> impl FnMut(&mut Z, &mut E, &mut E::State, &mut EM, CorpusId) -> Result<bool, Error>
where
    E: UsesState,
    E::State: HasRand,
    EM: UsesState<State = E::State>,
    Z: UsesState<State = E::State>,
{
    assert!(percent <= 100);

    move |&mut _, &mut _, state: &mut E::State, &mut _, _| -> Result<bool, Error> {
        let c = state.rand_mut().below(100);
        Ok(c < percent)
    }
}

pub(crate) fn mutator_crossover_insert<I, S>(state: &mut S, input: &mut I, other: &mut I) -> bool
where
    I: HasBytesVec,
    S: HasRand + HasMaxSize,
{
    let size = input.bytes().len();
    let max_size = state.max_size();
    if size >= max_size {
        return false;
    }

    let other_size = other.bytes().len();

    if other_size < 2 {
        return false;
    }

    let range = rand_range(state, other_size, min(other_size, max_size - size));
    let target = state.rand_mut().below(size as u64) as usize;

    input.bytes_mut().resize(size + range.len(), 0);
    unsafe {
        buffer_self_copy(
            input.bytes_mut(),
            target,
            target + range.len(),
            size - target,
        );
    }

    unsafe {
        buffer_copy(
            input.bytes_mut(),
            other.bytes(),
            range.start,
            target,
            range.len(),
        );
    };
    true
}