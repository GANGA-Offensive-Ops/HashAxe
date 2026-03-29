use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList};
use std::fs::File;
use std::io::{BufRead, BufReader};

enum RuleOp {
    Lowercase,
    Uppercase,
    Capitalize,
    ToggleCase,
    Reverse,
    Duplicate,
    Reflect,
    Append(u8),
    Prepend(u8),
    TruncateLeft,
    TruncateRight,
}

fn parse_rule(s: &str) -> Vec<RuleOp> {
    let mut ops = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b':' => { }, 
            b'l' => ops.push(RuleOp::Lowercase),
            b'u' => ops.push(RuleOp::Uppercase),
            b'c' => ops.push(RuleOp::Capitalize),
            b't' => ops.push(RuleOp::ToggleCase),
            b'r' => ops.push(RuleOp::Reverse),
            b'd' => ops.push(RuleOp::Duplicate),
            b'f' => ops.push(RuleOp::Reflect),
            b'$' => {
                i += 1;
                if i < bytes.len() { ops.push(RuleOp::Append(bytes[i])); }
            },
            b'^' => {
                i += 1;
                if i < bytes.len() { ops.push(RuleOp::Prepend(bytes[i])); }
            },
            b'[' => ops.push(RuleOp::TruncateLeft),
            b']' => ops.push(RuleOp::TruncateRight),
            // Remaining 100+ rules omitted for brevity/prototype
            _ => { }
        }
        i += 1;
    }
    ops
}

fn apply_op(op: &RuleOp, word: &mut Vec<u8>) {
    match op {
        RuleOp::Lowercase => word.make_ascii_lowercase(),
        RuleOp::Uppercase => word.make_ascii_uppercase(),
        RuleOp::Capitalize => {
            word.make_ascii_lowercase();
            if !word.is_empty() { word[0] = word[0].to_ascii_uppercase(); }
        },
        RuleOp::ToggleCase => {
            for b in word.iter_mut() {
                if b.is_ascii_lowercase() { *b = b.to_ascii_uppercase(); }
                else if b.is_ascii_uppercase() { *b = b.to_ascii_lowercase(); }
            }
        },
        RuleOp::Reverse => word.reverse(),
        RuleOp::Duplicate => {
            let p = word.clone();
            word.extend(p);
        },
        RuleOp::Reflect => {
            let mut p = word.clone();
            p.reverse();
            word.extend(p);
        },
        RuleOp::Append(c) => word.push(*c),
        RuleOp::Prepend(c) => word.insert(0, *c),
        RuleOp::TruncateLeft => { if !word.is_empty() { word.remove(0); } },
        RuleOp::TruncateRight => { if !word.is_empty() { word.pop(); } },
    }
}

#[pyfunction]
fn apply_rules<'py>(py: Python<'py>, word: &[u8], rules: Vec<String>) -> PyResult<Bound<'py, PyList>> {
    let mut results: Vec<Bound<'py, PyBytes>> = Vec::with_capacity(rules.len());
    
    for r in &rules {
        let ops = parse_rule(r);
        let mut w = word.to_vec();
        for op in &ops {
            apply_op(op, &mut w);
        }
        results.push(PyBytes::new_bound(py, &w));
    }
    
    Ok(PyList::new_bound(py, results))
}

#[pyfunction]
fn apply_rules_from_file<'py>(py: Python<'py>, word: &[u8], rule_file: &str) -> PyResult<Bound<'py, PyList>> {
    let file = File::open(rule_file)?;
    let reader = BufReader::new(file);
    
    let mut results: Vec<Bound<'py, PyBytes>> = Vec::new();
    
    for line_rst in reader.lines() {
        if let Ok(line) = line_rst {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            
            let ops = parse_rule(line);
            let mut w = word.to_vec();
            for op in &ops { apply_op(op, &mut w); }
            results.push(PyBytes::new_bound(py, &w));
        }
    }
    Ok(PyList::new_bound(py, results))
}

#[pyfunction]
fn apply_rules_batch<'py>(py: Python<'py>, words: Vec<Bound<'py, PyBytes>>, rules: Vec<String>) -> PyResult<Bound<'py, PyList>> {
    let mut results: Vec<Bound<'py, PyBytes>> = Vec::with_capacity(words.len() * rules.len());
    let parsed_rules: Vec<_> = rules.iter().map(|r| parse_rule(r)).collect();
    
    for w_obj in words {
        let w = w_obj.as_bytes();
        for ops in &parsed_rules {
            let mut w_mut = w.to_vec();
            for op in ops { apply_op(op, &mut w_mut); }
            results.push(PyBytes::new_bound(py, &w_mut));
        }
    }
    Ok(PyList::new_bound(py, results))
}

#[pymodule]
fn hashaxe_rules_rs(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(apply_rules, m)?)?;
    m.add_function(wrap_pyfunction!(apply_rules_from_file, m)?)?;
    m.add_function(wrap_pyfunction!(apply_rules_batch, m)?)?;
    Ok(())
}
