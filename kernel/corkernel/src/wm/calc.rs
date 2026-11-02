//! Windows Calculator (calc.exe) Application Engine for CorOS.
//! 100% in-house implementation supporting arithmetic calculations,
//! numeric key entry, floating point operations, clear, and backspace.

use alloc::format;
use alloc::string::String;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CalcOp {
    None,
    Add,
    Subtract,
    Multiply,
    Divide,
}

pub struct CalculatorApp {
    pub display_text: String,
    pub accumulator: f64,
    pub pending_op: CalcOp,
    pub clear_on_next_digit: bool,
    pub history_line: String,
}

impl CalculatorApp {
    pub fn new() -> Self {
        Self {
            display_text: String::from("0"),
            accumulator: 0.0,
            pending_op: CalcOp::None,
            clear_on_next_digit: false,
            history_line: String::new(),
        }
    }

    /// Input a single digit character '0'..'9' or '.'
    pub fn input_char(&mut self, c: char) {
        if self.clear_on_next_digit {
            self.display_text.clear();
            self.clear_on_next_digit = false;
        }

        if c == '.' {
            if !self.display_text.contains('.') {
                if self.display_text.is_empty() {
                    self.display_text.push('0');
                }
                self.display_text.push('.');
            }
        } else if c.is_ascii_digit() {
            if self.display_text == "0" {
                self.display_text.clear();
            }
            self.display_text.push(c);
        }
    }

    /// Set an operation (+, -, *, /).
    pub fn set_operation(&mut self, op: CalcOp) {
        self.evaluate();
        if let Ok(val) = self.display_text.parse::<f64>() {
            self.accumulator = val;
            self.pending_op = op;
            let op_str = match op {
                CalcOp::Add => "+",
                CalcOp::Subtract => "-",
                CalcOp::Multiply => "*",
                CalcOp::Divide => "/",
                CalcOp::None => "",
            };
            self.history_line = format!("{} {}", self.display_text, op_str);
            self.clear_on_next_digit = true;
        }
    }

    /// Evaluate pending operation (=).
    pub fn evaluate(&mut self) {
        if self.pending_op == CalcOp::None {
            return;
        }

        if let Ok(val) = self.display_text.parse::<f64>() {
            let res = match self.pending_op {
                CalcOp::Add => self.accumulator + val,
                CalcOp::Subtract => self.accumulator - val,
                CalcOp::Multiply => self.accumulator * val,
                CalcOp::Divide => if val != 0.0 { self.accumulator / val } else { 0.0 },
                CalcOp::None => val,
            };

            self.display_text = format!("{}", res);
            self.history_line.clear();
            self.accumulator = res;
            self.pending_op = CalcOp::None;
            self.clear_on_next_digit = true;
        }
    }

    /// Clear all state (C).
    pub fn clear_all(&mut self) {
        self.display_text = String::from("0");
        self.accumulator = 0.0;
        self.pending_op = CalcOp::None;
        self.history_line.clear();
        self.clear_on_next_digit = false;
    }

    /// Backspace (delete last character).
    pub fn backspace(&mut self) {
        if !self.clear_on_next_digit && self.display_text.len() > 1 {
            self.display_text.pop();
        } else {
            self.display_text = String::from("0");
        }
    }
}
