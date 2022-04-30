// Copyright (C) 2019-2022 Aleo Systems Inc.
// This file is part of the snarkVM library.

// The snarkVM library is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// The snarkVM library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with the snarkVM library. If not, see <https://www.gnu.org/licenses/>.

#[macro_use]
mod boilerplate;

pub(super) mod add;
pub(super) use add::*;

pub(super) mod hash;
pub(super) use hash::*;

pub(super) mod mul;
pub(super) use mul::*;

pub(super) mod neg;
pub(super) use neg::*;

pub(super) mod sub;
pub(super) use sub::*;

use crate::{
    function::{parsers::Operand, registers::Registers},
    helpers::Register,
    Program,
    Sanitizer,
};
use snarkvm_circuits::{Parser, ParserResult};
use snarkvm_utilities::{error, FromBytes, ToBytes};

use core::fmt;
use nom::{
    branch::alt,
    bytes::complete::tag,
    combinator::map,
    sequence::{pair, preceded},
};
use std::io::{Read, Result as IoResult, Write};

pub trait Opcode {
    ///
    /// Returns the opcode of the operation.
    ///
    fn opcode() -> &'static str;
}

pub trait Operation<P: Program>: Parser + Into<Instruction<P>> {
    ///
    /// Evaluates the operation.
    ///
    fn evaluate(&self, registers: &Registers<P>);
}

pub enum Instruction<P: Program> {
    /// Adds `first` with `second`, storing the outcome in `destination`.
    Add(Add<P>),
    /// Multiplies `first` with `second`, storing the outcome in `destination`.
    Mul(Mul<P>),
    /// Negates `first`, storing the outcome in `destination`.
    Neg(Neg<P>),
    /// Subtracts `second` from `first`, storing the outcome in `destination`.
    Sub(Sub<P>),
    /// Performs a Pedersen hash taking a 64-bit value as input.
    Ped64(Ped64<P>),
    /// Performs a Pedersen hash taking a 128-bit value as input.
    Ped128(Ped128<P>),
    /// Performs a Pedersen hash taking a 256-bit value as input.
    Ped256(Ped256<P>),
    /// Performs a Pedersen hash taking a 512-bit value as input.
    Ped512(Ped512<P>),
    /// Performs a Pedersen hash taking a 1024-bit value as input.
    Ped1024(Ped1024<P>),
}

impl<P: Program> Instruction<P> {
    /// Returns the opcode of the instruction.
    #[inline]
    pub(crate) fn opcode(&self) -> &'static str {
        match self {
            Self::Add(..) => Add::<P>::opcode(),
            Self::Mul(..) => Mul::<P>::opcode(),
            Self::Neg(..) => Neg::<P>::opcode(),
            Self::Sub(..) => Sub::<P>::opcode(),
            Self::Ped64(..) => Ped64::<P>::opcode(),
            Self::Ped128(..) => Ped128::<P>::opcode(),
            Self::Ped256(..) => Ped256::<P>::opcode(),
            Self::Ped512(..) => Ped512::<P>::opcode(),
            Self::Ped1024(..) => Ped1024::<P>::opcode(),
        }
    }

    /// Returns the operands of the instruction.
    #[inline]
    pub(crate) fn operands(&self) -> Vec<Operand<P>> {
        match self {
            Self::Add(add) => add.operands(),
            Self::Mul(mul) => mul.operands(),
            Self::Neg(neg) => neg.operands(),
            Self::Sub(sub) => sub.operands(),
            Self::Ped64(ped64) => ped64.operands(),
            Self::Ped128(ped128) => ped128.operands(),
            Self::Ped256(ped256) => ped256.operands(),
            Self::Ped512(ped512) => ped512.operands(),
            Self::Ped1024(ped1024) => ped1024.operands(),
        }
    }

    /// Returns the destination register of the instruction.
    #[inline]
    pub(crate) fn destination(&self) -> &Register<P> {
        match self {
            Self::Add(add) => add.destination(),
            Self::Mul(mul) => mul.destination(),
            Self::Neg(neg) => neg.destination(),
            Self::Sub(sub) => sub.destination(),
            Self::Ped64(ped64) => ped64.destination(),
            Self::Ped128(ped128) => ped128.destination(),
            Self::Ped256(ped256) => ped256.destination(),
            Self::Ped512(ped512) => ped512.destination(),
            Self::Ped1024(ped1024) => ped1024.destination(),
        }
    }

    /// Evaluates the instruction.
    #[inline]
    pub(crate) fn evaluate(&self, registers: &Registers<P>) {
        match self {
            Self::Add(instruction) => instruction.evaluate(registers),
            Self::Mul(instruction) => instruction.evaluate(registers),
            Self::Neg(instruction) => instruction.evaluate(registers),
            Self::Sub(instruction) => instruction.evaluate(registers),
            Self::Ped64(instruction) => instruction.evaluate(registers),
            Self::Ped128(instruction) => instruction.evaluate(registers),
            Self::Ped256(instruction) => instruction.evaluate(registers),
            Self::Ped512(instruction) => instruction.evaluate(registers),
            Self::Ped1024(instruction) => instruction.evaluate(registers),
        }
    }
}

impl<P: Program> Parser for Instruction<P> {
    type Environment = P::Environment;

    /// Parses a string into an instruction.
    #[inline]
    fn parse(string: &str) -> ParserResult<Self> {
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the instruction from the string.
        let (string, instruction) = alt((
            // Note that order of the individual parsers matters.
            preceded(pair(tag(Add::<P>::opcode()), tag(" ")), map(Add::parse, Into::into)),
            preceded(pair(tag(Mul::<P>::opcode()), tag(" ")), map(Mul::parse, Into::into)),
            preceded(pair(tag(Neg::<P>::opcode()), tag(" ")), map(Neg::parse, Into::into)),
            preceded(pair(tag(Sub::<P>::opcode()), tag(" ")), map(Sub::parse, Into::into)),
            preceded(pair(tag(Ped64::<P>::opcode()), tag(" ")), map(Ped64::parse, Into::into)),
            preceded(pair(tag(Ped128::<P>::opcode()), tag(" ")), map(Ped128::parse, Into::into)),
            preceded(pair(tag(Ped256::<P>::opcode()), tag(" ")), map(Ped256::parse, Into::into)),
            preceded(pair(tag(Ped512::<P>::opcode()), tag(" ")), map(Ped512::parse, Into::into)),
            preceded(pair(tag(Ped1024::<P>::opcode()), tag(" ")), map(Ped1024::parse, Into::into)),
        ))(string)?;
        // Parse the semicolon from the string.
        let (string, _) = tag(";")(string)?;

        Ok((string, instruction))
    }
}

impl<P: Program> fmt::Display for Instruction<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Add(instruction) => write!(f, "{} {};", self.opcode(), instruction),
            Self::Mul(instruction) => write!(f, "{} {};", self.opcode(), instruction),
            Self::Neg(instruction) => write!(f, "{} {};", self.opcode(), instruction),
            Self::Sub(instruction) => write!(f, "{} {};", self.opcode(), instruction),
            Self::Ped64(instruction) => write!(f, "{} {};", self.opcode(), instruction),
            Self::Ped128(instruction) => write!(f, "{} {};", self.opcode(), instruction),
            Self::Ped256(instruction) => write!(f, "{} {};", self.opcode(), instruction),
            Self::Ped512(instruction) => write!(f, "{} {};", self.opcode(), instruction),
            Self::Ped1024(instruction) => write!(f, "{} {};", self.opcode(), instruction),
        }
    }
}

impl<P: Program> FromBytes for Instruction<P> {
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let code = u16::read_le(&mut reader)?;
        match code {
            0 => Ok(Self::Add(Add::read_le(&mut reader)?)),
            1 => Ok(Self::Mul(Mul::read_le(&mut reader)?)),
            2 => Ok(Self::Neg(Neg::read_le(&mut reader)?)),
            3 => Ok(Self::Sub(Sub::read_le(&mut reader)?)),
            4 => Ok(Self::Ped64(Ped64::read_le(&mut reader)?)),
            5 => Ok(Self::Ped128(Ped128::read_le(&mut reader)?)),
            6 => Ok(Self::Ped256(Ped256::read_le(&mut reader)?)),
            7 => Ok(Self::Ped512(Ped512::read_le(&mut reader)?)),
            8 => Ok(Self::Ped1024(Ped1024::read_le(&mut reader)?)),
            9.. => Err(error(format!("Failed to deserialize an instruction of code {code}"))),
        }
    }
}

impl<P: Program> ToBytes for Instruction<P> {
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        match self {
            Self::Add(instruction) => {
                u16::write_le(&0u16, &mut writer)?;
                instruction.write_le(&mut writer)
            }
            Self::Mul(instruction) => {
                u16::write_le(&1u16, &mut writer)?;
                instruction.write_le(&mut writer)
            }
            Self::Neg(instruction) => {
                u16::write_le(&2u16, &mut writer)?;
                instruction.write_le(&mut writer)
            }
            Self::Sub(instruction) => {
                u16::write_le(&3u16, &mut writer)?;
                instruction.write_le(&mut writer)
            }
            Self::Ped64(instruction) => {
                u16::write_le(&4u16, &mut writer)?;
                instruction.write_le(&mut writer)
            }
            Self::Ped128(instruction) => {
                u16::write_le(&5u16, &mut writer)?;
                instruction.write_le(&mut writer)
            }
            Self::Ped256(instruction) => {
                u16::write_le(&6u16, &mut writer)?;
                instruction.write_le(&mut writer)
            }
            Self::Ped512(instruction) => {
                u16::write_le(&7u16, &mut writer)?;
                instruction.write_le(&mut writer)
            }
            Self::Ped1024(instruction) => {
                u16::write_le(&8u16, &mut writer)?;
                instruction.write_le(&mut writer)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[macro_export]
    macro_rules! test_instruction_halts {
        ($test_name:ident, $instruction: ident, $reason: expr, $a: expr, $b: expr) => {
            #[test]
            #[should_panic(expected = $reason)]
            fn $test_name() {
                use $crate::{
                    function::{Operation, Registers},
                    Parser,
                    Process,
                    Register,
                    Value,
                };
                type P = Process;

                let a = Value::<P>::from_str($a);
                let b = Value::<P>::from_str($b);

                let registers = Registers::<P>::default();
                registers.define(&Register::from_str("r0"));
                registers.define(&Register::from_str("r1"));
                registers.define(&Register::from_str("r2"));
                registers.assign(&Register::from_str("r0"), a);
                registers.assign(&Register::from_str("r1"), b);

                $instruction::from_str("r0 r1 into r2").evaluate(&registers);
            }
        };

        ($test_name:ident, $instruction: ident, $reason: expr, $input: expr) => {
            #[test]
            #[should_panic(expected = $reason)]
            fn $test_name() {
                use $crate::{
                    function::{Operation, Registers},
                    Parser,
                    Process,
                    Register,
                    Value,
                };
                type P = Process;

                let input = Value::<P>::from_str($input);

                let registers = Registers::<P>::default();
                registers.define(&Register::from_str("r0"));
                registers.define(&Register::from_str("r1"));
                registers.assign(&Register::from_str("r0"), input);

                $instruction::from_str("r0 into r1").evaluate(&registers);
            }
        };
    }

    #[macro_export]
    macro_rules! unary_instruction_test {
        ($test_name: ident, $instruction: ident, $input: expr, $expected: expr) => {
            #[test]
            fn $test_name() {
                use $crate::{
                    function::{Operation, Registers},
                    Parser,
                    Process,
                    Register,
                    Value,
                };
                type P = Process;

                let input = Value::<P>::from_str($input);
                let expected = Value::<P>::from_str($expected);

                let registers = Registers::<P>::default();
                registers.define(&Register::from_str("r0"));
                registers.define(&Register::from_str("r1"));
                registers.assign(&Register::from_str("r0"), input);

                $instruction::from_str("r0 into r1").evaluate(&registers);
                let candidate = registers.load(&Register::from_str("r1"));
                assert_eq!(expected, candidate);
            }
        };
    }

    #[macro_export]
    macro_rules! binary_instruction_test {
        ($test_name: ident, $instruction: ident, $a: expr, $b: expr, $c: expr) => {
            #[test]
            fn $test_name() {
                use $crate::{
                    function::{Operation, Registers},
                    Parser,
                    Process,
                    Register,
                    Value,
                };
                type P = Process;

                let a = Value::<P>::from_str($a);
                let b = Value::<P>::from_str($b);
                let expected = Value::<P>::from_str($c);

                let registers = Registers::<P>::default();
                registers.define(&Register::from_str("r0"));
                registers.define(&Register::from_str("r1"));
                registers.define(&Register::from_str("r2"));
                registers.assign(&Register::from_str("r0"), a);
                registers.assign(&Register::from_str("r1"), b);

                $instruction::from_str("r0 r1 into r2").evaluate(&registers);
                let candidate = registers.load(&Register::from_str("r2"));
                assert_eq!(expected, candidate);
            }
        };
    }

    #[macro_export]
    macro_rules! test_modes {
        ($type: ident, $instruction: ident, $a: expr, $b: expr, $expected: expr) => {
            mod $type {
                use super::*;
                use $crate::binary_instruction_test;

                binary_instruction_test!(
                    test_public_and_public_yields_private,
                    $instruction,
                    concat!($a, ".public"),
                    concat!($b, ".public"),
                    concat!($expected, ".private")
                );

                binary_instruction_test!(
                    test_public_and_constant_yields_private,
                    $instruction,
                    concat!($a, ".public"),
                    concat!($b, ".constant"),
                    concat!($expected, ".private")
                );

                binary_instruction_test!(
                    test_public_and_private_yields_private,
                    $instruction,
                    concat!($a, ".public"),
                    concat!($b, ".private"),
                    concat!($expected, ".private")
                );

                binary_instruction_test!(
                    test_private_and_constant_yields_private,
                    $instruction,
                    concat!($a, ".private"),
                    concat!($b, ".constant"),
                    concat!($expected, ".private")
                );

                binary_instruction_test!(
                    test_private_and_public_yields_private,
                    $instruction,
                    concat!($a, ".private"),
                    concat!($b, ".public"),
                    concat!($expected, ".private")
                );

                binary_instruction_test!(
                    test_private_and_private_yields_private,
                    $instruction,
                    concat!($a, ".private"),
                    concat!($b, ".private"),
                    concat!($expected, ".private")
                );

                binary_instruction_test!(
                    test_constant_and_private_yields_private,
                    $instruction,
                    concat!($a, ".constant"),
                    concat!($b, ".private"),
                    concat!($expected, ".private")
                );

                binary_instruction_test!(
                    test_constant_and_public_yields_private,
                    $instruction,
                    concat!($a, ".constant"),
                    concat!($b, ".public"),
                    concat!($expected, ".private")
                );

                binary_instruction_test!(
                    test_constant_and_constant_yields_constant,
                    $instruction,
                    concat!($a, ".constant"),
                    concat!($b, ".constant"),
                    concat!($expected, ".constant")
                );
            }
        };

        ($type: ident, $instruction: ident, $input: expr, $expected: expr) => {
            mod $type {
                use super::*;
                use $crate::unary_instruction_test;

                unary_instruction_test!(
                    test_public_yields_private,
                    $instruction,
                    concat!($input, ".public"),
                    concat!($expected, ".private")
                );

                unary_instruction_test!(
                    test_private_yields_private,
                    $instruction,
                    concat!($input, ".private"),
                    concat!($expected, ".private")
                );

                unary_instruction_test!(
                    test_constant_yields_constant,
                    $instruction,
                    concat!($input, ".constant"),
                    concat!($expected, ".constant")
                );
            }
        };
    }
}
