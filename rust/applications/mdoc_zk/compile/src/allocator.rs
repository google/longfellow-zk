// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use circuits_bit_plucker::BitPlucker;
use circuits_bitvec::{BitvecIO, V128, V256, V32, V8};
use compile_algebra::field::CompileField;
use compile_compiler::CompilerLogic;
use compile_logic::{Eltw, LogicIO};

pub struct WireAllocator<'l, 'a, FC: CompileField> {
    pub iologic: &'l CompilerLogic<'a, FC>,
    pub bitvec_io: &'l BitvecIO<'l, CompilerLogic<'a, FC>>,
    pub pos: usize,
}

impl<'l, 'a, FC: CompileField> WireAllocator<'l, 'a, FC> {
    pub fn new(
        iologic: &'l CompilerLogic<'a, FC>,
        bitvec_io: &'l BitvecIO<'l, CompilerLogic<'a, FC>>,
        pos: usize,
    ) -> Self {
        Self {
            iologic,
            bitvec_io,
            pos,
        }
    }

    pub fn allocate_wire(&mut self) -> Eltw<CompilerLogic<'a, FC>> {
        self.iologic.next(&mut self.pos)
    }

    pub fn allocate_bitvec<const N: usize>(
        &mut self,
    ) -> circuits_bitvec::Bitvec<CompilerLogic<'a, FC>, N> {
        self.bitvec_io.next::<N>(&mut self.pos)
    }

    pub fn allocate_plucked_v8<const PLUCKER_WIDTH: usize>(
        &mut self,
        plucker: &BitPlucker<'_, CompilerLogic<'a, FC>, PLUCKER_WIDTH>,
    ) -> (V8<CompilerLogic<'a, FC>>, Vec<Eltw<CompilerLogic<'a, FC>>>) {
        let n_packed = 8 / PLUCKER_WIDTH;
        let packed: Vec<_> = (0..n_packed).map(|_| self.allocate_wire()).collect();
        let unpacked = plucker.unpack::<8>(&packed);
        (unpacked, packed)
    }

    pub fn allocate_plucked_v8_array<const N: usize, const PLUCKER_WIDTH: usize>(
        &mut self,
        plucker: &BitPlucker<'_, CompilerLogic<'a, FC>, PLUCKER_WIDTH>,
    ) -> (
        [V8<CompilerLogic<'a, FC>>; N],
        Vec<Eltw<CompilerLogic<'a, FC>>>,
    ) {
        let mut plucked = Vec::with_capacity(N * 8 / PLUCKER_WIDTH);
        let arr = std::array::from_fn(|_| {
            let (v, p) = self.allocate_plucked_v8::<PLUCKER_WIDTH>(plucker);
            plucked.extend(p);
            v
        });
        (arr, plucked)
    }

    pub fn allocate_plucked_v32<const PLUCKER_WIDTH: usize>(
        &mut self,
        plucker: &BitPlucker<'_, CompilerLogic<'a, FC>, PLUCKER_WIDTH>,
    ) -> (V32<CompilerLogic<'a, FC>>, Vec<Eltw<CompilerLogic<'a, FC>>>) {
        let n_packed = 32 / PLUCKER_WIDTH;
        let packed: Vec<_> = (0..n_packed).map(|_| self.allocate_wire()).collect();
        let unpacked = plucker.unpack::<32>(&packed);
        (unpacked, packed)
    }

    pub fn allocate_plucked_v128<const PLUCKER_WIDTH: usize>(
        &mut self,
        plucker: &BitPlucker<'_, CompilerLogic<'a, FC>, PLUCKER_WIDTH>,
    ) -> (
        V128<CompilerLogic<'a, FC>>,
        Vec<Eltw<CompilerLogic<'a, FC>>>,
    ) {
        let n_packed = 128 / PLUCKER_WIDTH;
        let packed: Vec<_> = (0..n_packed).map(|_| self.allocate_wire()).collect();
        let unpacked = plucker.unpack::<128>(&packed);
        (unpacked, packed)
    }

    pub fn allocate_plucked_v256<const PLUCKER_WIDTH: usize>(
        &mut self,
        plucker: &BitPlucker<'_, CompilerLogic<'a, FC>, PLUCKER_WIDTH>,
    ) -> (
        V256<CompilerLogic<'a, FC>>,
        Vec<Eltw<CompilerLogic<'a, FC>>>,
    ) {
        let n_packed = 256 / PLUCKER_WIDTH;
        let packed: Vec<_> = (0..n_packed).map(|_| self.allocate_wire()).collect();
        let unpacked = plucker.unpack::<256>(&packed);
        (unpacked, packed)
    }

    pub fn allocate_tag_plucked<const PLUCKER_WIDTH: usize>(
        &mut self,
        plucker: &BitPlucker<'_, CompilerLogic<'a, FC>, PLUCKER_WIDTH>,
    ) -> (
        [V128<CompilerLogic<'a, FC>>; 2],
        [Vec<Eltw<CompilerLogic<'a, FC>>>; 2],
    ) {
        let (t0, p0) = self.allocate_plucked_v128::<PLUCKER_WIDTH>(plucker);
        let (t1, p1) = self.allocate_plucked_v128::<PLUCKER_WIDTH>(plucker);
        ([t0, t1], [p0, p1])
    }
}
