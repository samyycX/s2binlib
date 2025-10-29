/************************************************************************************
 *  S2BinLib - A static library that helps resolving memory from binary file
 *  and map to absolute memory address, targeting source 2 game engine.
 *  Copyright (C) 2025  samyyc
 * 
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 ***********************************************************************************/

use anyhow::Result;

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

pub fn find_pattern_simd(binary_data: &[u8], pattern: &[u8], pattern_wildcard: &[usize]) -> Result<u64> {
    if pattern.is_empty() || binary_data.len() < pattern.len() {
        return Err(anyhow::anyhow!("Pattern not found"));
    }

    let mut wildcard_mask = vec![0xFFu8; pattern.len()];
    for &idx in pattern_wildcard {
        if idx < pattern.len() {
            wildcard_mask[idx] = 0;
        }
    }

    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") && pattern.len() > 16 {
            return find_pattern_impl_avx2(binary_data, pattern, &wildcard_mask);
        } else if is_x86_feature_detected!("sse2") {
            return find_pattern_impl_sse2(binary_data, pattern, &wildcard_mask);
        }
    }

    find_pattern_scalar(binary_data, pattern, &wildcard_mask)
}

#[cfg(target_arch = "x86_64")]
fn find_pattern_impl_avx2(binary_data: &[u8], pattern: &[u8], wildcard_mask: &[u8]) -> Result<u64> {
    unsafe {
        for i in 0..=(binary_data.len() - pattern.len()) {
            if wildcard_mask[0] == 0xFF && binary_data[i] != pattern[0] {
                continue;
            }
            if matches_avx2(&binary_data[i..], pattern, wildcard_mask) {
                return Ok(i as u64);
            }
        }
    }
    Err(anyhow::anyhow!("Pattern not found"))
}

#[cfg(target_arch = "x86_64")]
fn find_pattern_impl_sse2(binary_data: &[u8], pattern: &[u8], wildcard_mask: &[u8]) -> Result<u64> {
    unsafe {
        for i in 0..=(binary_data.len() - pattern.len()) {
            if wildcard_mask[0] == 0xFF && binary_data[i] != pattern[0] {
                continue;
            }
            if matches_sse2(&binary_data[i..], pattern, wildcard_mask) {
                return Ok(i as u64);
            }
        }
    }
    Err(anyhow::anyhow!("Pattern not found"))
}

fn find_pattern_scalar(binary_data: &[u8], pattern: &[u8], wildcard_mask: &[u8]) -> Result<u64> {
    for i in 0..=(binary_data.len() - pattern.len()) {
        if wildcard_mask[0] == 0xFF && binary_data[i] != pattern[0] {
            continue;
        }
        if matches_scalar(&binary_data[i..], pattern, wildcard_mask) {
            return Ok(i as u64);
        }
    }
    Err(anyhow::anyhow!("Pattern not found"))
}

#[inline]
fn matches_scalar(data: &[u8], pattern: &[u8], mask: &[u8]) -> bool {
    for i in 0..pattern.len() {
        if mask[i] != 0 && data[i] != pattern[i] {
            return false;
        }
    }
    true
}

#[inline]
#[target_feature(enable = "avx2")]
#[cfg(target_arch = "x86_64")]
pub unsafe fn matches_avx2(data: &[u8], pattern: &[u8], mask: &[u8]) -> bool {
    let len = pattern.len();
    let mut offset = 0;

    while offset + 32 <= len {
        unsafe {
            let data_chunk = _mm256_loadu_si256(data.as_ptr().add(offset) as *const __m256i);
            let pattern_chunk = _mm256_loadu_si256(pattern.as_ptr().add(offset) as *const __m256i);
            let mask_chunk = _mm256_loadu_si256(mask.as_ptr().add(offset) as *const __m256i);
            
            let xor = _mm256_xor_si256(data_chunk, pattern_chunk);
            let masked = _mm256_and_si256(xor, mask_chunk);
            
            if _mm256_testz_si256(masked, masked) == 0 {
                return false;
            }
        }
        offset += 32;
    }

    for i in offset..len {
        if mask[i] != 0 && data[i] != pattern[i] {
            return false;
        }
    }

    true
}

#[inline]
#[target_feature(enable = "sse2")]
#[cfg(target_arch = "x86_64")]
pub unsafe fn matches_sse2(data: &[u8], pattern: &[u8], mask: &[u8]) -> bool {
    let len = pattern.len();
    let mut offset = 0;

    while offset + 16 <= len {
        unsafe {
            let data_chunk = _mm_loadu_si128(data.as_ptr().add(offset) as *const __m128i);
            let pattern_chunk = _mm_loadu_si128(pattern.as_ptr().add(offset) as *const __m128i);
            let mask_chunk = _mm_loadu_si128(mask.as_ptr().add(offset) as *const __m128i);

            let xor = _mm_xor_si128(data_chunk, pattern_chunk);
            let masked = _mm_and_si128(xor, mask_chunk);
            
            let cmp = _mm_cmpeq_epi8(masked, _mm_setzero_si128());
            let mask_result = _mm_movemask_epi8(cmp);
            
            if mask_result != 0xFFFF {
                return false;
            }
        }
        offset += 16;
    }

    for i in offset..len {
        if mask[i] != 0 && data[i] != pattern[i] {
            return false;
        }
    }

    true
}