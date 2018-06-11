#[cfg(test)]
mod tests;

#[derive(Debug)]
struct HighwayHashState{
    v0:   [u64; 4],
    v1:   [u64; 4],
    mul0: [u64; 4],
    mul1: [u64; 4]
}

impl HighwayHashState {
    fn new(key: [u64; 4]) -> HighwayHashState {
        let mul0 = [
            0xdbe6d5d5fe4cce2f,
            0xa4093822299f31d0,
            0x13198a2e03707344,
            0x243f6a8885a308d3
        ];
        let mul1 = [
            0x3bd39e10cb0ef593,
            0xc0acf169b5f18a8c,
            0xbe5466cf34e90c6c,
            0x452821e638d01377
        ];

        let v0 = [
            mul0[0] ^ key[0],
            mul0[1] ^ key[1],
            mul0[2] ^ key[2],
            mul0[3] ^ key[3]
        ];

        let v1 = [
            mul1[0] ^ ((key[0] >> 32) | (key[0] << 32)),
            mul1[1] ^ ((key[1] >> 32) | (key[1] << 32)),
            mul1[2] ^ ((key[2] >> 32) | (key[2] << 32)),
            mul1[3] ^ ((key[3] >> 32) | (key[3] << 32))
        ];

        HighwayHashState {
            v0,
            v1,
            mul0,
            mul1
        }
    }

    fn update(&mut self, lanes: [u64; 4]) {
        for i in 0..4 {
            self.v1[i] = self.v1[i].wrapping_add(self.mul0[i].wrapping_add(lanes[i]));
            self.mul0[i] ^= (self.v1[i] & 0xffffffff).wrapping_mul(self.v0[i] >> 32);
            self.v0[i] = self.v0[i].wrapping_add(self.mul1[i]);
            self.mul1[i] ^= (self.v0[i] & 0xffffffff).wrapping_mul(self.v1[i] >> 32);
        }
        self.v0[0] = self.v0[0].wrapping_add(zipper_merge_left(self.v1[1], self.v1[0]));
        self.v0[1] = self.v0[1].wrapping_add(zipper_merge_right(self.v1[1], self.v1[0]));

        self.v0[2] = self.v0[2].wrapping_add(zipper_merge_left(self.v1[3], self.v1[2]));
        self.v0[3] = self.v0[3].wrapping_add(zipper_merge_right(self.v1[3], self.v1[2]));

        self.v1[0] = self.v1[0].wrapping_add(zipper_merge_left(self.v0[1], self.v0[0]));
        self.v1[1] = self.v1[1].wrapping_add(zipper_merge_right(self.v0[1], self.v0[0]));

        self.v1[2] = self.v1[2].wrapping_add(zipper_merge_left(self.v0[3], self.v0[2]));
        self.v1[3] = self.v1[3].wrapping_add(zipper_merge_right(self.v0[3], self.v0[2]));
    }

    fn update_packet(&mut self, packet: [u8; 32]) {
        self.update([
            read_64(&packet[0..8]),
            read_64(&packet[8..16]),
            read_64(&packet[16..24]),
            read_64(&packet[24..32])
        ]);
    }

    fn update_remainder(&mut self, bytes: &[u8]) {
        let len = bytes.len() as u64;
        let len_mod4: usize = bytes.len()  % 4;
        let remainder: usize = bytes.len() - len_mod4;

        let mut packet: [u8; 32] = [0; 32];

        for i in 0..4 {
            self.v0[i] = self.v0[i].wrapping_add(len << 32).wrapping_add(len);
        }
        rotate_32_by(bytes.len() as u32, &mut self.v1);
        for i in 0..remainder {
            packet[i] = bytes[i];
        }
        if len >= 16 {
            for i in 0..4 {
                packet[28 + i] = bytes[remainder + i + len_mod4 - 4];
            }
        } else {
            if len_mod4 != 0 {
                packet[16 + 0] = bytes[remainder];
                packet[16 + 1] = bytes[remainder + len_mod4 >> 1];
                packet[16 + 2] = bytes[remainder + len_mod4 - 1];
            }
        }
        self.update_packet(packet);
    }

    fn process_all(&mut self, data: &[u8]) {
        for chunk in data.chunks(32) {
            if chunk.len() == 32 {
                let mut packet: [u8; 32] = [0; 32];
                packet.copy_from_slice(chunk);
                self.update_packet(packet);
            } else {
                self.update_remainder(chunk);
            }
        }
    }

    fn permute_and_update(&mut self) {
        let mut permuted: [u64; 4] = [0; 4];
        permute(self.v0, &mut permuted);
        self.update(permuted);
    }

    fn finalize_u64(&mut self) -> u64 {
        for _ in 0..4 {
            self.permute_and_update();
        }

        self.v0[0].wrapping_add(
            self.v1[0].wrapping_add(
                self.mul0[0].wrapping_add(
                    self.mul1[0]
                )
            )
        )
    }

    fn finalize_u128(&mut self) -> u128 {
        for _ in 0..6 {
            self.permute_and_update();
        }
        let half0 = self.v0[0].wrapping_add(
            self.mul0[0].wrapping_add(
                self.v1[2].wrapping_add(
                    self.mul1[2]
                )
            )
        ) as u128;
        let half1 = self.v0[1].wrapping_add(
            self.mul0[1].wrapping_add(
                self.v1[3].wrapping_add(
                    self.mul1[3]
                )
            )
        ) as u128;
        (half0 << 64) + half1
    }
}

fn zipper_merge_left(v1: u64, v0: u64) -> u64 {
    (((v0 & 0xff000000) | (v1 & 0xff00000000)) >> 24) |
    (((v0 & 0xff0000000000) | (v1 & 0xff000000000000)) >> 16) |
    (v0 & 0xff0000) | ((v0 & 0xff00) << 32) |
    ((v1 & 0xff00000000000000) >> 8) | (v0 << 56)
}

fn zipper_merge_right(v1: u64, v0: u64) -> u64 {
    (((v1 & 0xff000000) | (v0 & 0xff00000000)) >> 24) |
    (v1 & 0xff0000) | ((v1 & 0xff0000000000) >> 16) |
    ((v1 & 0xff00) << 24) | ((v0 & 0xff000000000000) >> 8) |
    ((v1 & 0xff) << 48) | (v0 & 0xff00000000000000)
}

fn read_64 (src: &[u8]) -> u64 {
    (src[0] as u64) | ((src[1] as u64) << 8) |
    ((src[2]as u64) << 16) | ((src[3]as u64) << 24) |
    ((src[4]as u64) << 32) | ((src[5]as u64) << 40) |
    ((src[6]as u64) << 48) | ((src[7]as u64) << 56)
}

fn rotate_32_by(count: u32, lanes: &mut [u64; 4]) {
    for i in 0..4 {
        let half0: u32 = (lanes[i] & 0xffffffff) as u32;
        let half1: u32 = (lanes[i] >> 32) as u32;

        lanes[i] = (half0.rotate_left(count) as u64) | 
                   ((half1.rotate_left(count) as u64)  << 32);
    }
}

fn permute(v: [u64; 4], permuted: &mut [u64; 4]) {
    permuted[0] = (v[2] >> 32) | (v[2] << 32);
    permuted[1] = (v[3] >> 32) | (v[3] << 32);
    permuted[2] = (v[0] >> 32) | (v[0] << 32);
    permuted[3] = (v[1] >> 32) | (v[1] << 32);
}


// Non-cat API
pub fn highway_hash_64(data: &[u8], key: [u64; 4]) -> u64 {
    let mut state = HighwayHashState::new(key);
    state.process_all(data);
    return state.finalize_u64();
}

pub fn highway_hash_128(data: &[u8], key: [u64; 4]) -> u128 {
    let mut state = HighwayHashState::new(key);
    state.process_all(data);
    return state.finalize_u128();
}