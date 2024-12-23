# ZKPQC2

The chall first has a coin guess oracle by self-absorption shake from ripemd-160. Also, notice that ripemd is a merkle damgard structure hash algorithm, so we can take hash extension on it.
Finally, it outputs `hats`--the sum of two polynomial `s'`'s component, it's `tickets` come from ripemd's state, and `s'` is the ntt format of `s`. Target is to recovery the 32-bytes seed.

Intended sol is to guess the first 160 bits of hash oracle, which is easy to achieve on 137 request, and we need to use `rubbish` to predict next state. If we guess more, the state wil lose control. Then, when we get the corresponding index of `hats`, if we get enough `hats`, we can just solve this linear equations. However, after test we can only get less than 500 useful combination. 

The Kyber's q=3329 is carefully selected. There is a 256-th roots of unity -- 17 in $X^{256} + 1$ [0], the ntt transform can be view as a special vandermonde matrix, so we can view `hats` as mod-q linear equations on the initial secret `s`. Even though it's not full rank, it's enough to solve it because Kyber's public key reveals $b = As + e$ on secret. Just takes lattice on it [1]!

## reference
[0]https://pq-crystals.org/kyber/data/kyber-specification-round3-20210131.pdf

[1]https://eprint.iacr.org/2023/777