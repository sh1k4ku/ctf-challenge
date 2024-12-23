# ZKPQC1

A isogeny trick wrapped with ZKP (acutually it's just a PoK). 
Target is to find 3 new ker on E0, whose order is `2^a` or `2^(a-1)`.
The key idea is that there is a automorphisms on invariant 1728. 
If the isogeny path corresponding to the isogeny constructed by the given kernel starts with `[287496, 1728, 1728, 287496]`, then there exists such an automorphism that can construct multiple different isogeny with the same isogeny path.
then we can get new and equivalent isogeny path on the curve.

The specific implementation of the topic does not need to be so complicated. The more bruteforce method is just to get the isogeny path from the given kernel, then enumerate all isogeny based on the isogeny path that meets the conditions, and then calculate the corresponding kernel.

Also, it's worth to notice that the E0 curve actually has an endomorphism $2i$ with degree 4. When the order of the kernel point constructed by the negotiated `J` is less than or equal to `2^(a-2)`, this endomorphism can be used to construct another isogeny mapping. Therefore, we limit the order of the negotiated kernel to `2^a` to avoid this more intuitive solution method through endomorphism.

Acutually we are not quite sure why there are at most 3 but not more different kernel points whose orders fall on [`2^a`, `2^(a-1)`]. We hope someone can help explain this.

For the PoK part, you can implement by yourself or refer to the PoK algorithm in the paper[0] and implement the response part.


## reference
[0] https://eprint.iacr.org/2022/475
