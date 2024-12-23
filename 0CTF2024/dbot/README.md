# dbot

## level0
3 primes p q s, s is known, we have 80 chances to request, send v = (x0 + x1)/2
$$
ph1_i \equiv (p + a_i) * (q + b) \text{ mod }s\\
ph2_i \equiv (-p + c_i) * (q + b) \text{ mod }s\\
\therefore \text{let } r_i = ph1_i + ph2_i \equiv (a_i + c_i) * (q + b)\text{ mod }s\\
\text{let } t_i \equiv \frac{r_i}{r_0} \equiv \frac{a_i + c_i}{a_0 + c_0}\equiv \frac{k_i}{k_0} \text{ mod }s
$$
then take hnp to recover $k_i$, and obtain $q+b \;mod\;s$, coppersmith can solve it.


## level1
4 primes p q r s, s is known, also 80 chances. We take ph1 use half chances and remains for ph2.
$$
ph1_i \equiv (p + a_i) * (q + a_i) \text{ mod }s\\
ph2_i \equiv (p - (a_i + 1)) * (q + (a_i + 1)) \equiv (p - b_i) * (q + b_i) \text{ mod }s\\

\therefore \text{let }k_i \equiv ph1_i - ph1_0 \equiv (a_i - a_0) * (p+q) + (a_i - a_0)(a_i + a_0) \text{ mod }s.\\
\text{let }k^\prime_i \equiv ph2_i - ph2_0 \equiv (b_i - b_0) * (p-q) + (b_i - b_0)(b_i + b_0) \text{ mod }s.\\
$$
first we take orthogonal lattice to get $k_i$ and $k^\prime_i$ and $p + q\;mod \;s$ and $p - q \; mod \;s$, so we can get some high bits of p and q. Finally use coppersmith twice to factor the N (with some enumeration).

Notably, the lowest 1 bit of primes must be '1', it can make the copper's bound less 1bit; also, we can use flatter to speed up the enumeration.


## Afterward
I forgot the RSA OT's modular need to be complex QAQ. Due to modular is prime, so we can easily get `d` mod (s-1), no matter what v we send, we can easily compute ph1 and ph2 every requ.