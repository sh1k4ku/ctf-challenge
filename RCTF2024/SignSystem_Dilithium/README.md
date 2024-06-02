# SignSystem_Dilithium

The challenge comes from the PQC(Post-quantum cryptography) algorithm dilithium [1]. According to [2], we can know that this algorithm only needs to recover $\bold{s_1}$ to forge a valid signature, so the current side channel work on it is mainly focused on the equation $\bold{z} = \bold{y} + \bold{c}\cdot \bold{s_1}$. Based on the idea, I designed this chal.

The main code is copied from [3]. Players can easily find many "**libpqcrystals**" related strings in the code. After a simple search, we can download the source code. Using the **diff** command, we can find that there is an additional function called polyy_unpack, modified from polyz_unpack, in the file poly.c , which is used to randomly generate the coefficients of $\bold{y}$.

I think the modifications are very interesting, I used the trigonometric function **tan** and multiplied it by some numbers, so that some coefficients of $\bold{y}$ become 0. The number multiplied before round is used to control the number of **0s**, and the number after round is used to control the range of $\bold{y}$ and $\bold{z}$. If we can determine which components of $\bold{y}$ are 0, we can use convolution to obtain a formula related to $\bold{s_1}$ that satisfies $\bold{c_i} \cdot \bold{s_1} = z_i$. After obtaining enough formulas, we can solve this problem through **orthorgonal lattice attack**. After testing, about **170** equations can recover $\bold{s_1}$.

Due to the distribution of $\bold{c}$ and $\bold{s_1}$, the range of $||\bold{c}\cdot \bold{s_1}||$ is less than or equal to78. Since the coefficient of $\bold{y}$ is at least a multiple of 49, when $z_i$ is relatively small, we can assume that the corresponding $\bold{y}$'s component is 0. After testing, I found that setting bound to 20~26 has a higher probability of obtaining an equation that meets the conditions. After that, the lattice attack becomes simple.

When I wrote the exploit, I referred to [4] to introduce the c function in python, but some parameters of this chal are different from those in [4] and need to be modified to the corresponding parameters according to the source code。

# Unexpected solution

At first, the number to be multiplied after round was fixed to 49, which led to an unexpected solution, that is, $\bold{z} = \bold{c} \cdot \bold{s_1}$ mod 49 , at which point only the inverse is required to recover $\bold{s_1}$. We apologize for this mistake. In the revenge version, the number to be multiplied is randomly generated from [49,59], which also reduces the probability of a solution.

# Reference

[1]Ducas L, Kiltz E, Lepoint T, et al. Crystals-dilithium: A lattice-based digital signature scheme[J]. IACR Transactions on Cryptographic Hardware and Embedded Systems, 2018: 238-268.

[2]Ravi P, Jhanwar M P, Howe J, et al. Side-channel assisted existential forgery attack on Dilithium-A NIST PQC candidate[J]. Cryptology ePrint Archive, 2018.

[3]https://pq-crystals.org/dilithium/

[4]https://github.com/DownUnderCTF/Challenges_2023_Public/tree/main/crypto/dilithium/src

