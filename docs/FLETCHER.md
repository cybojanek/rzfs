Fletcher4
=========

Formula
-------

The Fletcher4 checksum is calculated using the following formula:

```math
a_0 = 0
b_0 = 0
c_0 = 0
d_0 = 0

a_i = a_{i-1} + f_{i-1}
b_i = b_{i-1} + a_i
c_i = c_{i-1} + b_i
d_i = d_{i-1} + c_i
```

Calculating `a`
---------------

Consider `a` for the first few values:

```math
a_0 = 0
a_1 = a_0 + f_0
a_2 = a_1 + f_1
a_3 = a_2 + f_2
```

Expand the values for `a_3`:

```math
a_3 =             a_2 + f_2
a_3 =       a_1 + f_1 + f_2
a_3 = a_0 + f_0 + f_1 + f_2
a_3 =   0 + f_0 + f_1 + f_2

a_n = f_0 + f_1 + ... + f_{n-1}
```

Which can be represented as the sum:

```math
   n          n
a  =  Σ  f    =  Σ  f
 n   i=1  n-1   i=1  n-i
```

Calculating `b`
---------------

Consider `b` for the first few values:

```math
b_0 = 0
b_1 = b_0 + a_1
b_2 = b_1 + a_2
b_3 = b_2 + a_3
```

Expand the values for `b_3`:

```math
b_3 =                     b_2 +              a_3
b_3 =       b_1 +         a_2 +              a_3
b_3 = b_0 + a_1 +         a_2 +              a_3
b_3 =   0 + a_1 +         a_2 +              a_3
b_3 =       f_0 + (f_0 + f_1) + (f_0 + f_1 + f_2)
b_3 = 3 * f_0 + 2 * f_1 + f_2

b_n = n * f_0 + (n - 1) * f_1 + ... + 1 * f_{n-1}
```

Which can be represented as the sum starting at `f_0` and ending at `f_{n-1}`.

```math
      n
b  =  Σ  (n + 1 - i) * f
 n   i=1                n-1
```

However, this can be simplified, if the sum starts at `f_{n-1}` and ends at `f_0`.
Note that the subscript for `f` is no longer `n-1`, but is now `n-i`.

```math
      n
b  =  Σ  i * f
 n   i=1      n-i
```

Calculating `c`
---------------

Consider `c` for the first few values:

```math
c_0 = 0
c_1 = c_0 + b_1
c_2 = c_1 + b_2
c_3 = c_2 + b_3
```

Expand the values for `c_3`:

```math
c_3 = b_1 + b_2             + b_3
c_3 = f_0 + (2 * f_0 + f_1) + (3 * f_0 + 2 * f_1 + f_2)
c_3 = 6 * f_0 + 3 * f_1 + f_2

c_n = sum(1..n) * f_0 + sum(1..n-1) * f_1 + .. + 1 * f_{n-1}.
```

Using the trick from calculating `b_n`, if the sum starts at `f_{n-1}`, `c`
can be calculated using the using the following sum.

Note that `i * (i + 1) / 2`, is the formula for the sum of the first `i`
natural numbers.

```math
      n
c  =  Σ  i * (i + 1) / 2 * f
 n   i=1                    n-i
```

Calculating `d`
---------------

Consider d for the first few values:

```math
d_0 = 0
d_1 = d_0 + c_1
d_2 = d_1 + c_2
d_3 = d_2 + c_3
```

Expand the values for d_3:

```math
d_3 = c_1 + c_2             + c_3
d_3 = f_0 + (3 * f_0 + f_1) + (6 * f_0 + 3 * f_1 + f_2)
d_3 = 10 * f_0 + 4 * f_1 + f_2

d_n = (sum(1..1) + ... + sum(1..n)) * f_0 + (sum(1..1) + ... + sum(1..n-1)) * f_1 + ...
```

That is, the sum of sums from 1 to `n`. Starting the sum at `f_{n-1}`, `d`
can be calculated using the following sum.

Note that `i * (i + 1) * (i + 2) / 6` is the formula for the sum of sums from
1 to `i`.

```math
      n
d  =  Σ  i * (i + 1) * (i + 2) / 6 * f
 n   i=1                              n-i
```

SIMD computation
----------------

Based on Intel's Fast Computation of Fletcher Checksums.

One way of speeding up the Fletcher4 computation, is to use SIMD instructions,
and process the input in chunks using parallel streams.

That is, each accumulator sums the nth value. At the end of the calculation,
the parallel streams need to be combined.

Dual Stream SIMD
----------------

Assume two parallel streams, and adjust the sumation for `a`. Instead of
summing `i` from 1 to `n`, use `i` from 1 to `n/2`.

The computation for `a` is straightforward, because it is a simple sumation,
so the final result is a sum of the two lanes.

```math
     n/2              n/2
a' =  Σ  f     , a' =  Σ  f
 1   i=1  n-2i    2   i=1  n-2i-1

a  = a' + a'
 n    1    2
```

For `b`, the computation is a little more complex. What each lane has computed is:

```math
     n/2                  n/2
b' =  Σ  i * f     , b' =  Σ  i * f
 1   i=1      n-2i    2   i=1      n-2i-1
```

The computation that is required, is slightly different (`i` needs to be fixed).
For each sumation, expand the formula, and find a combination of `a'` and `b'`
that will result in the same value.

```math
     n/2
b" =  Σ  2i * f
 1   i=1       n-2i

   = 2 * Σ i * f
   = 2b'

     n/2
b" =  Σ  (2i - 1) * f
 2   i=1             n-2i-1

   = Σ 2i * f - f
   = 2b' - a'

b  = 2b' + 2b' - a'
 n     1     2    2

   = 2(b' + b') - a'
        1    2     2
```

For `c`, each lane has computed:

```math
     n/2                            n/2
c' =  Σ  i * (i + 1) / 2 * f      =  Σ  (i^2 + i) / 2 * f
 1   i=1                    n-2i    i=1                  n-2i

     n/2
c' =  Σ  i * (i + 1) / 2 * f
 2   i=1                    n-2i-1
```

Substituting for `i` to calculate what is required:

```math
     n/2
c" =  Σ  2i * (2i + 1) / 2 * f
 1   i=1                     n-2i

   = Σ (4i^2 + 2i) / 2 * f
   = Σ (4i^2 + 4i - 2i) / 2 * f
   = Σ (4i^2 + 4i) / 2 * f - 2i / 2 * f
   = Σ (4i^2 + 4i) / 2 * f - i * f
   = 4c' - b'

     n/2
c" =  Σ  (2i - 1) * (2i - 1 + 1) / 2 * f
 2   i=1                                n-2i-1

   = Σ (2i - 1) * 2i / 2 * f
   = Σ (4i^2 - 2i) / 2 * f
   = Σ (4i^2 + 4i - 6i) / 2 * f
   = Σ (4i^2 + 4i) / 2 * f - 6i / 2 * f
   = Σ (4i^2 + 4i) / 2 * f - 3i * f
   = 4c' - 3b'

c  = 4c' - b' + 4c' - 3b'
 n     1    1     2     2

   = 4(c' + c') - (b' + 3b')
        1    2      1     2
```

For `d` each lane has computed:

```math
     n/2                                     n/2
d' =  Σ  i * (i + 1) * (i + 2) / 6 * f     =  Σ  (i^3 + 3i^2 + 2i) / 6 * f
 1   i=1                              n-2i   i=1                          n-2i

     n/2
d' =  Σ  i * (i + 1) * (i + 2) / 6 * f
 2   i=1                              n-2i-1
```

Substituting for `i` to calculate what is required:

```math
     n/2
d" =  Σ  2i * (2i + 1) * (2i + 2) / 6 * f
 1   i=1                                 n-2i

   = Σ 2i * (4i^2 + 6i + 2) / 6 * f
   = Σ (8i^3 + 12i^2 + 4i) / 6 * f
   = Σ (8i^3 + 24i^2 + 16i - 12i^2 - 12i) / 6 * f
   = Σ (8i^3 + 24i^2 + 16i) / 6 * f - (12i^2 + 12i) / 6 * f
   = Σ 8 * (i^3 + 3i^2 + 2i) / 6 * f - 12 * (i^2 + i) / 6 * f
   = Σ 8 * (i^3 + 3i^2 + 2i) / 6 * f - 4 * (i^2 + i) / 2 * f
   = 8d' - 4c'

     n/2
d" =  Σ  (2i - 1) * (2i - 1 + 1) * (2i - 1 + 2) / 6 * f
 2   i=1                                               n-2i-1

   = Σ (2i - 1) * 2i * (2i + 1) / 6 * f
   = Σ 2i * (4i^2 - 1) / 6 * f
   = Σ (8i^3 - 2i) / 6 * f
   = Σ (8i^3 + 24i^2 + 16i - 24i^2 - 18i) / 6 * f
   = Σ (8i^3 + 24i^2 + 16i) / 6 * f - (24i^2 + 18i) / 6 * f
   = Σ 8 * (i^3 + 3i^2 + 2i) / 6 * f - (24i^2 + 24i - 6i) / 6 * f
   = Σ 8 * (i^3 + 3i^2 + 2i) / 6 * f - (24i^2 + 24i) / 6 * f + 6i / 6 * f
   = Σ 8 * (i^3 + 3i^2 + 2i) / 6 * f - 24 * (i^2 + i) / 6 * f + i * f
   = Σ 8 * (i^3 + 3i^2 + 2i) / 6 * f - 8 * (i^2 + i) / 2 * f  + i * f
   = 8d' - 8c' + b'

d = 8d' - 4c' + 8d' - 8c' + b'
 n    1     1     2     2    2

  = 8(d' + d') - (4c' + 8c') + b'
       1    2       1     2     2
```

Quad Stream SIMD
----------------

Assume four parallel streams.

`a`

```math
     n/4              n/4                n/4                n/4
a' =  Σ  f     , a' =  Σ  f       , a' =  Σ  f       , a' =  Σ  f
 1   i=1  n-4i    2   i=1  n-4i-1    3   i=1  n-4i-2    4   i=1  n-4i-3

a  = a' + a' + a' + a'
 n    1    2    3    4
```

`b`

```math
     n/4
b' =  Σ  i * f
 1   i=1      n-4i

     n/4                          n/4
b" =  Σ  4i * f            , b" =  Σ  (4i - 1) * f
 1   i=1       n-4i           2   i=1             n-4i-1

     n/4                          n/4
b" =  Σ  (4i - 2) * f      , b" =  Σ  (4i - 3) * f
 3   i=1            n-4i-2    3   i=1             n-4i-3

b  = 4b' + 4b' - a' + 4b' - 2a' + 4b' - 3a'
 n     1     2    2     3     3     4     4

   = 4(b' + b' + b' + b') - (a' + 2a' + 3a')
        1    2    3    4      2     3     4
```

`c`

```math
     n/4                            n/4
c' =  Σ  i * (i + 1) / 2 * f      =  Σ  (i^2 + i) / 2 * f
 1   i=1                    n-4i    i=1                  n-4i

c" = Σ ((4i)^2 + 4i) / 2 * f
 1
   = Σ (16i^2 + 4i) / 2 * f
   = Σ (16i^2 + 16i - 12i) / 2 * f
   = Σ (16i^2 + 16i) / 2 * f - 12i / 2 * f
   = Σ (16i^2 + 16i) / 2 * f - 6i * f
   = 16c' - 6b'

c" = Σ ((4i - 1)^2 + (4i - 1)) / 2 * f
 2
   = Σ (16i^2 - 8i + 1 + 4i - 1) / 2 * f
   = Σ (16i^2 - 4i) / 2 * f
   = Σ (16i^2 + 16i - 20i) / 2 * f
   = Σ (16i^2 + 16i) / 2 * f - 20i / 2 * f
   = 16c' - 10b'

c" = Σ ((4i - 2)^2 + (4i - 2)) / 2 * f
 3
   = Σ (16i^2 - 16i + 4 + 4i - 2) / 2 * f
   = Σ (16i^2 - 12i + 2) / 2 * f
   = Σ (16i^2 + 16i - 28i + 2) / 2 * f
   = Σ (16i^2 + 16i) / 2 * f - (28i - 2) / 2 * f
   = Σ (16i^2 + 16i) / 2 * f - 14i * f + f
   = 16c' - 14b' + a'

c" = Σ ((4i - 3)^2 + (4i - 3)) / 2 * f
 4
   = Σ (16i^2 - 24i + 9 + 4i - 3) / 2 * f
   = Σ (16i^2 - 20i + 6) / 2 * f
   = Σ (16i^2 + 16i - 36i + 6) / 2 * f
   = Σ (16i^2 + 16i) / 2 * f - (36i - 6) / 2 * f
   = Σ (16i^2 + 16i) / 2 * f - 18i * f + 3 * f
   = 16c' - 18b' + 3a'

c  = 16c' - 6b' + 16c' - 10b' + 16c' - 14b' + a' + 16c' - 18b' + 3a'
 n      1     1      2      2      3      3    3      4      4     4

   = 16(c' + c' + c' + c') - (6b' + 10b' + 14b' + 18b') + a' + 3a'
         1    2    3    4       1      2      3      4     3     4
```

`d`

```math
     n/4                                     n/4
d' =  Σ  i * (i + 1) * (i + 2) / 6 * f     =  Σ  (i^3 + 3i^2 + 2i) / 6 * f
 1   i=1                              n-4i   i=1                          n-4i

d" = Σ ((4i)^3 + 3*(4i)^2 + 2 * 4i) / 6 * f
 1
   = Σ (64i^3 + 48i^2 + 8i) / 6 * f
   = Σ (64i^3 + 192i^2 + 128i - 144i^2 - 120i) / 6 * f
   = Σ (64i^3 + 192i^2 + 128i) / 6 * f - (144i^2 + 120i) / 6 * f
   = 64d' - Σ (48i^2 + 40i) / 2 * f
   = 64d' - Σ (48i^2 + 48i - 8i) / 2 * f
   = 64d' - Σ (48i^2 + 48i) / 2 * f + 4i * f
   = 64d' - 48c' + 4b'

d" = Σ ((4i - 1)^3 + 3*(4i - 1)^2 + 2 * (4i - 1)) / 6 * f
 2
   = Σ (64i^3 - 4i) / 6 * f
   = Σ (64i^3 + 192i^2  + 128i - 192i^2 - 132i) / 6 * f
   = Σ (64i^3 + 192i^2  + 128i) / 6 * f - (192i^2 + 132i) / 6 * f
   = 64d' - Σ (192i^2 + 192i - 60i) / 6 * f
   = 64d' - Σ (192i^2 + 192i) / 6 * f + 60i / 6 * f
   = 64d' - Σ (64i^2 + 64i) / 2 * f + 10i * f
   = 64d' - 64c' + 10b'

d" = Σ ((4i - 2)^3 + 3*(4i - 2)^2 + 2 * (4i - 2)) / 6 * f
 3
   = Σ (64i^3 - 48i^2 + 8i) / 6 * f
   = Σ (64i^3 + 192i^2 + 128i) / 6 * f - (240i^2 + 120i) / 6 * f
   = 64d' - Σ (240i^2 + 240i) / 6 * f + 120i / 6 * f
   = 64d' - Σ (80i^2 + 80i) / 2 * f + 20i * f
   = 64d' - 80c' + 20b'

d" = Σ ((4i - 3)^3 + 3*(4i - 3)^2 + 2 * (4i - 3)) / 6 * f
 4
   = Σ (64i^3 - 96i^2 + 44i - 6) / 6 * f
   = Σ (64i^3 + 192i^2 + 128i - 288i^2 - 84i - 6) / 6 * f
   = 64d' - Σ (288i^2 + 84i + 6) / 6 * f
   = 64d' - Σ (288i^2 + 288i - 204i + 6) / 6 * f
   = 64d' - Σ (288i^2 + 288i) / 6 * f - (204i - 6) / 6 * f
   = 64d' - Σ (96i^2 + 96i) / 2 * f - (204i - 6) / 6 * f
   = 64d' - 96c' + Σ (34i - 1) * f
   = 64d' - 96c' + 34b' - a'

d  = 64d' - 48c' + 4b' + 64d' - 64c' + 10b' + 64d' - 80c' + 20b' + 64d' - 96c' + 34b' - a'
 n      1      1     1      2      2      2      3      3      3      4      4      4    4

   = 64(d' + d' + d' + d') - (48c' + 64c' + 80c' + 96c') + (4b' + 10b' + 20b' + 34b') - a'
         1    2    3    4        1      2      3      4       1      2      3      4     4
```

Octo Stream SIMD
----------------

Assume eight parallel streams.

`a`

```math
a  = a' + a' + ... + a'
 n    1    2          8
```

`b`

```math
b" = Σ 8i * f = 8b'
 1                1

b" = Σ (8i - 1) * f = 8b' - a'
 2                      2    2

b" = Σ (8i - 2) * f = 8b' - 2a'
 3                      3     3

b  = 8b' + 8b' - a' + 8b' - 2a' + ... + 8b' - 7a'
 n     1     2    2     3     3           8     8
```

`c`

```math
     n/8                            n/8
c' =  Σ  i * (i + 1) / 2 * f      =  Σ  (i^2 + i) / 2 * f
 1   i=1                    n-8i    i=1                  n-8i

     n/8
c" =  Σ ((8i)^2 + 8i) / 2 * f
 1   i=1                     n-8i

   = Σ (64i^2 + 8i) / 2 * f
   = Σ (64i^2 + 64i - 56i) / 2 * f
   = Σ (64i^2 + 64i) / 2 * f - 56i / 2 * f
   = 64c' - 28b'

c" = Σ ((8i - 1)^2 + 8i - 1) / 2 * f
 2
   = Σ (64i^2 - 16i + 1 + 8i - 1) / 2 * f
   = Σ (64i^2 + 64i - 72i) / 2 * f
   = Σ (64i^2 + 64i) / 2 * f - 72i / 2 * f
   = 64c' - 36b'

c" = Σ ((8i - 2)^2 + 8i - 2) / 2 * f
 3
   = Σ (64i^2 - 32i + 4 + 8i - 2) / 2 * f
   = Σ (64i^2 + 64i - 88i + 2) / 2 * f
   = 64c' - 44b' + a'

c" = Σ ((8i - 3)^2 + 8i - 3) / 2 * f
 4
   = Σ (64i^2 - 48i + 9 + 8i - 3) / 2 * f
   = Σ (64i^2 - 40i + 6) / 2 * f
   = Σ (64i^2 + 64i - 104i + 6) / 2 * f
   = 64c' - 52b' + 3a'

c" = Σ ((8i - 4)^2 + 8i - 4) / 2 * f
 5
   = Σ (64i^2 - 64i + 16 + 8i - 4) / 2 * f
   = Σ (64i^2 + 64i - 120i + 12) / 2 * f
   = 64c' - 60b' + 6a'

c" = Σ ((8i - 5)^2 + 8i - 5) / 2 * f
 6
   = Σ (64i^2 - 80i + 25 + 8i - 5) / 2 * f
   = Σ (64i^2 + 64i - 136i + 20) / 2 * f
   = 64c' - 68b' + 10a'

c" = Σ ((8i - 6)^2 + 8i - 6) / 2 * f
 7
   = Σ (64i^2 - 96i + 36 + 8i - 6) / 2 * f
   = Σ (64i^2 + 64i - 152i + 30) / 2 * f
   = 64c' - 76b' + 15a'

c" = Σ ((8i - 7)^2 + 8i - 7) / 2 * f
 8
   = Σ (64i^2 - 112i + 49 + 8i - 7) / 2 * f
   = Σ (64i^2 + 64i - 168i + 42) / 2 * f
   = 64c' - 84b' + 21a'

c  = 64(c' + .. + c') - (28b' + 36b' + 44b' + 52b' + 60b' + 68b' + 76b' + 84b')
 n       1         8        1      2      3      4      5      6      7      8

   + a' + 3a' + 6a' + 10a' + 15a' + 21a'
      3     4     5      6      7      8
```

`d`

```math
     n/8                                     n/8
d' =  Σ  i * (i + 1) * (i + 2) / 6 * f     =  Σ  (i^3 + 3i^2 + 2i) / 6 * f
 1   i=1                              n-8i   i=1                          n-8i

     n/8
d" =  Σ ((8i)^3 + 3(8i)^2 + 2(8i)) / 6 * f
 1   i=1                                n-8i

   = Σ (512i^3 + 192i^2 + 16i) / 6 * f
   = Σ (512i^3 + 1536i^2 + 1024i - 1344i^2 - 1008i) / 6 * f
   = Σ (512i^3 + 1536i^2 + 1024i) / 6 * f - (1344i^2 + 1008i) / 6 * f
   = 512d' - Σ (448i^2 + 336i) / 2 * f
   = 512d' - Σ (448i^2 + 448i) / 2 * f - 112i / 2 * f
   = 512d' - 448c' + 56b'

     n/8
d" =  Σ ((8i-1)^3 + 3(8i-1)^2 + 2(8i-1)) / 6 * f
 2   i=1                                        n-8i-1

   = Σ (512i^3 - 8i) / 6 * f
   = Σ (512i^3 + 1536i^2 + 1024i - 1536i^2 - 1032i) / 6 * f
   = Σ (512i^3 + 1536i^2 + 1024i) / 6 * f - (1536i^2 + 1032i) / 6 * f
   = 512d' - Σ (512i^2 + 344i) / 2 * f
   = 512d' - Σ (512i^2 + 512i) / 2 * f - 168i / 2 * f
   = 512d' - 512c' + 84b'

     n/8
d" =  Σ ((8i-2)^3 + 3(8i-2)^2 + 2(8i-2)) / 6 * f
 3   i=1                                        n-8i-2

   = Σ (512i^3 - 192i^2 + 16i) / 6 * f
   = Σ (512i^3 + 1536i^2 + 1024i - 1728i^2 - 1008i) / 6 * f
   = Σ (512i^3 + 1536i^2 + 1024i) / 6 * f - (1728i^2 + 1008i) / 6 * f
   = 512d' - Σ (576i^2 + 336i) / 2 * f
   = 512d' - Σ (576i^2 + 576i) / 2 * f - 240i / 2 * f
   = 512d' - 576c' + 120b'

     n/8
d" =  Σ ((8i-3)^3 + 3(8i-3)^2 + 2(8i-3)) / 6 * f
 4   i=1                                        n-8i-3

   = Σ (512i^3 - 384i^2 + 88i - 6) / 6 * f
   = Σ (512i^3 + 1536i^2 + 1024i - 1920i^2 - 936i - 6) / 6 * f
   = Σ (512i^3 + 1536i^2 + 1024i) / 6 * f - (1920i^2 + 936i + 6) / 6 * f
   = 512d' - Σ (640i^2 + 312i + 2) / 2 * f
   = 512d' - Σ (640i^2 + 640i) / 2 * f - 328i / 2 * f + f
   = 512d' - 640c' + 164b' - a'

     n/8
d" =  Σ ((8i-4)^3 + 3(8i-4)^2 + 2(8i-4)) / 6 * f
 5   i=1                                        n-8i-4

   = Σ (512i^3 - 576i^2 + 208i - 24) / 6 * f
   = Σ (512i^3 + 1536i^2 + 1024i - 2112i^2 - 816i - 24) / 6 * f
   = Σ (512i^3 + 1536i^2 + 1024i) / 6 * f - (2112i^2 + 816i + 24) / 6 * f
   = 512d' - Σ (704i^2 + 272i + 24) / 2 + 4 * f
   = 512d' - Σ (704i^2 + 704i) / 2 - 432i / 2 * f + 4 * f
   = 512d' - 704c' + 216b' - 4a'

     n/8
d" =  Σ ((8i-5)^3 + 3(8i-5)^2 + 2(8i-5)) / 6 * f
 6   i=1                                        n-8i-5

   = Σ (512i^3 - 768i^2 + 376i - 60) / 6 * f
   = Σ (512i^3 + 1536i^2 + 1024i - 2304i^2 - 648i - 60) / 6 * f
   = Σ (512i^3 + 1536i^2 + 1024i) / 6 * f - (2304i^2 + 648i + 60) / 6 * f
   = 512d' - Σ (768i^2 + 216i + 20) / 2 * f
   = 512d' - Σ (768i^2 + 768i) / 2 * f - 552i / 2 * f + 10 * f
   = 512d' - 768c' + 276b' - 10a'

     n/8
d" =  Σ ((8i-6)^3 + 3(8i-6)^2 + 2(8i-6)) / 6 * f
 7   i=1                                        n-8i-6

   = Σ (512i^3 - 960i^2 + 592i - 120) / 6 * f
   = Σ (512i^3 + 1536i^2 + 1024i - 2496i^2 - 432i - 120) / 6 * f
   = Σ (512i^3 + 1536i^2 + 1024i) / 6 * f - (2496i^2 + 432i + 120) / 6 * f
   = 512d' - Σ (832i^2 + 144i + 40) / 2 * f
   = 512d' - Σ (832i^2 + 832i) / 2 * f - 688i / 2 * f + 40 / 2 * f
   = 512d' - 832c' + 344b' - 20a'

     n/8
d" =  Σ ((8i-7)^3 + 3(8i-7)^2 + 2(8i-7)) / 6 * f
 8   i=1                                        n-8i-7

   = Σ (512i^3 - 1152i^2 + 856i - 210) / 6 * f
   = Σ (512i^3 + 1536i^2 + 1024i - 2688i^2 - 168i - 210) / 6 * f
   = Σ (512i^3 + 1536i^2 + 1024i) - (2688i^2 + 168i + 210) / 6 * f
   = 512d' - Σ (896i^2 + 56i + 70) / 2 * f
   = 512d' - Σ (896i^2 + 896i) / 2 * f - 840i / 2 * f + 70 / 2 * f
   = 512d' - 896c' + 420b' - 35a'
```

Test Case Generation
--------------------

Python script to generate test cases for `checksum::fletcher4::tests`.

```python
#!/usr/bin/env python3
import struct

test_vector = [
  0xbc, 0x4b, 0x4d, 0x58, 0x43, 0xca, 0x34, 0x35, 0xe4, 0xd0, 0x59, 0xe4, 0xd0, 0x2b, 0x08,
  0xe3, 0x2f, 0xe3, 0x78, 0xe1, 0xe6, 0xf6, 0xf1, 0x34, 0x84, 0xdc, 0x1e, 0x0e, 0x12, 0x28,
  0x2e, 0xbe, 0x53, 0xbd, 0x1a, 0xf9, 0x8a, 0x97, 0x6e, 0xab, 0x7c, 0x06, 0xed, 0x50, 0xa8,
  0xc9, 0xe4, 0x1e, 0xb8, 0xaf, 0xb8, 0x8c, 0x94, 0xb5, 0x15, 0xed, 0xa8, 0x3f, 0x9d, 0x99,
  0x9c, 0x26, 0xe8, 0x1d, 0x87, 0x29, 0x1f, 0x60, 0x64, 0xca, 0xd1, 0xe8, 0x48, 0x7e, 0xe4,
  0xf2, 0x56, 0xf3, 0x59, 0x73, 0x04, 0x39, 0xb2, 0x62, 0x56, 0xea, 0xf1, 0x44, 0xf0, 0x06,
  0x28, 0x2e, 0x56, 0x16, 0xd3, 0x80, 0x0d, 0x47, 0x9e, 0x87, 0x3f, 0x52, 0x64, 0x30, 0x63,
  0x6d, 0x64, 0x58, 0xcb, 0x84, 0x4d, 0xf7, 0x1c, 0x6e, 0xc7, 0x07, 0x86, 0x3d, 0x17, 0xec,
  0x51, 0x8f, 0x51, 0x6e, 0x5a, 0x52, 0x64, 0xee,
]

for unpack_fmt in (">I", "<I"):

    for size in 4, 8, 16, 32, 64, 128:
        a, b, c, d = 0, 0, 0, 0

        idx = 0
        data = test_vector[0:size]
        while idx < len(data):
            chunk = bytes(data[idx : idx + 4])
            idx += 4
            f = struct.unpack(unpack_fmt, chunk)[0]

            a += f
            b += a
            c += b
            d += c

        a = a % (1 << 64)
        b = b % (1 << 64)
        c = c % (1 << 64)
        d = d % (1 << 64)

        print(f"({size}, [{a:#016x}, {b:#016x}, {c:#016x}, {d:#016x}]), ")


    for size in 8192, 16384, 32768, 65536, 131072:
        a, b, c, d = 0, 0, 0, 0

        total = 0
        idx = 0

        while total < size:
            chunk = bytes(data[idx : idx + 4])

            total += 4
            idx += 4

            if idx == len(data):
                idx = 0

            f = struct.unpack(unpack_fmt, chunk)[0]

            a += f
            b += a
            c += b
            d += c

        a = a % (1 << 64)
        b = b % (1 << 64)
        c = c % (1 << 64)
        d = d % (1 << 64)

        print(f"({size}, [{a:#016x}, {b:#016x}, {c:#016x}, {d:#016x}]), ")
```
