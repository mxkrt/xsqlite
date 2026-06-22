''' _float_conversion - Python implementation of float related sqlite3 code

Functions that mimic the behaviour of various functions in util.c used in
the conversion of floating point values to a text representation that is
used in the ".dump" command. Based on analysis of the sqlite3 sources,
version 3530200.
'''

import struct as _struct
from binascii import hexlify as _hexlify
import math as _math

# range of powers of 10 that we need to deal with
# when converting IEEE754 doubls to and from decimal.
POWERSOF10_FIRST = -348
POWERSOF10_LAST  = 347

# unsigned 64-bit mask
u64_MASK = ((1 << 64) - 1)
# unsigned 128-bit mask
u128_MASK = ((1 << 128) - 1)

# number of digits to use in U64
SQLITE_U64_DIGITS = 20

# digit pairs used to convert a U64 or I64 into text (util.c line 996)
sqlite3DigitPairs = "00010203040506070809" +\
                    "10111213141516171819" +\
                    "20212223242526272829" +\
                    "30313233343536373839" +\
                    "40414243444546474849" +\
                    "50515253545556575859" +\
                    "60616263646566676869" +\
                    "70717273747576777879" +\
                    "80818283848586878889" +\
                    "90919293949596979899"

class FpDecode:
    ''' mimic FpDecode struct from sqliteInt.h '''

    def __init__(s):
        s.n = None         # significant digits
        s.iDP = None       # location of decimal point
        s.z = []           # store the significant digits
                           # (this simulates zBuf array with z pointer)
        s.sign = None      # + or -
        s.isSpecial = None # 1: Infinity 2: NaN


def U64_BIT(n): 
    ''' return a u64 with the N-th bit set '''
    return (1 << n)


def countLeadingZeros(m):
    ''' count leading zeros for a 64-bit unsigned integer. '''
    # util.c line 732
    n = 0
    if( m <= 0x00000000ffffffff): n += 32; m <<= 32
    if( m <= 0x0000ffffffffffff): n += 16; m <<= 16
    if( m <= 0x00ffffffffffffff): n += 8;  m <<= 8
    if( m <= 0x0fffffffffffffff): n += 4;  m <<= 4
    if( m <= 0x3fffffffffffffff): n += 2;  m <<= 2
    if( m <= 0x7fffffffffffffff): n += 1
    return n


def pwr2to10(p):
    ''' mimic pwr2to10 from util.c '''
    return (p * 78913) >> 18


def pwr10to2(p):
    ''' mimic prw10to2 from util.c '''
    return (p * 108853) >> 15


def sqlite3Multiply160(a, aLo, b, debug=False):
    ''' mimic sqlite3Multiply160 from util.c '''

    if debug is True:
        print(f"-> sqite3Multiply160({a},{aLo},{b})")

    a = a & u64_MASK
    b = b & u64_MASK
    aLo = aLo & 0xFFFFFFFF
    r = (a * b) + ((aLo * b) >> 32)
    pLo = (r >> 32) & 0xFFFFFFFF
    hi = (r >> 64) & u64_MASK
    return hi, pLo


def sqlite3Multiply128(a, b, debug=False):
    ''' mimic sqlite3Multiply128 from util.c '''

    if debug is True:
        print(f"-> sqite3Multiply128({a},{b})")

    # util.c lines 475 - 477
    r = (a & u64_MASK) * (b & u64_MASK)
    pLo = r & u64_MASK
    hi = (r >> 64) & u64_MASK
    return hi, pLo


def powerOfTen(p, debug=False):
    ''' mimic powerOfTen in util.c '''

    aBase = [
        0x8000000000000000, 0xa000000000000000, 0xc800000000000000, 0xfa00000000000000,
        0x9c40000000000000, 0xc350000000000000, 0xf424000000000000, 0x9896800000000000,
        0xbebc200000000000, 0xee6b280000000000, 0x9502f90000000000, 0xba43b74000000000,
        0xe8d4a51000000000, 0x9184e72a00000000, 0xb5e620f480000000, 0xe35fa931a0000000,
        0x8e1bc9bf04000000, 0xb1a2bc2ec5000000, 0xde0b6b3a76400000, 0x8ac7230489e80000,
        0xad78ebc5ac620000, 0xd8d726b7177a8000, 0x878678326eac9000, 0xa968163f0a57b400,
        0xd3c21bcecceda100, 0x84595161401484a0, 0xa56fa5b99019a5c8]

    aScale = [
        0x8049a4ac0c5811ae, 0xcf42894a5dce35ea, 0xa76c582338ed2621, 0x873e4f75e2224e68,
        0xda7f5bf590966848, 0xb080392cc4349dec, 0x8e938662882af53e, 0xe65829b3046b0afa,
        0xba121a4650e4ddeb, 0x964e858c91ba2655, 0xf2d56790ab41c2a2, 0xc428d05aa4751e4c,
        0x9e74d1b791e07e48, 0xcccccccccccccccc, 0xcecb8f27f4200f3a, 0xa70c3c40a64e6c51,
        0x86f0ac99b4e8dafd, 0xda01ee641a708de9, 0xb01ae745b101e9e4, 0x8e41ade9fbebc27d,
        0xe5d3ef282a242e81, 0xb9a74a0637ce2ee1, 0x95f83d0a1fb69cd9, 0xf24a01a73cf2dccf,
        0xc3b8358109e84f07, 0x9e19db92b4e31ba9
    ]

    aScaleLo = [
        0x205b896d, 0x52064cad, 0xaf2af2b8, 0x5a7744a7, 0xaf39a475, 0xbd8d794e,
        0x547eb47b, 0x0cb4a5a3, 0x92f34d62, 0x3a6a07f9, 0xfae27299, 0xaa97e14c,
        0x775ea265, 0xcccccccc, 0x00000000, 0x999090b6, 0x69a028bb, 0xe80e6f48,
        0x5ec05dd0, 0x14588f14, 0x8f1668c9, 0x6d953e2c, 0x4abdaf10, 0xbc633b39,
        0x0a862f81, 0x6c07a2c2
    ]

    if debug is True:
        print(f"-> PowerOfTen({p})")

    if p < POWERSOF10_FIRST or p > POWERSOF10_LAST:
        raise ValueError("p out of range")

    g = n = 0
    if p < 0:
        if p == -1:
            return aScale[13], aScaleLo[13]
        g = int(p / 27) # util.c line 681: p/27 truncates to 0
        n = p - 27 * g  # util.c line 682: p%27 maintains sign of remainder
        if n:
            g -= 1
            n += 27
    elif p < 27:
        return aBase[p], 0
    else:
        g = int(p / 27) # util.c line 691
        n = p - 27 * g  # util.c line 692

    if debug is True:
        print(f"   PowerOfTen: g={g},n={n}")

    s = aScale[g + 13]  # util.c line 694

    if debug is True:
        print(f"   PowerOfTen: s={s}")

    if n == 0:
        return s, aScaleLo[g + 13]

    x, lo = sqlite3Multiply160(s, aScaleLo[g + 13], aBase[n], debug)
    if debug is True:
        print(f"<- sqlite3Multiply160: {(x,lo)}")

    # util.c lines 700 rhrough 702
    if (1 << 63) & x == 0:
        x = ((x << 1) & u64_MASK) | ((lo >> 31) & 1)
        lo = ((lo << 1) & 0xFFFFFFFF) | 1

    return x & u64_MASK, lo & 0xFFFFFFFF


def sqlite3Fp10Convert2(d, p, debug=False):
    ''' mimic sqlite3Fp10Convert2 from util.c, line 780

    Return an IEEE754 floating point value that approximates d*pow(10,p)
    '''

    if debug is True:
        print(f"-> sqlite3Fp10Convert2({d, p})")

    d &= u64_MASK # d is a 64bit integer

    if p < POWERSOF10_FIRST: return 0.0         # util.c, line 785
    if p > POWERSOF10_LAST: return float("inf") # util.c, line 786

    # util.c line 787
    b = 64-countLeadingZeros(d)

    lp = pwr10to2(p)

    e = 53 - b - lp  # util.c, line 798

    if e > 1074:       # util.c line 790
        if e >=1130:
            return 0.0
        e = 1074

    s = -(e-(64-b) + lp + 3)

    pwr10h,pwr10l = powerOfTen(p, debug) # util.c line 795
    if pwr10l != 0:
        pwr10h += 1
        pwr10l = (~pwr10l) & u64_MASK
    if debug is True:
        print(f"   sqlite3Fp10Convert2: pwr10h={pwr10h},pwr10l={pwr10l}")

    x = (d << (64 - b)) & u128_MASK # util.c, line 800
    if debug is True:
        print(f"   sqlite3Fp10Convert2: x={x}")

    hi, lo = sqlite3Multiply128(x, pwr10h, debug)
    if debug is True:
        print(f"<- sqlite3Multiply128: ({hi,lo})")

    mid1 = lo>>32; # util.c, line 802
    sticky = 1

    if (hi & (U64_BIT(s) - 1)) == 0:
        # util.c, line 805
        u = ((pwr10l & u64_MASK) << 32) & u128_MASK
        hi2, lo2 = sqlite3Multiply128(x, u)
        mid2 = (lo2 >> 32) & u64_MASK
        sticky = 1 if (mid1 - mid2 > 1) else 0
        hi = hi - 1 if (mid1 < mid2) else hi

    # util.c, line 809
    u = (hi >> s) | sticky
    adj = 1 if (u >= U64_BIT(55) -2) else 0

    if adj:
        u = (u >> adj) | (u & 1)
        e -= adj

    # util.c, line 815
    m = (u + 1 + ((u >> 2) & 1)) >> 2

    # util.c, line 816
    if e <= -972: return float("inf")

    # util.c, line 817
    if (m & U64_BIT(52)) != 0:
        m = (m & ~U64_BIT(52)) | ((1075 - e) << 52)

    # util.c line 820
    return _struct.pack('>Q', m & u64_MASK)


def sqlite3Fp2Convert10(m, e, n, debug=False):
    ''' mimic sqlite3Fp2Convert10 from util.c

    Given m and e, which represent a quantity r == m*pow(2,e),
    return values *pD en *pP such that r == (*pD)*pow(10,*pP),
    approximately.
    '''

    if debug is True:
        print(f"-> sqlite3Fp2Convert10({m},{e},{n})")

    if n < 1 or n > 18:
        raise ValueError("n should be in range 1..18")

    p = n - 1 - pwr2to10(e + 63)

    # util.c line 762: h = sqlite3Multiply128(m, powerOfTen(p,&d2), &d1);
    h, d2 = powerOfTen(p, debug)
    if debug is True:
        print(f"<- powerOfTen: {h, d2}")
    h, d1 = sqlite3Multiply128(m, h, debug)
    if debug is True:
        print(f"-> powerOfTen: {(h,d1)}")

    # util.c line 763: assert( -(e + pwr10to2(p) + 2) >= 0  );
    if -(e + pwr10to2(p) + 2) < 0:
        raise ValueError("assert failed")
    # util.c line 764: assert( -(e + pwr10to2(p) + 1) <= 63 );
    if -(e + pwr10to2(p) + 1) > 63:
        raise ValueError("asserf failed")

    # util.c line 765 through 770
    if n == 18:
        shift = -(e + pwr10to2(p) + 2)
        h >>= shift
        pD = (h + ((h << 1) & 2)) >> 1
    else:
        shift = -(e + pwr10to2(p) + 1)
        pD = h >> shift

    pP = -p
    return pD & u64_MASK, int(pP)


def sqlite3FpDecode(r, iRound, mxRound, debug=False):
    ''' mimics the sqlite3FpDecode function

    Arguments:
    - p : FpDecode
    - r : double (bytes)
    - iRound, mxRound : round to min(iRound, mxRound) significant digits
    '''

    if debug is True:
        print(f"-> sqlite3FpDecode({_hexlify(r),iRound,mxRound})")

    # return value
    p = FpDecode()
    p.isSpecial = 0
    if mxRound < 0:
        raise ValueError("expected mxRound > 0")

    # simple decode to determine sign
    decoded_r = _struct.unpack('>d', r)[0]

    if debug is True:
        print(f"   sqlite3FpDecode: {decoded_r}")

    if decoded_r < 0:
        p.sign = '-'
        r = _struct.pack('>d', -decoded_r)

    elif decoded_r == 0.0:
        p.sign = '+'
        p.n = 1
        p.iDP = 1
        p.z = 0
        p.zBuf = [0]
        return p

    else:
        p.sign = '+'

    # copy the bytes into v and convert to int
    v = int.from_bytes(r[0:8], "big")
    # determine base-2 exponent (e)
    e = (v>>52)&0x7ff

    if debug is True:
        print(f"   sqlite3FpDecode: e={_hexlify(e.to_bytes(8, 'big', signed='True'))}")

    if (e == 0x7ff):
        # this is either infinit or NaN
        p.isSpecial = 1 + v != 0x7ff0000000000000
        p.n = 0
        p.iDP = 0
        p.z = 0
        return p

    v &= 0x000FFFFFFFFFFFFF
    vbytes = v.to_bytes(8, 'big')

    if debug is True:
        print(f"   sqlite3FpDecode: v={_hexlify(vbytes)}")

    if e == 0:
        # count leading zero's
        raise ValueError("check!")
        nn = len(hex(0xFFFFFFFFFFFFFFFF)) - len(hex(v))
        if debug is True:
            print(f"leading zeros    : {nn}")
        v <<= nn
        e = -1074 - nn
    else:
        v = ((v << 11) | (1 << 63)) & ((1 << 64) - 1)
        e -= 1086;

    if debug is True:
        print(f"   sqlite3FpDecode: {(v,e)}")
        print(f"   [intermediate  : {v*_math.pow(2,e)}]")

    if iRound <= 0 or iRound >= 18:
        n = 18
    else:
        n = iRound+1

    # util.c line 1428
    v, exp = sqlite3Fp2Convert10(v, e, n, debug)

    if debug is True:
        print(f"<- sqlite3Fp2Convert10: {(v, exp)}")
        print(f"   intermediate: {v*_math.pow(10, exp)}")

    # util.c line 1440
    i = SQLITE_U64_DIGITS
    p.zBuf = ["0"]*SQLITE_U64_DIGITS
    while v >= 10:
        # util.c line 1441: int kk = (v%100)*2
        kk = (v - int(v/100)*100) * 2
        p.zBuf[i - 2:i] = sqlite3DigitPairs[kk:kk + 2]
        i -= 2
        v //= 100
    if v:
        if i <= 0: raise ValueError("assert (i>0)");
        i-=1                   # util.c line 1452
        p.zBuf[i] = chr(ord('0') + v)
    if debug is True:
        zbuf = "".join(p.zBuf)
        print(f"   sqlite3FpDecode: zBuf: {zbuf}")

    # for practical reasons, convert to sequence of integers
    p.zBuf = [int(digit) for digit in p.zBuf]

    n = SQLITE_U64_DIGITS - i  # util.c line 1456
    p.iDP = n + exp            # util.c line 1459
    # util.c line 1460, iRound is never < 0, we use 17
    if iRound <= 0: raise ValueError("iRound <= 0")
    # create a read-only copy of zBuf starting at i
    z = p.zBuf[i:]          # util.c line 1469: z = &zBuf[i]
    z_ptr = i               # needed later for modifying zBuf
    if ( iRound > 0 and (iRound < n or n > mxRound) ):
        if (iRound > mxRound): iRound = mxRound
        if iRound == 17:  # util.c line 1472
            # try to reduce precision if that yields text that
            # will round-trip to the original floating-point
            # (this is the default for the ".dump" command)
            if z[15] == 9 and z[14] == 9:
                # util.c, line 1479
                jj = 14
                while jj > 0 and z[jj -1] == 9:
                    jj -= 1
                if jj == 0:
                    v2 = 1
                else:
                    v2 = z[0]
                    # util.c, line 1486
                    for kk in range(1, jj):
                        v2 = (v2 * 10) + z[kk]
                    v2 += 1
                round_trip = sqlite3Fp10Convert2(v2, exp + n -jj, debug)
                if round_trip == r:
                    iRound = jj+1
            # util.c line 1492
            elif (p.iDP>=n or (z[15]==0 and z[14]==0 and z[13]==0)):
                if z[0] == 0:
                    raise ValueError("assert( z[0]!='0'")
                jj = 13
                while jj > 0 and z[jj - 1] == 0:
                    jj -= 1
                v2 = z[0]
                for kk in range(1, jj):
                    v2 = v2 * 10 + z[kk]
                # util.c line 1499
                round_trip = sqlite3Fp10Convert2(v2, exp + n -jj, debug)
                if round_trip == r:
                    iRound = jj+1
            if debug == True:
                print(f"   sqlite3FpDecode: iRound = {iRound}")
            n = iRound
            # from here on down the C code modifies zBuf (via z pointer)
            # in order to round the last digits. We modify zBuf and not our
            # read-only copy z, so we need to use (z_ptr + j) into zBuf
            if z[iRound] >= 5:
                if debug == True:
                    print(f"   sqlite3FpDecode: z[{iRound}]={z[iRound]}")
                j = iRound-1
                while True:
                    # increment by one and check if we need roll-over
                    p.zBuf[z_ptr+j] += 1
                    if p.zBuf[z_ptr+j] <= 9:
                        # no roll-over needed, break
                        break
                    # if we get here, we need roll-over
                    # implemented in line 1510 and down
                    p.zBuf[z_ptr+j] = 0
                    if j == 0:
                        z_ptr -= 1
                        p.zBuf[z_ptr] = 1
                        n+=1
                        p.iDP+=1
                        break
                    else:
                        j-=1

                if debug is True:
                    zbuf = "".join(str(val) for val in p.zBuf)
                    print(f"   sqlite3FpDecode: zBuf: {zbuf}")

            if not n>0:
                raise ValueError("assert (n>0)")
            while p.zBuf[z_ptr+n-1] == 0:
                n-=1
                if not n>0:
                    raise ValueError("assert (n>0)")

            p.n = n
            p.z = z_ptr

    return p


def sqlite3_str_vappendf(value, debug=False):
    ''' minimal implementation to support etFLOAT '''

    # printf.c, line 555
    s = sqlite3FpDecode(value, 17, 20, debug)

    if s.isSpecial:
        raise ValueError("TODO isSpecial")

    if s.sign == '-':
        raise ValueError("TODO")

    # line 596, do we need this?
    # prefix = flag_prefix
    exp = s.iDP-1

    # case etFLOAT
    e2 = s.iDP -1
    return s


