''' _float_conversion - Python implementation of float related sqlite3 code

Floating point conversion is tricky, because floating point values are
approximate and converting to TEXT and back may lead to differences depending
on the format string used in the conversion.  SQLite takes special care to make
sure that a conversion to TEXT and back to binary representation (IEEE 754
Binary-64 format) is round-trip exact. For this, SQLite has implemented it's
own version of printf. In older versions of SQLite this was implemented in
sqlite3VXPrintf, in later versions the behaviour has changed and the code has
moved to sqlite3_str_vapendf. This function exists in printf.c.

See https://sqlite.org/floatingpoint.html for details.

In order for our ".dump" implementation to behave in the same manner, we need
to implement part of this logic in xsqlite. This source file contains part of
the functions in printf.c and util.c that we use to mimic the floating point
conversion behaviour. This is based on analysis of source version 3530200,
downloaded from here: https://sqlite.org/2026/sqlite-src-3530200.zip

Note that the output will likely be different when comparing to older
versions of SQLite (prior to 3.52.0) where a different algorithm was used.
'''

import struct as _struct
from binascii import hexlify as _hexlify
import math as _math
from collections import namedtuple as _nt

# range of powers of 10 that we need to deal with
# when converting IEEE754 doubls to and from decimal.
POWERSOF10_FIRST = -348
POWERSOF10_LAST  = 347

# unsigned 32-bit mask
u32_MASK = ((1 << 32) - 1)
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


# object that receives the decoding of a floating point value
# into an approximate decimal representation (sqliteInt.h, 4840)
# n         : Significant digits in the decode
# iDP       : Location of decimal point
# z         : Start of significant bits (ptr -> index in Python)
# zBuf      : Storage for significant digits (char array -> list in Python)
# sign      : '+' or '-'
# isSpecial : 1: Infinity, 2: NaN
FpDecode_t = _nt('FpDecode', 'n iDP z zBuf sign isSpecial')


# printf.c, line 18, only three conversion types needed
etFLOAT = 1
etEXP = 2
etGENERIC = 3


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

    # util.c, line 727: return (p * 78913) >> 18
    # assumption: int=32-bit signed integer
    sign = 1 << (32-1)
    x = (p * 78913) & u32_MASK
    x = x - (1 << 32) if (x & sign) else x
    return x >> 18


def pwr10to2(p):
    ''' mimic prw10to2 from util.c '''

    # util.c, line 726: return (p * 108853) >> 15
    # assumption: int=32-bit signed integer
    sign = 1 << (32-1)
    x = (p * 108853) & u32_MASK
    x = x - (1 << 32) if (x & sign) else x
    return x >> 15


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

    # initialize return value
    # util.c, line 1393: p->isSpecial=0
    p = FpDecode_t(0,0,0,[],'',0)
    if mxRound < 0:
        raise ValueError("expected mxRound > 0")

    # simple decode to determine sign
    decoded_r = _struct.unpack('>d', r)[0]

    if debug is True:
        print(f"   sqlite3FpDecode: {decoded_r}")

    if decoded_r < 0:
        p = p._replace(sign='-')
        r = _struct.pack('>d', -decoded_r)

    elif decoded_r == 0.0:
        # util.c, line 1402
        p = p._replace(sign='+', n=1, iDP=1, z=0, zBuf=['0'])
        return p

    else:
        p = p._replace(sign='+')

    # copy the bytes into v and convert to int
    v = int.from_bytes(r[0:8], "big")
    # determine base-2 exponent (e)
    e = (v>>52)&0x7ff

    if debug is True:
        print(f"   sqlite3FpDecode: e={_hexlify(e.to_bytes(8, 'big', signed='True'))}")

    if (e == 0x7ff):
        # this is either infinit or NaN
        # util.c line 1413
        isSpecial = 1
        if v != 0x7ff0000000000000:
            isSpecial+=1
        p = p._replace(n=0, iDP=0, z=0, isSpecial=isSpecial)
        return p

    # util.c, line 1419
    v &= 0x000FFFFFFFFFFFFF
    vbytes = v.to_bytes(8, 'big')

    if debug is True:
        print(f"   sqlite3FpDecode: v={_hexlify(vbytes)}")

    if e == 0:
        nn = countLeadingZeros(v)
        if debug is True:
            print(f"leading zeros    : {nn}")
        v <<= nn
        e = -1074 - nn
    else:
        v = ((v << 11) | (1 << 63)) & u64_MASK
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
    zBuf_ = ["0"]*SQLITE_U64_DIGITS
    p = p._replace(zBuf=zBuf_)
    while v >= 10:
        # util.c line 1441: int kk = (v%100)*2
        kk = (v - int(v//100)*100) * 2
        zBuf_[i - 2:i] = sqlite3DigitPairs[kk:kk + 2]
        i -= 2
        v //= 100
    if v:
        if i <= 0: raise ValueError("assert (i>0)");
        i-=1                   # util.c line 1452
        zBuf_[i] = chr(ord('0') + v)
    if debug is True:
        zbuf_p = "".join(zBuf_)
        print(f"   sqlite3FpDecode: zBuf: {zbuf_p}")

    # for practical reasons, convert to sequence of integers
    zBuf_ = [int(digit) for digit in zBuf_]

    n = SQLITE_U64_DIGITS - i  # util.c line 1456
    iDP_ = n + exp            # util.c line 1459

    # util.c line 1460, iRound is never < 0, we use 17
    if iRound <= 0: raise ValueError("iRound <= 0")
    # create a read-only copy of zBuf starting at i
    z = zBuf_[i:]          # util.c line 1469: z = &zBuf[i]
    z_ptr = i              # needed later for modifying zBuf
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
            elif (iDP_>=n or (z[15]==0 and z[14]==0 and z[13]==0)):
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
                    zBuf_[z_ptr+j] += 1
                    if zBuf_[z_ptr+j] <= 9:
                        # no roll-over needed, break
                        break
                    # if we get here, we need roll-over
                    # implemented in line 1510 and down
                    zBuf_[z_ptr+j] = 0
                    if j == 0:
                        z_ptr -= 1
                        zBuf_[z_ptr] = 1
                        n+=1
                        iDP_+=1
                        break
                    else:
                        j-=1

                if debug is True:
                    zbuf_p = "".join(str(val) for val in zBuf_)
                    print(f"   sqlite3FpDecode: zBuf: {zbuf_p}")

            if not n>0:
                raise ValueError("assert (n>0)")
            while zBuf_[z_ptr+n-1] == 0:
                n-=1
                if not n>0:
                    raise ValueError("assert (n>0)")

    # replace the digits with characters again
    zBuf_ = [str(digit) for digit in zBuf_]
    # update the FpDecode object
    p = p._replace(zBuf=zBuf_, iDP=iDP_,n=n,z=z_ptr)

    return p


def sqlite3_float_to_text(value, debug=False):
    ''' minimal implementation of sqlite3_str_vappendf in printf.c

    Only the minimum to create text representation of floating point
    values is implemented.
    '''

    # we accept Python float (64-bit) or bytes holding an IEEE-754 float
    if isinstance(value, float):
        value = _struct.pack('>d', value)
    elif isinstance(value, bytes):
        if len(value) != 8:
            raise ValueError("We expect 8 bytes, IEEE 754 float")
    else:
        raise ValueError("We expect either a float or bytes")

    # The sqlite3_str_vappendf function takes a format string and a list of
    # arguments and in order to determine how the conversion is done for
    # floating point numbers we need to track the function call throughout
    # the source code. We start at the handling of the cli ".dump" command,
    # since this is where all column values are converted to TEXT in order
    # to include them in de SQL statements.
    #
    # We start in shell.c.in in the function do_meta_command. In the code
    # responsiple for dealing with the ".dump" command, we see:
    #
    #    run_table_dump_query(p, zSql);
    #
    # Within this function we see for each row, the columns are converted to
    # text with a call to this function, where i is the column index
    #
    #    cli_printf(p->out, ",%s", sqlite3_column_text(pSelect, i));
    #
    # The sqlite3_column_text is located in vdbeapi.c and in turn calls:
    #
    #    const unsigned char *val = sqlite3_value_text( columnMem(pStmt,i) );
    #
    # This function (within vdbeapi.c as well) is a wrapper for another
    # function:
    #
    #    return (const unsigned char *)sqlite3ValueText(pVal, SQLITE_UTF8);
    #
    # This function in vdbemem.c checks some assumptions and tests if the
    # value already is a valid string representation. If not, the following
    # function is called to convert the value to text:
    #
    #    return valueToText(pVal, enc);
    #
    # Here, enc is SQLITE_UTF8 in the code-path we are analyzing. This
    # function also is in vdbemem.c and starts again with some asserts to
    # check the provided argument. Next, it is checked if the value is
    # either BLOB or TEXT and it is dealth with accordingly. Finally, and
    # the case we are interested in is when the type of value is different,
    # in which case the following is called:
    #
    #    sqlite3VdbeMemStringify(pVal, enc, 0);
    #
    # This function, first checks if we are indeed dealing with Int, Real
    # or IntReal, among other checks.
    #
    #    assert( pMem->flags&(MEM_Int|MEM_Real|MEM_IntReal) );
    #
    # The function then calls the following to convert the value to text:
    #
    #    vdbeMemRenderNum(nByte, pMem->z, pMem);
    #
    # This function, still in the same source file has the following
    # comment:
    #
    #    Render a Mem object which is one of MEM_Int, MEM_Real, or
    #    MEM_IntReal into a buffer.
    #
    # After some sanity checks and a workaround for a GCC bug, the
    # following code is relevant for conversion of Int and IntReal
    #
    #    p->n = sqlite3Int64ToText(p->u.i, zBuf);
    #
    # However, we are interested in float, so we end up in the else
    # statement where the following function is called:
    #
    #    sqlite3_str_appendf(&acc, "%!.*g",
    #         (p->db ? p->db->nFpDigit : 17), p->u.r);
    #
    # Here we see that the function is called with nFpDigit or as a
    # fallback the number 17. This number is used in place of the dot in
    # the format string !.*g. Here the ! sets "flag_altform2" to True,
    # which causes the sqlite3FpDecode function (see below) to use up to 20
    # digits, which is needed to make sure we have a round-trip accurate
    # conversion.
    #
    # This function is defined in printf.c and is a var-args wrapper for
    # sqlite3_str_vapppend:
    #
    #    sqlite3_str_vappendf(p, zFormat, ap);
    #
    # This function (which is the replacement of sqlite3VXPrintf) is the
    # actual work-horse of the format conversion. The conversion of floating
    # point values is dealt with from line 528:
    #
    #   case etFLOAT:
    #   case etEXP:
    #   case etGENERIC: {
    #
    # In this part of the code, the realvalue is parsed from the argument list.
    # The precision at this point is either nFpDigit or 17 when coming from the
    # sqlite3_str_appendf function call displayed above. The default for
    # nFpDigit (which seems to be available from version 3.52.0+) is 17, and it
    # is a connection-specific runtime configuration variable, so we can
    # probably assume 17 as the default value. We also know that we are dealing
    # with case etGENERIC, due to the 'g' in the format string. Thus, the
    # following part of the code is relevant for the precision:
    #
    #     }else if( xtype==etGENERIC ){
    #       if( precision==0 ) precision = 1;
    #       iRound = precision;
    #
    # So, for our partial implementation, we assume that iRound = 17 when the
    # following function call occurs:
    #
    #  sqlite3FpDecode(&s, realvalue, iRound, flag_altform2 ? 20 : 16);
    #
    # The sqlite3FpDecode function exists in util.c and decodes a
    # floating-point value into an approximate decimal representation. The
    # docstring says the following about the iRound and mxRound argument:
    #
    # if iRound>0 round to min(iRound,mxRound) significant digits total.
    #
    # We know that iRound is 17 and mxRound is 20 (because flag_altform2 is
    # enabled by '!' format string.
    #
    # Thus, we round to 17 significant digits.
    #
    # In summary: we know that we arrive here with the following format string
    # the format string %!.17g, so we have altform2, precision 17 and etGENERIC
    flag_altform2 = True
    precision = 17
    xtype = etGENERIC

    # the switch-case statement in line 410 brings us all the way to
    # line 530, since we have etGENERIC. Here we can skip further
    # initialization of precision, since we know it is 17
    # printf.c, line 551
    iRound = precision

    # printf.c, line 555
    s = sqlite3FpDecode(value, iRound, 20, debug)
    if debug is True:
        print(f"<- sqlite3FpDecode: {s}")

    # printf.c,line 558
    if s.isSpecial==2:
        return "NaN"
    elif s.isSpecial==1:
        # printf.c, line 566 - 573
        if s.sign=='-':
            return "-Inf"
        else:
            return "Inf"

    # since flag_prefix is not set, we only have to set
    # prefix when sign is negative (line 593)
    prefix=''
    if s.sign == '-':
        prefix='-'

    # line 599
    exp = s.iDP-1

    # printf.c line 605, we know that the case is etGENERIC, so
    # convert to etEXP or etFLOAT, as appropriate

    # printf.c line 607
    precision-=1
    flag_rtz = True            # because flag_alternateform is False
    if exp<-4 or exp>precision:
        xtype = etEXP
    else:
        precision = precision - exp
        xtype = etFLOAT

    #printf.c line 618
    if xtype==etEXP:
        e2 = 0;
    else:
        e2 = s.iDP -1

    # printf.c, line 646 is where a buffer is being initialized
    # combine with line 651 to initialize with prefix
    zOut = prefix

    # printf.c, line 654
    j = 0

    # printf.c, line 654 - 674
    if e2<0:
        zOut+='0'
    else:            # we do not need cThousand case
        j = e2+1
        if j>s.n:
            j = s.n
        # line 666, memcpy(bufpt, s.z, j)
        zOut+=''.join(s.zBuf[s.z:s.z+j])
        e2-=j
        if e2>=0:
            zOut+='0'*(e2+1)
            e2 = -1

    # printf.c, line 675, we always want decimal point (flag_altform2)
    flag_dp = True
    zOut+='.'

    # printf.c, line 681
    if e2 < -1 and precision>0:
        nn = -1-e2
        if nn > precision:
            nn=precision
        zOut+='0'
        precision-=nn

    # printf.c, line 689
    if precision>0:
        nn = s.n - j
        # skip over line 691, it is always false due to NEVER
        if nn>0:
            zOut+= ''.join(s.zBuf[s.z+j:s.z+j+nn])
            precision -= nn
        # line 697, add trailing zero's according to precision
        if precision>0:
            zOut+= '0'*precision

    # printf.c, line 703 remove trailing zero's
    zOut = zOut.rstrip('0')
    # printf.c, line 708, with altform2 we keep the
    # decimal point and add a final zero
    if zOut[-1]=='.':
        zOut+='0'

    # printf.c, line 715, Add the "eNNN" suffix
    if xtype==etEXP:
        exp = s.iDP - 1
        if exp < 0:
            zOut+=f'e-{exp}'
        else:
            zOut+=f'e+{exp}'

    return zOut


def _sqlite3VXPrintf(value, case=1):
    ''' Format floating point value similar to the way this is performed by the
    sqlite3VXPrintf function (in printf.c) as called (indirectly) from the
    quoteFunc (in func.c). When case=1, the %.15g formatting is returned, when
    case = 2, the %.20e formatting is returned.

    We cannot just use the python equivalent of .15g or .20e, since we've seen
    that the precision for the 'e' notation as produced by sqlite may differ.
    Additionally, the rounding and removal of terminating zeroes works a bit
    differently. In order to be able to verify our dumps with those produced by
    the native sqlite3 command we need to port this stuff to python. Only the
    bare minimum required for etGENERIC, etEXP and etFLOAT formatting (sqlite3
    terminology) is ported.
    '''

    # realvalue will be changed, keep value for normal .15g representation
    realvalue = value

    # some of the xtypes, just so we can use the same names here
    etFLOAT = 2
    etEXP = 3
    etGENERIC = 4

    if case == 1:
        # precision of 15 is decremented in line 467 for etGENERIC
        precision = 14
        xtype = etGENERIC
        precision -= 1

    elif case == 2:
        precision = 20
        xtype = etEXP
    else:
        raise ValueError('case can be one of [1,2]')

    # line 459, determine prefix
    prefix = ''
    if realvalue < 0.0:
        realvalue = -realvalue
        prefix = '-'

    # line 472, NaN
    if _math.isnan(realvalue):
        return 'NaN'

    # line 477, normalize to within (10.0, 1.0] range:
    exp = 0
    scale = 1.0
    result = ''
    # add prefix to result
    result += prefix

    # this seems to be updated in versions at higher than at least 3.8.7.1, on
    # which the previous version was based. This I changed here, but the entire
    # function needs revisiting, since I get rounding differences between the
    # xsqlite export and the native export
    if realvalue > 0.0:
        while (realvalue >= 1e100 * scale and exp <= 350):
            scale *= 1e100
            exp += 100
        while (realvalue >= 1e10 * scale and exp <= 350):
            scale *= 1e10
            exp += 10
        while (realvalue >= 10.0 * scale and exp <= 350):
            scale *= 10.0
            exp += 1
        realvalue /= scale
        while realvalue < 1e-8:
            realvalue *= 1e8
            exp -= 8
        while realvalue < 1.0:
            realvalue *= 10.0
            exp -= 1

        if exp > 350:
            result += 'Inf'
            return result

    # line 468, determine rounder
    rounder = 0.5
    for i in range(precision, 0, -1):
        rounder *= 0.1

    # line 503, convert etGENERIC to either etEXP or etFLOAT
    realvalue += rounder
    if realvalue >= 10.0:
        realvalue *= 0.1
        exp += 1

    # line 507, determine xtype based on exponent and precision
    if xtype == etGENERIC:
        if (exp < -4 or exp > precision):
            xtype = etEXP
        else:
            # at this point, everything is similar to python .15g formatting
            result = '{:.15g}'.format(float(value))
            # except for the additional .0 at the end
            if '.' not in result:
                result += '.0'
            return result

    # if we get here, xtype == etEXP, so no need to copy all checks

    # line 537, digits prior to decimal point (and part at line 498)
    # for etEXP this is always between 1 and 10, so e2 == 0
    # (no need to implement loop as in sqlite3VXPrintf)
    # add a digit and shift digits left (similar to et_getdigit)
    digit = int(realvalue)
    realvalue = (realvalue - digit) * 10
    result += str(digit)
    # line 545, decimal point (for etEXP always shown)
    result += '.'

    # line 555, significant digits after decimal point
    while precision > 0:
        precision -= 1
        digit = int(realvalue)
        realvalue = (realvalue - digit) * 10
        result += str(digit)

    # line 559, remove trailing zero's
    result = result.rstrip('0')

    # line 571, add the exponent with proper sign
    result += 'e'
    if exp < 0:
        result += '-'
        exp = -exp
    else:
        result += '+'
    if exp >= 100:
        result += '{:03d}'.format(exp)
    else:
        result += '{:02d}'.format(exp)

    return result
