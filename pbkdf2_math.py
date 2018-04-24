# -*- coding: utf-8 -*-
"""
    pbkdf2
    ~~~~~~

    This module implements pbkdf2 for Python.  It also has some basic
    tests that ensure that it works.  The implementation is straightforward
    and uses stdlib only stuff and can be easily be copy/pasted into
    your favourite application.

    Use this as replacement for bcrypt that does not need a c implementation
    of a modified blowfish crypto algo.

    Example usage:

    >>> pbkdf2_hex('what i want to hash', 'the random salt')
    'fa7cc8a2b0a932f8e6ea42f9787e9d36e592e0c222ada6a9'

    How to use this:

    1.  Use a constant time string compare function to compare the stored hash
        with the one you're generating::

            def safe_str_cmp(a, b):
                if len(a) != len(b):
                    return False
                rv = 0
                for x, y in izip(a, b):
                    rv |= ord(x) ^ ord(y)
                return rv == 0

    2.  Use `os.urandom` to generate a proper salt of at least 8 byte.
        Use a unique salt per hashed password.

    3.  Store ``algorithm$salt:costfactor$hash`` in the database so that
        you can upgrade later easily to a different algorithm if you need
        one.  For instance ``PBKDF2-256$thesalt:10000$deadbeef...``.


    :copyright: (c) Copyright 2011 by Armin Ronacher.
    :license: BSD, see LICENSE for more details.
"""
import hmac
import hashlib
from struct import Struct
from operator import xor
from itertools import izip, starmap


_pack_int = Struct('>I').pack


def pbkdf2_hex_32m_sha384(data, salt, iterations=32000000, keylen=24, hashfunc=hashlib.sha384):
    """Like :func:`pbkdf2_bin` but returns a hex encoded string."""
    return pbkdf2_bin(data, salt, iterations, keylen, hashfunc).encode('hex')

def pbkdf2_hex(data, salt, iterations=1000, keylen=24, hashfunc=None):
    """Like :func:`pbkdf2_bin` but returns a hex encoded string."""
    return pbkdf2_bin(data, salt, iterations, keylen, hashfunc).encode('hex')

def pbkdf2_bin(data, salt, iterations=1000, keylen=24, hashfunc=None):
    """Returns a binary digest for the PBKDF2 hash algorithm of `data`
    with the given `salt`.  It iterates `iterations` time and produces a
    key of `keylen` bytes.  By default SHA-1 is used as hash function,
    a different hashlib `hashfunc` can be provided.
    """
    hashfunc = hashfunc or hashlib.sha1
    mac = hmac.new(data, None, hashfunc)
    def _pseudorandom(x, mac=mac):
        h = mac.copy()
        h.update(x)
        return map(ord, h.digest())
    buf = []
    for block in xrange(1, -(-keylen // mac.digest_size) + 1):
        rv = u = _pseudorandom(salt + _pack_int(block))
        for i in xrange(iterations - 1):
            u = _pseudorandom(''.join(map(chr, u)))
            rv = list(starmap(xor, izip(rv, u)))
        buf.extend(rv)
    return ''.join(map(chr, buf))[:keylen]


def test():
    failed = []

    def check256(data, salt, iterations, keylen, expected):
        rv = pbkdf2_hex(data, salt, iterations, keylen, hashlib.sha256)
        if rv != expected:
            print 'Test failed:'
            print '  Expected:   %s' % expected
            print '  Got:        %s' % rv
            print '  Parameters:'
            print '    data=%s' % data
            print '    data (hex)=%s' % data.encode('hex')
            print '    salt=%s' % salt
            print '    salt(hex)=%s' % salt.encode('hex')
            print '    iterations=%d' % iterations
            print '    hashfunc = hashlib.sha256'
            print
            failed.append(1)

    def check512(data, salt, iterations, keylen, expected):
        rv = pbkdf2_hex(data, salt, iterations, keylen, hashlib.sha512)
        if rv != expected:
            print 'Test failed:'
            print '  Expected:   %s' % expected
            print '  Got:        %s' % rv
            print '  Parameters:'
            print '    data=%s' % data
            print '    data (hex)=%s' % data.encode('hex')
            print '    salt=%s' % salt
            print '    salt(hex)=%s' % salt.encode('hex')
            print '    iterations=%d' % iterations
            print '    hashfunc = hashlib.sha512'
            print
            failed.append(1)


    def check(data, salt, iterations, keylen, expected):
        rv = pbkdf2_hex(data, salt, iterations, keylen)
        if rv != expected:
            print 'Test failed:'
            print '  Expected:   %s' % expected
            print '  Got:        %s' % rv
            print '  Parameters:'
            print '    data=%s' % data
            print '    data (hex)=%s' % data.encode('hex')
            print '    salt=%s' % salt
            print '    salt(hex)=%s' % salt.encode('hex')
            print '    iterations=%d' % iterations
            print
            failed.append(1)
    # From RFC 6070
    check('password', 'salt', 1, 20,
          '0c60c80f961f0e71f3a9b524af6012062fe037a6')
    check('password', 'salt', 2, 20,
          'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957')
    check('password', 'salt', 4096, 20,
          '4b007901b765489abead49d926f721d065a429c1')
    check('passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt',
          4096, 25, '3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038')
    check('pass\x00word', 'sa\x00lt', 4096, 16,
          '56fa6aa75548099dcc37d7f03425e0c3')

    # From Crypt-PBKDF2
    check('password', 'ATHENA.MIT.EDUraeburn', 1, 16,
          'cdedb5281bb2f801565a1122b2563515')
    check('password', 'ATHENA.MIT.EDUraeburn', 1, 32,
          'cdedb5281bb2f801565a1122b25635150ad1f7a04bb9f3a333ecc0e2e1f70837')
    check('password', 'ATHENA.MIT.EDUraeburn', 2, 16,
          '01dbee7f4a9e243e988b62c73cda935d')
    check('password', 'ATHENA.MIT.EDUraeburn', 2, 32,
          '01dbee7f4a9e243e988b62c73cda935da05378b93244ec8f48a99e61ad799d86')
    check('password', 'ATHENA.MIT.EDUraeburn', 1200, 32,
          '5c08eb61fdf71e4e4ec3cf6ba1f5512ba7e52ddbc5e5142f708a31e2e62b1e13')
    check('X' * 64, 'pass phrase equals block size', 1200, 32,
          '139c30c0966bc32ba55fdbf212530ac9c5ec59f1a452f5cc9ad940fea0598ed1')
    check('X' * 65, 'pass phrase exceeds block size', 1200, 32,
          '9ccad6d468770cd51b10e6a68721be611a8b4d282601db3b36be9246915ec82a')
    print 'Fast SHA1 tests complete - if you did not see a failure warning, they worked.'
    # From http://stackoverflow.com/questions/5130513/pbkdf2-hmac-sha2-test-vectors
    check256('password', 'salt', 1, 32, 
          '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b')
    check256('password', 'salt', 2, 32, 
          'ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43')
    check256('password', 'salt', 4096, 32, 
          'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a')
    check256('passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt', 4096, 40, 
          '348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9')
    check256('pass\0word', 'sa\0lt', 4096, 16, 
          '89b69d0516f829893c696226650a8687')
    print 'Fast SHA256 tests complete - if you did not see a failure warning, they worked.'
    #From http://stackoverflow.com/questions/15593184/pbkdf2-hmac-sha-512-test-vectors
    check512('password', 'salt', 1, 64, 
          '867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce')
    check512('password', 'salt', 2, 64, 
          'e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53cf76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e')
    check512('password', 'salt', 4096, 64, 
          'd197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5')
    check512('passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt', 4096, 64, 
          '8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868c005174dc4ee71115b59f9e60cd9532fa33e0f75aefe30225c583a186cd82bd4daea9724a3d3b8')


    print 'Fast SHA512 tests complete - if you did not see a failure warning, they worked.'

    print 'Starting slow tests!'
    # This one is from the RFC but it just takes for ages
    check('password', 'salt', 16777216, 20,
          'eefe3d61cd4da4e4e9945b3d6ba2158c2634e984')
    print 'Slow SHA1 tests complete'    
    check256('password', 'salt', 16777216, 32,
          'cf81c66fe8cfc04d1f31ecb65dab4089f7f179e89b3b0bcb17ad10e3ac6eba46')
    print 'Slow SHA256 tests complete'


    raise SystemExit(bool(failed))


if __name__ == '__main__':
    test()
