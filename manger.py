import logging
import os
import math

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

# setup
def generate_keypair(size_N_in_bits):
    size_prime = 1 << (size_N_in_bits / 2)
    while True:
        p = random_prime(size_prime)
        q = random_prime(size_prime)
        N = p * q
        phi = (p-1)*(q-1)
        e = 17
        if gcd(e, phi) != 1:
            continue
        # will sometimes not work, generate another setup?
        d = inverse_mod(e, phi)
        break
    return e, d, N

# to do ceil() of large divisions
def ceildiv(a, b):
    return -(-a // b)

# helper
def get_byte_length(message):
    res = 0
    if (len(bin(message)) - 2) % 8 != 0:
        res += 1
    res += (len(bin(message)) - 2) // 8
    return res


# pad plaintext [00, 02, randoms, 00, messsage] of len target_length
def padding(message, target_length):
    # 02
    res = 0x02 << 8 * (target_length - 2)
    # random
    random_pad = os.urandom(target_length - 3 - get_byte_length(message))
    for idx, val in enumerate(random_pad):
        if val == 0:
            val = 1
        res += val << (len(random_pad) - idx + get_byte_length(message)) * 8
    # 00
    # message
    res += message

    return res


# a length oracle
def oracle_length(c, d, N):
    p = pow(c, d, N)
    return get_byte_length(p)

# our attack with Manger
def Manger(key_size, logging):
    # setup 1
    e = 65537
    d = 0x6c27f906388b272918e6c4be5f1980c2983a7585c7a00d9c9754a42aeba4a5ed969184711836e3eb67f4d57eb6a36bc3bf523c5ea6276a9d33afe0c1e4f9d74dd6b8d9769d8070d71442f346825d932f67e8b91947b8db6dec27f1b6ef586c4ac077e16cd2c931c3b6aaeac52aa51252bbe0a0acb6aa2e2d741963a8e760776cc6a5d5962d7096ce0e09dbcb35bd55b60e0cc800b87735facca85dd7d9efada97d7af151e93c0f995bd3a5d145e38a54ed286771b85699a35d98483f925482f3afe5ba9354d54d4cf2859013d810d6917e9b207fb9f7f52ad8ba3994b7e996db16211b4ef523c9b8fb17b373cc296c007ffd3cdc36cafe8af375252c4c0175f9
    N = 0x00caf32e78e4ef10e7811b1699477e688d805a2b4e5d218916194fbacdbb204e79718822d9ab880e711cbfc97e0eff6aa46a3cdd3fa7da3e1a3a69604fca418f43fdc31b037efd2896bcdc01e31a760cd95609b646edd2b99c48580f1ed63aedc5a9168bae770ceb4aed9f1c5deb67b1b76c058b9ce58086ce82e6c4e510357826b58502e26239d5827e756fa8e7f184137ada6f7b5e1bebcb551b14085951d8cfda661c488381c51652f14f2f9f8849ac9ac1cb51ddc29c3823af4a6cac17850a283dec6933d4dd8ac833edf9aef9b9a48f6d434c6c609e6cbbb6f32017e91ffc828ff375244768fc6ccbb2b5e5a3b18bcbe18d05ebb8559365e77d0a02ac2c11

    # setup 2
    N_size = 256
    plaintext = 0x6c6f6c  # "lol"
    #ciphertext = pub.encrypt(b"lol", PKCS1v15())
    #padded = padding(plaintext, N_size)
    padded = 0x2b93bccc20c71f2cd6172f7c2521931f08add5581a0f115443d41991f48bc69949490af2b9b3e393eeb8542e65ef0b6e959b5c2d4c7c217247151447c258b2fe5fd5e1642e05858399835174b7e5c828ad126eab96a7b0e14f8edbe18f958acb4edbc7a104ff013170b97b73eda8c7cb4412b4e708869012decdac51da0796bbdde80d28941afc1e5c50d27c01e1a42778a65e9d396a4dd19f60b8ae81cc97f2649a16d6b576ab68921b70ee0c119c6c6377a9bc20456a8393814b02da9f8fea8914e2ccf67170dea808afd4d246fda5562939a5d678253e1d72da16fbd59c11676957b3ef7feed0670d88e04fccbd14ff0a9ee9eaffc3f3b9584006c6f6c
    logging.info("to find: %d" % padded)
    ciphertext = pow(padded, e, N)
    # setup 3
    B = lower(N_size)
    total_msg = 0

    # setup attack
    N_bit_length = (N_size - 2) * 8

    # attack
    f1 = 2
    leak = 0

    # step 1
    logging.info("step 1.")
    while True:
        c2 = (ciphertext * pow(f1, e, N)) % N
        total_msg += 1
        leak = oracle_length(c2, d, N)
        if leak == N_size:
            logging.info("step 1.3b, msg "+str(total_msg))
            break
        logging.info("step 1.3a, msg "+str(total_msg))
        f1 = 2 * f1

    logging.info(str(total_msg) + " messages")

    # Step 2.
    logging.info("Step 2.")
    f2 = (N+B) // B
    f2 = f2 * (f1 // 2)
    while True:
        c2 = (ciphertext * pow(f2, e, N)) % N
        total_msg += 1
        leak = oracle_length(c2, d, N)
        if leak < N_size:
            logging.info("step 2.3b, msg "+str(total_msg))
            break
        logging.info("step 2.3a, msg "+str(total_msg))
        f2 = f2 + (f1//2)
    logging.info(str(total_msg) + " messages")
    
    # step 3.
    logging.info("Step 3.")
    m_min = ceildiv(N, f2)
    m_max = (N+B) // f2
    logging.info("\n- m_min: %d\n- m_max: %d\n" % (m_min, m_max))
    while True:
        # find good f3
        f_tmp = 2*B // (m_max - m_min)
        i = f_tmp * m_min // N
        f3 = ceildiv(i * N, m_min)
        # try the oracle
        c2 = (ciphertext * pow(f3, e, N)) % N
        total_msg += 1
        leak = oracle_length(c2, d, N)
        # branch
        if leak < N_size:
            logging.info("step 3.5b, msg "+str(total_msg))
            m_max = (i * N + B) // f3
        else:
            logging.info("3.5a, msg "+str(total_msg))
            m_min = ceildiv(i * N + B, f3)
        logging.info("\n- m_min: %d\n- 2find: %d\n- m_max: %d\n" % (m_min, padded, m_max))
        if m_min == m_max:
            break
        assert(total_msg<=200)
    if m_min != padded:
        logging.fatal("algorithm did not work")
        exit(1)
    logging.info(str(total_msg) + " messages")
    return total_msg


# for N_size = 2:
# m_max = 11111111 11111111
def upper(num):
    return 2**(num*8) - 1

# for N_size = 2:
# m_min = 1 00000000
def lower(num):
    return 2**((num-1)*8)

#
if __name__ == "__main__":
    logging.basicConfig()
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    Manger(2048, logger)
