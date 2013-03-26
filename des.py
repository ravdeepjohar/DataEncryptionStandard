import sys
import os.path

__Author__="Ravdeep Johar (rsj7209@g.rit.edu) & Karina Molochinsky"

#Specify the souce of the file
__file__="C:\Users\RSJ\Desktop\DES\des.py"

# Add lib/ to the system path
lib_directory = os.path.realpath(os.path.join(__file__, "../lib/"))
sys.path.append(lib_directory)

import destools
from variables import INITIAL_PERMUTATION, FINAL_PERMUTATION, EXPANSION, PERMUTATION, PERMUTED_CHOICE_1_LEFT, PERMUTED_CHOICE_1_RIGHT, PERMUTED_CHOICE_2, SBOXES, KEY_SHIFT_AMOUNTS

print_logs = True


def feistel_round(half_block, subkey):
    assert len(half_block) == 32
    assert len(subkey) == 48

    expansion_output = destools.permute(half_block, EXPANSION)
    xor_output = destools.xor(expansion_output, subkey)
    sbox_output = substituion_round(xor_output)
    permute_output = destools.permute(sbox_output, PERMUTATION)

    log("       Feistel(Right Block, Subkey):");
    log("       Expand(Right Block)=", convert_bits_to_string(expansion_output))
    log("       Expanded(...) XOR Subkey=", convert_bits_to_string(xor_output, 6))
    log("       S-Box(...)=", convert_bits_to_string(sbox_output))
    log("       Permutation(...) (output) =", convert_bits_to_string(permute_output))

    return permute_output

def substituion_round(half_block):
    assert len(half_block) == 48
    result = []

    # group_num represents which 6-bit group (out of 8) we are processing.
    for group_num in xrange(0,8):
        index = group_num * 6  # Index into half_block of start of group
        lookup_table = SBOXES[group_num]
        outer_bits = destools.bits_to_int(half_block[index+0], half_block[index+5])
        inner_bits = destools.bits_to_int(
            half_block[index+1],
            half_block[index+2],
            half_block[index+3],
            half_block[index+4],
        )
        result += destools.int_to_4_bits(lookup_table[outer_bits][inner_bits])

    return result

def decrypt(block, key):
    return encrypt(block, key, decrypt=True)

def encrypt(block, key, decrypt=False):
    nrounds = 16
    assert len(block) == 64
    assert len(key) == 64

    if decrypt:
        log("Decrypting text to plaintext:", convert_bits_to_string(block))
    else:
        log("Encrypting plaintext to ciphertext:", convert_bits_to_string(block))

    # Generate substitution keys
    subkeys = []
    key_left = destools.permute(key, PERMUTED_CHOICE_1_LEFT)
    key_right = destools.permute(key, PERMUTED_CHOICE_1_RIGHT)
    assert len(key_left) == 28
    assert len(key_right) == 28
    log("Generating Subkeys:")
    log("    Initial Key =", convert_bits_to_string(key))
    log("    Permuting into Left and Right keys")
    log("    Left Half  =", convert_bits_to_string(key_left))
    log("    Right Half =", convert_bits_to_string(key_right))
    for i in xrange(nrounds):
        shift_amount = KEY_SHIFT_AMOUNTS[i]
        destools.left_shift(key_left, shift_amount)
        destools.left_shift(key_right, shift_amount)
        subkey = destools.permute(key_left + key_right, PERMUTED_CHOICE_2)
        subkeys.append(subkey)

        log("")
        log("Subkey %s:" % i)
        log("    Shifting key halves to the left by %s bits" % shift_amount)
        log("    Left Half  =", convert_bits_to_string(key_left))
        log("    Right Half =", convert_bits_to_string(key_right))
        log("    Permuting Left and Right key into subkey")
        log("    Subkey =", convert_bits_to_string(subkey))

    # Apply subkeys in reverse order if decrypting
    log("")
    if decrypt:
        log("Reversing order of subkeys")
        subkeys = subkeys[::-1]

    # Initial Permutation
    block = destools.permute(block, INITIAL_PERMUTATION)
    log("Initial Permutation:", convert_bits_to_string(block))
    log("")

    # Rounds
    left_block = block[0:32]
    right_block = block[32:]
    for i in xrange(nrounds):

        log("Round %s:" % i)
        log("    Input:")
        log("        Subkey      =", convert_bits_to_string(subkeys[i]))
        log("        Left Block  =", convert_bits_to_string(left_block))
        log("        Right Block =", convert_bits_to_string(right_block))

        tmp = right_block
        fiestel_out = feistel_round(right_block, subkeys[i])
        right_block = destools.xor(left_block, fiestel_out)
        left_block = tmp

        log("    Output:")
        log("        Left Block = Left Block XOR Feistel(...)")
        log("                   =", convert_bits_to_string(right_block))
        log("        Right Block (Unchanged)")
        if i == 15:
            log("    DO NOT SWITCH right and left block after the last round")
        else:
            log("    Left and Right blocks are switched and input into next round.")
        log("")

    # Final Permutation
    # right and left are switched here because the final round does not switch
    # them.  Here we just switch them back.
    encrypted = destools.permute(right_block + left_block, FINAL_PERMUTATION)
    log("Result after all rounds = Left Block + Right Block")
    log("                        =", convert_bits_to_string(right_block+left_block))
    log("After Final Permutation =", convert_bits_to_string(encrypted))
    log("")

    return encrypted

def log(*text):
    if print_logs:
        for string in text:
            print string,
        print

def convert_bits_to_string(bits, blocksize=8):
    return "%s (0x%s)" % \
        (destools.bits_to_binary_string(bits, blocksize), destools.bits_to_hex(bits))
    '''
    return "0x%s %s-bit" % \
        (destools.bits_to_hex(bits), len(bits))
    '''
    '''
    return "%s (0x%s) %s-bit" % \
        (destools.bits_to_binary_string(bits, blocksize), destools.bits_to_hex(bits), len(bits))
    '''

if __name__ == "__main__":

    from optparse import OptionParser
    op = OptionParser(
        usage = "%prog [options] <plaintext|ciphertext> des key",
        description = "Encrypt (default) or decrypt using DES.  plaintext, ciphertext and key must be 64 bits in hex.")
    op.add_option("-d", "--decrypt", dest="decrypt", action="store_true",
        default=False, help="Interpret the first argument as ciphertext and decrypt it.")
    op.add_option("-c", "--encrypt", dest="decrypt", action="store_false",
        default=False, help="Interpret the first argument as plaintext and encrypt it. (default)")
    op.add_option("-a", "--ascii", dest="ascii", action="store_true",
        default=False, help="Convert input plaintext from ascii if encrypting, or convert resulting plaintext to ascii if decrypting.")
    (options, args) = op.parse_args()

    if len(args) < 2:
        op.error("Not enough arguments")
    elif len(args) > 2:
        op.error("Too many arguments")
    key = destools.hex_to_bits(args[1])

    # text is plaintext if encrypting or ciphertext if decrypting
    if options.ascii and not options.decrypt:
        text = destools.ascii_to_bits(args[0])
    else:
        text = destools.hex_to_bits(args[0])
    if len(text) != 64:
        if options.decrypt:
            op.error("ciphertext must be 16 hex digits")
        else:
            op.error("plaintext must be 16 hex digits (or 8 ascii letters if using -a/--ascii)")
    if len(key) != 64:
        print key, len(key)
        op.error("key must be 16 hex digits")

        #print logs
        print_logs = True

    if options.decrypt:
        result = decrypt(text, key)
    else:
        result = encrypt(text, key)

    if options.ascii and options.decrypt:
        print destools.bits_to_ascii(result)
    else:
        print destools.bits_to_hex(result)
