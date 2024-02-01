#!/usr/bin/env python

import reference
import json
from secp256k1 import *
from bitcoin_utils import deser_txid, hash160, COutPoint
import bip32
from copy import deepcopy
from importlib import reload
reload(reference)

G = ECKey().set(1).get_pubkey()
sending_test_vectors = []

HRP="sp"
#TODO: use clearly mock signatures, e.g. 010203040506...

def get_key_pair(index, seed=b'deadbeef', derivation='m/0h'):

    master = bip32.BIP32.from_seed(seed)
    d = ECKey().set(master.get_privkey_from_path(f'{derivation}/{index}'))
    P = d.get_pubkey()

    return d, P

def add_private_keys(inputs, input_priv_keys):
    for x, i in enumerate(inputs):
        i['private_key'] = input_priv_keys[x][0].get_bytes().hex()

    return inputs

def encode_hybrid_key(pub_key):
    x = pub_key.get_x()
    y = pub_key.get_y()
    return bytes([0x06 if y % 2 == 0 else 0x07]) + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')

def get_p2pkh_scriptsig(pub_key, priv_key, hybrid=False):
    msg = hashlib.sha256(b'message').digest()
    sig = priv_key.sign_ecdsa(msg, low_s=False, rfc6979=True).hex()
    s = len(sig) // 2
    if not hybrid:
        pubkey_bytes = bytes([0x21]) + pub_key.get_bytes(False)
    else:
        pubkey_bytes = bytes([0x41]) + encode_hybrid_key(pub_key)

    return f'{s:0x}' + sig + pubkey_bytes.hex()

def get_p2pkh_scriptPubKey(pub_key, hybrid=False):
    if not hybrid:
        pubkey_bytes = pub_key.get_bytes(False)
    else:
        pubkey_bytes = encode_hybrid_key(pub_key)
    return "76a914" + reference.hash160(pubkey_bytes).hex() + "88ac"

def get_p2tr_witness(priv_key):
    msg = hashlib.sha256(b'message').digest()
    sig = priv_key.sign_schnorr(msg).hex()
    return serialize_witness_stack([sig])

def get_leafp2tr_witness(priv_key, internal_key, add_annex=True):
    msg = hashlib.sha256(b'message').digest()
    sig = priv_key.sign_schnorr(msg).hex()
    leaf_script = (0x20 << 264) | (int.from_bytes(priv_key.get_pubkey().get_bytes(True), 'big') << 8) | 0xac
    control = (0xc1 << 512) | (internal_key << 256) | int.from_bytes(hashlib.sha256(b'leafhash').digest(), 'big')
    witness_stack = [sig, leaf_script.to_bytes(34, 'big').hex(), control.to_bytes(65, 'big').hex()]
    if (add_annex):
        witness_stack.append('50')
    return serialize_witness_stack(witness_stack)

def get_p2tr_scriptPubKey(pub_key):
    return "5120" + pub_key.get_bytes(True).hex()

def serialize_witness_stack(stack_items):
    stack_size = len(stack_items)
    result = f'{stack_size:02x}'
    for item in stack_items:
        size = len(item) // 2
        result += f'{size:02x}' + item
    return result

def new_test_case():
    recipient =  {
        "given": {
            "vin": [],
            "outputs": [],
            "key_material": {
                "spend_priv_key": "hex",
                "scan_priv_key": "hex",
            },
            "labels": [],
        },
        "expected": {
            "addresses": [],
            "outputs": [],
        }
    }
    sender = {
        "given": {
            "vin": [],
            "recipients": []
        },
        "expected": {
            "outputs": []
        }
    }
    test_case = {
        "comment": "",
        "sending": [],
        "receiving": [],
    }
    return sender, recipient, test_case

# In[10]:


def generate_labeled_output_tests():

    msg = hashlib.sha256(b'message').digest()
    aux = hashlib.sha256(b'random auxiliary data').digest()
    G = ECKey().set(1).get_pubkey()
    test_cases = []
    outpoints = [
            ("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16", 0),
            ("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d", 0),
    ]
    sender_bip32_seed = 'deadbeef'
    i1, I1 = get_key_pair(0, seed=bytes.fromhex(sender_bip32_seed))
    i2, I2 = get_key_pair(1, seed=bytes.fromhex(sender_bip32_seed))
    input_priv_keys = [(i1, False), (i2, False)]
    input_pub_keys = [I1, I2]

    recipient_bip32_seed = 'f00dbabe'
    b_scan, b_spend, B_scan, B_spend = reference.derive_silent_payment_key_pair(bytes.fromhex(recipient_bip32_seed))
    label_ints = [2, 3, 1001337]

    address = reference.encode_silent_payment_address(B_scan, B_spend, hrp=HRP)
    labeled_addresses = [
        reference.create_labeled_silent_payment_address(b_scan, B_spend, case, hrp=HRP) for case in label_ints
    ]
    recipient_addresses = [address] + labeled_addresses
    comments = ["Receiving with labels: label with even parity", "Receiving with labels: label with odd parity", "Receiving with labels: large label integer"]
    for i, case in enumerate(label_ints):
        sender, recipient, test_case = new_test_case()
        address = reference.create_labeled_silent_payment_address(b_scan, B_spend, case, hrp=HRP)
        addresses = [(address, 1.0)]

        inputs = []
        for i, outpoint in enumerate(outpoints):
            inputs += [{
                'txid': outpoint[0],
                'vout': outpoint[1],
                'scriptSig': get_p2pkh_scriptsig(input_pub_keys[i], input_priv_keys[i][0]),
                'txinwitness': '',
                'prevout': {'scriptPubKey': {'hex': get_p2pkh_scriptPubKey(input_pub_keys[i])}},
            }]
    
        sender['given']['vin'] = add_private_keys(deepcopy(inputs), input_priv_keys)
        sender['given']['recipients'] = addresses
        recipient['given']['vin'] = inputs
        recipient['given']['key_material']['scan_priv_key'] = b_scan.get_bytes().hex()
        recipient['given']['key_material']['spend_priv_key'] = b_spend.get_bytes().hex()
        recipient['expected']['addresses'] = recipient_addresses
        recipient['given']['labels'] = label_ints

        A_sum = sum(input_pub_keys)
        deterministic_nonce = reference.get_input_hash([COutPoint(deser_txid(o[0]), o[1]) for o in outpoints], A_sum)
        outputs = reference.create_outputs(input_priv_keys, deterministic_nonce, addresses, hrp=HRP)
        sender['expected']['outputs'] = outputs
        output_pub_keys = [r[0] for r in outputs]
        recipient['given']['outputs'] = output_pub_keys

        add_to_wallet = reference.scanning(
            b_scan,
            B_spend,
            A_sum,
            deterministic_nonce,
            [ECPubKey().set(bytes.fromhex(pub)) for pub in output_pub_keys],
            labels={(reference.generate_label(b_scan, l)*G).get_bytes(False).hex():reference.generate_label(b_scan, l).hex() for l in label_ints},
        )
        for o in add_to_wallet:

            pubkey = ECPubKey().set(bytes.fromhex(o['pub_key']))
            full_private_key = b_spend.add(
                bytes.fromhex(o['priv_key_tweak'])
            )
            if full_private_key.get_pubkey().get_y()%2 != 0:
                full_private_key.negate()

            sig = full_private_key.sign_schnorr(msg, aux)
            assert pubkey.verify_schnorr(sig, msg)
            o['signature'] = sig.hex()

        recipient['expected']['outputs'] = add_to_wallet
        test_case['sending'].extend([sender])
        test_case['receiving'].extend([recipient])
        test_case["comment"] = comments[i]
        test_cases.append(test_case)

    return test_cases


def generate_single_output_outpoint_tests():

    msg = hashlib.sha256(b'message').digest()
    aux = hashlib.sha256(b'random auxiliary data').digest()
    G = ECKey().set(1).get_pubkey()
    outpoint_test_cases = [
        [
            ("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16", 0),
            ("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d", 0)
        ],
        [
            ("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d", 0),
            ("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16", 0)
        ],
        [
            ("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16", 3),
            ("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16", 7)
        ],
        [
            ("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d", 7),
            ("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d", 3)
        ],
    ]

    sender_bip32_seed = 'deadbeef'
    recipient_bip32_seed = 'f00dbabe'
    i1, I1 = get_key_pair(0, seed=bytes.fromhex(sender_bip32_seed))
    i2, I2 = get_key_pair(1)
    input_priv_keys = [(i1, False), (i2, False)]
    input_pub_keys = [I1, I2]

    test_cases = []
    comments = [
        "Simple send: two inputs",
        "Simple send: two inputs, order reversed",
        "Simple send: two inputs from the same transaction",
        "Simple send: two inputs from the same transaction, order reversed"
    ]
    for i, outpoints in enumerate(outpoint_test_cases):
        sender, recipient, test_case = new_test_case()
        test_case["comment"] = comments[i]

        inputs = []
        for i, outpoint in enumerate(outpoints):
            inputs += [{
                'txid': outpoint[0],
                'vout': outpoint[1],
                'scriptSig': get_p2pkh_scriptsig(input_pub_keys[i], input_priv_keys[i][0]),
                'txinwitness': '',
                'prevout': {'scriptPubKey': {'hex': get_p2pkh_scriptPubKey(input_pub_keys[i])}},
            }]
        sender['given']['vin'] = add_private_keys(deepcopy(inputs), input_priv_keys)

        recipient['given']['vin'] = inputs

        b_scan, b_spend, B_scan, B_spend = reference.derive_silent_payment_key_pair(bytes.fromhex(recipient_bip32_seed))
        recipient['given']['key_material']['scan_priv_key'] = b_scan.get_bytes().hex()
        recipient['given']['key_material']['spend_priv_key'] = b_spend.get_bytes().hex()
        address = reference.encode_silent_payment_address(B_scan, B_spend, hrp=HRP)

        sender['given']['recipients'].extend([(address, 1.0)])
        recipient['expected']['addresses'].extend([address])

        A_sum = sum(input_pub_keys)
        deterministic_nonce = reference.get_input_hash([COutPoint(deser_txid(o[0]), o[1]) for o in outpoints], A_sum)
        outputs = reference.create_outputs(input_priv_keys, deterministic_nonce, [(address, 1.0)], hrp=HRP)
        sender['expected']['outputs'] = outputs
        output_pub_keys = [recipient[0] for recipient in outputs]
        recipient['given']['outputs'] = output_pub_keys

        add_to_wallet = reference.scanning(
            b_scan,
            B_spend,
            A_sum,
            deterministic_nonce,
            [ECPubKey().set(bytes.fromhex(pub)) for pub in output_pub_keys],
        )
        for o in add_to_wallet:

            pubkey = ECPubKey().set(bytes.fromhex(o['pub_key']))
            full_private_key = b_spend.add(
                bytes.fromhex(o['priv_key_tweak'])
            )
            if full_private_key.get_pubkey().get_y()%2 != 0:
                full_private_key.negate()

            sig = full_private_key.sign_schnorr(msg, aux)
            assert pubkey.verify_schnorr(sig, msg)
            o['signature'] = sig.hex()

        recipient['expected']['outputs'] = add_to_wallet
        test_case['sending'].extend([sender])
        test_case['receiving'].extend([recipient])
        test_cases.append(test_case)

    return test_cases


def generate_multiple_output_tests():

    msg = hashlib.sha256(b'message').digest()
    aux = hashlib.sha256(b'random auxiliary data').digest()
    G = ECKey().set(1).get_pubkey()
    recipient_test_cases = []
    outpoints = [
            ("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16", 0),
            ("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d", 0),
    ]
    sender_bip32_seed = 'deadbeef'
    i1, I1 = get_key_pair(0, seed=bytes.fromhex(sender_bip32_seed))
    i2, I2 = get_key_pair(1, seed=bytes.fromhex(sender_bip32_seed))
    input_priv_keys = [(i1, False), (i2, False)]
    input_pub_keys = [I1, I2]

    recipient_one_bip32_seed = 'f00dbabe'
    recipient_two_bip32_seed = 'decafbad'

    scan1, spend1, Scan1, Spend1 = reference.derive_silent_payment_key_pair(bytes.fromhex(recipient_one_bip32_seed))
    address1 = reference.encode_silent_payment_address(Scan1, Spend1, hrp=HRP)
    addresses1 = [(address1, amount) for amount in [2.0, 3.0]]

    scan2, spend2, Scan2, Spend2 = reference.derive_silent_payment_key_pair(bytes.fromhex(recipient_two_bip32_seed))
    address2 = reference.encode_silent_payment_address(Scan2, Spend2, hrp=HRP)
    addresses2 = [(address2, amount) for amount in [4.0, 5.0]]

    test_cases = []

    sender, recipient1, test_case = new_test_case()
    sender1 = deepcopy(sender)
    recipient2 = deepcopy(recipient1)
    test_case2 = deepcopy(test_case)

    inputs = []
    for i, outpoint in enumerate(outpoints):
        inputs += [{
            'txid': outpoint[0],
            'vout': outpoint[1],
            'scriptSig': get_p2pkh_scriptsig(input_pub_keys[i], input_priv_keys[i][0]),
            'txinwitness': '',
            'prevout': {'scriptPubKey': {'hex': get_p2pkh_scriptPubKey(input_pub_keys[i])}},
        }]

    sender1['given']['vin'] = sender['given']['vin'] = add_private_keys(deepcopy(inputs), input_priv_keys)
    sender['given']['recipients'] = addresses1
    recipient1['given']['vin'] = inputs
    recipient2['given']['vin'] = inputs
    recipient1['given']['key_material']['scan_priv_key'] = scan1.get_bytes().hex()
    recipient1['given']['key_material']['spend_priv_key'] = spend1.get_bytes().hex()
    recipient1['expected']['addresses'] = [address1]
    recipient2['given']['key_material']['scan_priv_key'] = scan2.get_bytes().hex()
    recipient2['given']['key_material']['spend_priv_key'] = spend2.get_bytes().hex()
    recipient2['expected']['addresses'] = [address2]

    A_sum = sum(input_pub_keys)
    deterministic_nonce = reference.get_input_hash([COutPoint(deser_txid(o[0]), o[1]) for o in outpoints], A_sum)
    outputs = reference.create_outputs(input_priv_keys, deterministic_nonce, addresses1, hrp=HRP)
    sender['expected']['outputs'] = outputs
    output_pub_keys = [recipient[0] for recipient in outputs]
    recipient1['given']['outputs'] = output_pub_keys

    add_to_wallet = reference.scanning(
        scan1,
        Spend1,
        A_sum,
        deterministic_nonce,
        [ECPubKey().set(bytes.fromhex(pub)) for pub in output_pub_keys],
    )
    for o in add_to_wallet:

        pubkey = ECPubKey().set(bytes.fromhex(o['pub_key']))
        full_private_key = spend1.add(
            bytes.fromhex(o['priv_key_tweak'])
        )
        if full_private_key.get_pubkey().get_y()%2 != 0:
            full_private_key.negate()

        sig = full_private_key.sign_schnorr(msg, aux)
        assert pubkey.verify_schnorr(sig, msg)
        o['signature'] = sig.hex()

    recipient1['expected']['outputs'] = add_to_wallet
    test_case['sending'].extend([sender])
    test_case['receiving'].extend([recipient1])
    test_case["comment"] = "Multiple outputs: multiple outputs, same recipient"
    test_cases.append(test_case)

    sender1['given']['recipients'] = addresses1 + addresses2
    outputs = reference.create_outputs(input_priv_keys, deterministic_nonce, addresses1 + addresses2, hrp=HRP)
    sender1['expected']['outputs'] = outputs
    output_pub_keys = [recipient[0] for recipient in outputs]
    recipient1['given']['outputs'] = output_pub_keys
    recipient2['given']['outputs'] = output_pub_keys

    add_to_wallet = reference.scanning(
        scan2,
        Spend2,
        A_sum,
        deterministic_nonce,
        [ECPubKey().set(bytes.fromhex(pub)) for pub in output_pub_keys],
    )
    for o in add_to_wallet:

        pubkey = ECPubKey().set(bytes.fromhex(o['pub_key']))
        full_private_key = spend2.add(
            bytes.fromhex(o['priv_key_tweak'])
        )
        if full_private_key.get_pubkey().get_y()%2 != 0:
            full_private_key.negate()

        sig = full_private_key.sign_schnorr(msg, aux)
        assert pubkey.verify_schnorr(sig, msg)
        o['signature'] = sig.hex()

    recipient2['expected']['outputs'] = add_to_wallet
    test_case2['sending'].extend([sender1])
    test_case2['receiving'].extend([recipient1, recipient2])
    test_case2["comment"] = "Multiple outputs: multiple outputs, multiple recipients"
    test_cases.append(test_case2)

    return test_cases


# In[13]:


def generate_paying_to_self_test():

    msg = hashlib.sha256(b'message').digest()
    aux = hashlib.sha256(b'random auxiliary data').digest()
    outpoints = [
        ("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16", 0),
        ("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d", 0)
    ]

    sender_bip32_seed = 'deadbeef'
    recipient_bip32_seed = 'deadbeef'
    i1, I1 = get_key_pair(0, seed=bytes.fromhex(sender_bip32_seed))
    i2, I2 = get_key_pair(1)
    input_priv_keys = [(i1, False), (i2, False)]
    input_pub_keys = [I1, I2]

    sender, recipient, test_case = new_test_case()
    sender['given']['outpoints'] = outpoints
    recipient['given']['outpoints'] = outpoints
    sender['given']['input_priv_keys'].extend([i1.get_bytes().hex(), i2.get_bytes().hex()])
    recipient['given']['input_pub_keys'].extend([I1.get_bytes(False).hex(), I2.get_bytes(False).hex()])

    b_scan, b_spend, B_scan, B_spend = create_silent_payment_key_pair(bytes.fromhex(recipient_bip32_seed))
    recipient['given']['bip32_seed'] = recipient_bip32_seed
    recipient['given']['scan_priv_key'] = b_scan.get_bytes().hex()
    recipient['given']['spend_priv_key'] = b_spend.get_bytes().hex()
    address = reference.encode_silent_payment_address(B_scan, B_spend, hrp=HRP)

    sender['given']['recipients'].extend([(address, 1.0)])
    recipient['expected']['addresses'].extend([address])

    A_sum = sum(input_pub_keys)
    deterministic_nonce = reference.get_input_hash([COutPoint(deser_txid(o[0]), o[1]) for o in outpoints], A_sum)
    outputs = reference.create_outputs(input_priv_keys, deterministic_nonce, [(address, 1.0)], hrp=HRP)
    sender['expected']['outputs'] = outputs
    output_pub_keys = [recipient[0] for recipient in outputs]
    recipient['given']['outputs'] = output_pub_keys

    add_to_wallet = reference.scanning(
        b_scan,
        B_spend,
        A_sum,
        deterministic_nonce,
        [ECPubKey().set(bytes.fromhex(pub)) for pub in output_pub_keys],
    )
    for o in add_to_wallet:

        pubkey = ECPubKey().set(bytes.fromhex(o['pub_key']))
        full_private_key = b_spend.add(
            bytes.fromhex(o['priv_key_tweak'])
        )
        if full_private_key.get_pubkey().get_y()%2 != 0:
            full_private_key.negate()

        sig = full_private_key.sign_schnorr(msg, aux)
        assert pubkey.verify_schnorr(sig, msg)
        o['signature'] = sig.hex()

    recipient['expected']['outputs'] = add_to_wallet
    test_case['sending'].extend([sender])
    test_case['receiving'].extend([recipient])

    return test_case


def generate_multiple_outputs_with_labels_tests():

    msg = hashlib.sha256(b'message').digest()
    aux = hashlib.sha256(b'random auxiliary data').digest()
    G = ECKey().set(1).get_pubkey()
    recipient_test_cases = []
    outpoints = [
            ("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16", 0),
            ("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d", 0),
    ]
    sender_bip32_seed = 'deadbeef'
    i1, I1 = get_key_pair(0, seed=bytes.fromhex(sender_bip32_seed))
    i2, I2 = get_key_pair(1, seed=bytes.fromhex(sender_bip32_seed))
    input_priv_keys = [(i1, False), (i2, False)]
    input_pub_keys = [I1, I2]

    recipient_bip32_seed = 'f00dbabe'
    scan1, spend1, Scan1, Spend1 = reference.derive_silent_payment_key_pair(bytes.fromhex(recipient_bip32_seed))
    address = reference.encode_silent_payment_address(Scan1, Spend1, hrp=HRP)
    l1 = 1
    l2 = 1337
    labels_one = [l1]
    labels_three = [l1, l2]
    label_address_one = reference.create_labeled_silent_payment_address(scan1, Spend1, m=l1, hrp=HRP)
    label_address_two = reference.create_labeled_silent_payment_address(scan1, Spend1, m=l2, hrp=HRP)
    addresses1 = [(address, 1.0), (label_address_one, 2.0)]
    addresses2 = [(label_address_one, 3.0), (label_address_one, 4.0)]
    addresses3 = [(address, 5.0), (label_address_one, 6.0), (label_address_two, 7.0), (label_address_two, 8.0)]

    test_cases = []
    labels = [labels_one, labels_one, labels_three]
    sp_addresses = [[address, label_address_one], [address, label_address_one], [address, label_address_one, label_address_two]]
    comments = [
        "Multiple outputs with labels: un-labeled and labeled address; same recipient",
        "Multiple outputs with labels: multiple outputs for labeled address; same recipient",
        "Multiple outputs with labels: un-labeled, labeled, and multiple outputs for labeled address; multiple recipients",
    ]
    for i, addrs in enumerate([addresses1, addresses2, addresses3]):
        sender, recipient, test_case = new_test_case()

        inputs = []
        for i, outpoint in enumerate(outpoints):
            inputs += [{
                'txid': outpoint[0],
                'vout': outpoint[1],
                'scriptSig': get_p2pkh_scriptsig(input_pub_keys[i], input_priv_keys[i][0]),
                'txinwitness': '',
                'prevout': {'scriptPubKey': {'hex': get_p2pkh_scriptPubKey(input_pub_keys[i])}},
            }]

        sender['given']['vin'] = add_private_keys(deepcopy(inputs), input_priv_keys)
        recipient['given']['vin'] = inputs

        recipient['given']['key_material']['scan_priv_key'] = scan1.get_bytes().hex()
        recipient['given']['key_material']['spend_priv_key'] = spend1.get_bytes().hex()
        sender['given']['recipients'] = addrs
        recipient['expected']['addresses'] = sp_addresses[i]
        recipient['given']['labels'] = labels[i]
        A_sum = sum(input_pub_keys)
        deterministic_nonce = reference.get_input_hash([COutPoint(deser_txid(o[0]), o[1]) for o in outpoints], A_sum)
        outputs = reference.create_outputs(input_priv_keys, deterministic_nonce, addrs, hrp=HRP)
        sender['expected']['outputs'] = outputs
        output_pub_keys = [recipient[0] for recipient in outputs]
        recipient['given']['outputs'] = output_pub_keys

        add_to_wallet = reference.scanning(
            scan1,
            Spend1,
            A_sum,
            deterministic_nonce,
            [ECPubKey().set(bytes.fromhex(pub)) for pub in output_pub_keys],
            labels={(reference.generate_label(scan1, l)*G).get_bytes(False).hex():reference.generate_label(scan1, l).hex() for l in labels[i]},
        )
        for o in add_to_wallet:

            pubkey = ECPubKey().set(bytes.fromhex(o['pub_key']))
            full_private_key = spend1.add(
                bytes.fromhex(o['priv_key_tweak'])
            )
            if full_private_key.get_pubkey().get_y()%2 != 0:
                full_private_key.negate()

            sig = full_private_key.sign_schnorr(msg, aux)
            assert pubkey.verify_schnorr(sig, msg)
            o['signature'] = sig.hex()

        recipient['expected']['outputs'] = add_to_wallet
        test_case['sending'].extend([sender])
        test_case['receiving'].extend([recipient])
        test_case["comment"] = comments[i]
        test_cases.append(test_case)

    return test_cases


def generate_single_output_input_tests():

    msg = hashlib.sha256(b'message').digest()
    aux = hashlib.sha256(b'random auxiliary data').digest()
    G = ECKey().set(1).get_pubkey()
    outpoints = [
        ("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16", 0),
        ("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d", 0)
    ]

    sender_bip32_seed = 'deadbeef'
    recipient_bip32_seed = 'f00dbabe'
    i1, I1 = get_key_pair(0, seed=bytes.fromhex(sender_bip32_seed))
    i2, I2 = get_key_pair(1, seed=bytes.fromhex(sender_bip32_seed))
    i3, I3 = get_key_pair(2, seed=bytes.fromhex(sender_bip32_seed))
    i4, I4 = get_key_pair(3, seed=bytes.fromhex(sender_bip32_seed))

    if I1.get_y()%2 != 0:
        i1.negate()
        I1.negate()

    if I2.get_y()%2 != 0:
        i2.negate()
        I2.negate()

    if I3.get_y()%2 == 0:
        i3.negate()
        I3.negate()

    if I4.get_y()%2 == 0:
        i4.negate()
        I4.negate()


    address_reuse = [
        [(i1, False), (i1, False)],
        [I1, I1]
    ]
    taproot_only = [
        [(i1, True), (i2, True)],
        [I1, I2]
    ]

    taproot_only_with_odd_y = [
        [(i1, True), (i4, True)],
        [I1, I4]
    ]
    mixed = [
        [(i1, True), (i3, False)],
        [I1, I3]
    ]
    mixed_with_odd_y = [
        [(i4, True), (i3, False)],
        [I4, I3]
    ]
    test_cases = []
    comments = [
        "Single recipient: multiple UTXOs from the same public key",
        "Single recipient: taproot only inputs with even y-values",
        "Single recipient: taproot only with mixed even/odd y-values",
        "Single recipient: taproot input with even y-value and non-taproot input",
        "Single recipient: taproot input with odd y-value and non-taproot input"
    ]
    for i, inputs in enumerate([address_reuse, taproot_only, taproot_only_with_odd_y, mixed, mixed_with_odd_y]):
        sender, recipient, test_case = new_test_case()

        inp = []
        for x, (key, is_taproot) in enumerate(inputs[0]):
            pub_key = inputs[1][x]
            if is_taproot:
                inp += [{
                    "txid": outpoints[x][0],
                    "vout": outpoints[x][1],
                    "scriptSig": "",
                    "txinwitness": get_p2tr_witness(key),
                    "prevout": {"scriptPubKey": {"hex": get_p2tr_scriptPubKey(pub_key)}},
                }]
            else:
                inp += [{
                    "txid": outpoints[x][0],
                    "vout": outpoints[x][1],
                    "scriptSig": get_p2pkh_scriptsig(pub_key, key),
                    "txinwitness": "",
                    "prevout": {"scriptPubKey": {"hex": get_p2pkh_scriptPubKey(pub_key)}},
                }]

        priv_keys = []
        for (priv_key, is_taproot) in inputs[0]:
            priv_keys += [priv_key.get_bytes().hex()]
            

        sender['given']['vin'] = add_private_keys(deepcopy(inp), inputs[0])
        recipient['given']['vin'] = inp

        b_scan, b_spend, B_scan, B_spend = reference.derive_silent_payment_key_pair(bytes.fromhex(recipient_bip32_seed))
        recipient['given']['key_material']['scan_priv_key'] = b_scan.get_bytes().hex()
        recipient['given']['key_material']['spend_priv_key'] = b_spend.get_bytes().hex()
        address = reference.encode_silent_payment_address(B_scan, B_spend, hrp=HRP)

        sender['given']['recipients'].extend([(address, 1.0)])
        recipient['expected']['addresses'].extend([address])
        
        A_sum = sum([p if not inputs[0][i][1] or p.get_y()%2==0 else p * -1  for i, p in enumerate(inputs[1])])
        deterministic_nonce = reference.get_input_hash([COutPoint(deser_txid(o[0]), o[1]) for o in outpoints], A_sum)

        outputs = reference.create_outputs(inputs[0], deterministic_nonce, [(address, 1.0)], hrp=HRP)
        sender['expected']['outputs'] = outputs
        output_pub_keys = [recipient[0] for recipient in outputs]
        recipient['given']['outputs'] = output_pub_keys

        add_to_wallet = reference.scanning(
            b_scan,
            B_spend,
            A_sum,
            deterministic_nonce,
            [ECPubKey().set(bytes.fromhex(pub)) for pub in output_pub_keys],
        )
        for o in add_to_wallet:

            pubkey = ECPubKey().set(bytes.fromhex(o['pub_key']))
            full_private_key = b_spend.add(
                bytes.fromhex(o['priv_key_tweak'])
            )
            if full_private_key.get_pubkey().get_y()%2 != 0:
                full_private_key.negate()

            sig = full_private_key.sign_schnorr(msg, aux)
            assert pubkey.verify_schnorr(sig, msg)
            o['signature'] = sig.hex()

        recipient['expected']['outputs'] = add_to_wallet
        test_case['sending'].extend([sender])
        test_case['receiving'].extend([recipient])
        test_case["comment"] = comments[i]
        test_cases.append(test_case)

    return test_cases


def generate_change_tests():

    sender, recipient, test_case = new_test_case()

    msg = hashlib.sha256(b'message').digest()
    aux = hashlib.sha256(b'random auxiliary data').digest()
    G = ECKey().set(1).get_pubkey()
    recipient_test_cases = []
    outpoints = [
            ("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16", 0),
            ("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d", 0),
    ]
    sender_bip32_seed = 'deadbeef'
    i1, I1 = get_key_pair(0, seed=bytes.fromhex(sender_bip32_seed))
    i2, I2 = get_key_pair(1, seed=bytes.fromhex(sender_bip32_seed))
    input_priv_keys = [(i1, False), (i2, False)]
    input_pub_keys = [I1, I2]

    scan0, spend0, Scan0, Spend0 = reference.derive_silent_payment_key_pair(bytes.fromhex(sender_bip32_seed))
    sender_address = reference.encode_silent_payment_address(Scan0, Spend0, hrp=HRP)
    change_label = 0
    change_labels = [change_label]
    change_address = reference.create_labeled_silent_payment_address(scan0, Spend0, m=change_label, hrp=HRP)

    recipient_bip32_seed = 'f00dbabe'
    seeds = [sender_bip32_seed, recipient_bip32_seed]
    scan1, spend1, Scan1, Spend1 = reference.derive_silent_payment_key_pair(bytes.fromhex(recipient_bip32_seed))
    address = reference.encode_silent_payment_address(Scan1, Spend1, hrp=HRP)
    addresses = [(address, 1.0), (change_address, 2.0)]

    test_cases = []
    sp_recipients = [[address, change_address]]

    rec1, rec2 = deepcopy(recipient), deepcopy(recipient)
    rec1['given']['key_material']['scan_priv_key'] = scan0.get_bytes().hex()
    rec1['given']['key_material']['spend_priv_key'] = spend0.get_bytes().hex()
    rec2['given']['key_material']['scan_priv_key'] = scan1.get_bytes().hex()
    rec2['given']['key_material']['spend_priv_key'] = spend1.get_bytes().hex()
    rec1['expected']['addresses'] = [sender_address, change_address]
    rec1['given']['labels'] = change_labels
    rec2['expected']['addresses'] = [address]


    inputs = []
    for i, outpoint in enumerate(outpoints):
        inputs += [{
            'txid': outpoint[0],
            'vout': outpoint[1],
            'scriptSig': get_p2pkh_scriptsig(input_pub_keys[i], input_priv_keys[i][0]),
            'txinwitness': '',
            'prevout': {'scriptPubKey': {'hex': get_p2pkh_scriptPubKey(input_pub_keys[i])}},
        }]

    sender['given']['vin'] = add_private_keys(deepcopy(inputs), input_priv_keys)
    sender['given']['recipients'] = addresses
    A_sum = sum(input_pub_keys)
    deterministic_nonce = reference.get_input_hash([COutPoint(deser_txid(o[0]), o[1]) for o in outpoints], A_sum)
    outputs = reference.create_outputs(input_priv_keys, deterministic_nonce, addresses, hrp=HRP)
    sender['expected']['outputs'] = outputs

    output_pub_keys = [recipient[0] for recipient in outputs]

    test_case['sending'].extend([sender])
    labels = [change_labels, []]
    for i, rec in enumerate([rec1, rec2]):
        rec['given']['vin'] = inputs
        rec['given']['outputs'] = output_pub_keys

        scan, spend, Scan, Spend = reference.derive_silent_payment_key_pair(bytes.fromhex(seeds[i]))
        add_to_wallet = reference.scanning(
            scan,
            Spend,
            A_sum,
            deterministic_nonce,
            [ECPubKey().set(bytes.fromhex(pub)) for pub in output_pub_keys],
            labels={(reference.generate_label(scan, l)*G).get_bytes(False).hex():reference.generate_label(scan, l).hex() for l in labels[i]},
        )
        for o in add_to_wallet:

            pubkey = ECPubKey().set(bytes.fromhex(o['pub_key']))
            full_private_key = spend.add(
                bytes.fromhex(o['priv_key_tweak'])
            )
            if full_private_key.get_pubkey().get_y()%2 != 0:
                full_private_key.negate()

            sig = full_private_key.sign_schnorr(msg, aux)
            assert pubkey.verify_schnorr(sig, msg)
            o['signature'] = sig.hex()

        rec['expected']['outputs'] = add_to_wallet
        test_case['receiving'].extend([rec])
    test_case["comment"] = "Single recipient: use silent payments for sender change"
    test_cases.append(test_case)
    return test_cases


# In[17]:

def generate_all_inputs_test():

    sender, recipient, test_case = new_test_case()

    msg = hashlib.sha256(b'message').digest()
    aux = hashlib.sha256(b'random auxiliary data').digest()
    recipient_test_cases = []
    outpoints = [
            ("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16", 0),
            ("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d", 0),
            ("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d", 1),
            ("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d", 2),
            ("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d", 3),
            ("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d", 4),
            ("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d", 5),
            ("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d", 6),
            ("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d", 7),
            ("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d", 8),
            ("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d", 9),
            ("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d", 10),
            ("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d", 11),
            ("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d", 12),
            ("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d", 13),
    ]
    sender_bip32_seed = 'deadbeef'
    input_priv_keys = []
    input_pub_keys = []

    recipient_bip32_seed = 'f00dbabe'
    scan, spend, Scan, Spend = reference.derive_silent_payment_key_pair(bytes.fromhex(recipient_bip32_seed))
    address = reference.encode_silent_payment_address(Scan, Spend, hrp=HRP)
    addresses = [(address, 1.0)]

    recipient['given']['key_material']['scan_priv_key'] = scan.get_bytes().hex()
    recipient['given']['key_material']['spend_priv_key'] = spend.get_bytes().hex()
    recipient['expected']['addresses'] = [address]

    inputs = []

    ## included
    # p2pk
    i = len(inputs)
    priv, pub = get_key_pair(i, seed=bytes.fromhex(sender_bip32_seed))
    sig = priv.sign_ecdsa(msg, low_s=False, rfc6979=True).hex()
    x = len(sig) // 2
    inputs += [{
        'txid': outpoints[i][0],
        'vout': outpoints[i][1],
        'scriptSig': f'{x:0x}' + sig,
        'txinwitness': '',
        'prevout': {'scriptPubKey': {'hex': "21" + input_pub_keys[i].get_bytes(False).hex() + "ac"}},
    }]
    input_priv_keys += [(priv, False)]
    input_pub_keys += [pub]

    # p2pkh
    i = len(inputs)
    priv, pub = get_key_pair(i, seed=bytes.fromhex(sender_bip32_seed))
    inputs += [{
        'txid': outpoints[i][0],
        'vout': outpoints[i][1],
        'scriptSig': get_p2pkh_scriptsig(input_pub_keys[i], input_priv_keys[i][0]),
        'txinwitness': '',
        'prevout': {'scriptPubKey': {'hex': get_p2pkh_scriptPubKey(input_pub_keys[i])}},
    }]
    input_priv_keys += [(priv, False)]
    input_pub_keys += [pub]

    # p2pkh hybrid key
    # TODO: uncompressed key
    

    # p2wpkh
    i = len(inputs)
    priv, pub = get_key_pair(i, seed=bytes.fromhex(sender_bip32_seed))
    sig = priv.sign_ecdsa(msg, low_s=False, rfc6979=True).hex()
    inputs += [{
        'prevout': list(outpoints[i]) + ["", serialize_witness_stack([sig, input_pub_keys[i].get_bytes(False).hex()])],
        'scriptPubKey': "0014" + reference.hash160(input_pub_keys[i].get_bytes(False)).hex(),
    }]
    input_priv_keys += [(priv, False)]
    input_pub_keys += [pub]

    # p2wpkh hybrid key
    # TODO: verify is this is even possible
    i = len(inputs)
    priv, pub = get_key_pair(i, seed=bytes.fromhex(sender_bip32_seed))
    sig = priv.sign_ecdsa(msg, low_s=False, rfc6979=True).hex()
    inputs += [{
        'txid': outpoints[i][0],
        'vout': outpoints[i][1],
        'scriptSig': '', 
        'txinwitness': serialize_witness_stack([sig, input_pub_keys[i].get_bytes(False).hex()]),
        'prevout': {'scriptPubKey': {'hex': "0014" + reference.hash160(encode_hybrid_key(input_pub_keys[i])).hex()}},
    }]
    input_priv_keys += [(priv, False)]
    input_pub_keys += [pub]

    # p2sh-p2wpkh
    i = len(inputs)
    sig = input_priv_keys[i][0].sign_ecdsa(msg, low_s=False, rfc6979=True).hex()
    x = len(sig) // 2
    witnessProgramm = bytes([0x00, 0x14]) + reference.hash160(input_pub_keys[i].get_bytes(False))
    inputs += [{
        'txid': outpoints[i][0],
        'vout': outpoints[i][1],
        'scriptSig': "16" + witnessProgramm.hex(), 
        'txinwitness': serialize_witness_stack([sig, input_pub_keys[i].get_bytes(False).hex()]),
        'prevout': {'scriptPubKey': {'hex': "a914" + reference.hash160(witnessProgramm).hex() + "87"}},
    }]
    input_priv_keys += [(priv, False)]
    input_pub_keys += [pub]

    # p2tr key path
    i = len(inputs)
    priv, pub = get_key_pair(i, seed=bytes.fromhex(sender_bip32_seed))
    inputs += [{
        'txid': outpoints[i][0],
        'vout': outpoints[i][1],
        'scriptSig': "",
        'txinwitness': get_p2tr_witness(input_priv_keys[i][0]),
        'prevout': {'scriptPubKey': {'hex': get_p2tr_scriptPubKey(input_pub_keys[i])}},
    }]
    input_priv_keys += [(priv, True)]
    input_pub_keys += [pub]

    # p2tr script path
    i = len(inputs)
    priv_key, pub_key = get_key_pair(i, seed=bytes.fromhex(sender_bip32_seed))
    # can verify calculation below with following command
    # tap ae0554b17264a231ec94407263897a6294a92f8f1f587e56c1d4e9a1bad0d571 1 '[OP_TRUE]' 0
    leaf_version = "c0"
    script = "51" # OP_TRUE
    if pub_key.get_y() % 2 != 0:
        priv_key.negate()
    leaf_hash = TaggedHash("TapLeaf", bytes.fromhex(leaf_version + "01" + script))
    tap_tweak = TaggedHash("TapTweak", pub_key.get_bytes() + leaf_hash)
    tweaked_key = pub_key.tweak_add(tap_tweak)
    control_block = leaf_version + pub_key.get_bytes().hex()
    inputs += [{
        'txid': outpoints[i][0],
        'vout': outpoints[i][1],
        'scriptSig': "",
        'txinwitness': serialize_witness_stack([script, control_block]),
        'prevout': {'scriptPubKey': {'hex': get_p2tr_scriptPubKey(tweaked_key)}},
    }]
    input_pub_keys += [tweaked_key]
    input_priv_keys += [(priv_key.tweak_add(tap_tweak), True)]
    eligible = i

    ## excluded output types
    # TODO: p2tr spend path with P == H
    # TODO: p2sh
    # TODO: p2wsh
    # TODO: p2ms
    # TODO: add non-standard spend

    # scanning negative cases
    # TODO: unkown witness should be ignored during scanning
    # TODO: scanning no taproot output
    # TODO: scanning no inputs for ECDH

    sender['given']['recipients'] = addresses
    A_sum = sum([p if not input_priv_keys[i][1] or p.get_y()%2==0 else p * -1  for i, p in enumerate(input_pub_keys)])
    deterministic_nonce = reference.get_input_hash([COutPoint(deser_txid(o[0]), o[1]) for o in outpoints], A_sum)
    outputs = reference.create_outputs(input_priv_keys, deterministic_nonce, addresses, hrp=HRP)
    sender['expected']['outputs'] = outputs
    sender['given']['inputs'] = add_private_keys(deepcopy(inputs), input_priv_keys)

    output_pub_keys = [recipient[0] for recipient in outputs]

    test_case['sending'].extend([sender])
    recipient['given']['vin'] = inputs
    recipient['given']['outputs'] = output_pub_keys


    add_to_wallet = reference.scanning(
        scan,
        Spend,
        A_sum,
        deterministic_nonce,
        [ECPubKey().set(bytes.fromhex(pub)) for pub in output_pub_keys],
        labels={},
    )
    for o in add_to_wallet:

        pubkey = ECPubKey().set(bytes.fromhex(o['pub_key']))
        full_private_key = spend.add(
            bytes.fromhex(o['priv_key_tweak'])
        )
        if full_private_key.get_pubkey().get_y()%2 != 0:
            full_private_key.negate()

        sig = full_private_key.sign_schnorr(msg, aux)
        assert pubkey.verify_schnorr(sig, msg)
        o['signature'] = sig.hex()

    recipient['expected']['outputs'] = add_to_wallet
    test_case['receiving'].extend([recipient])
    test_case["comment"] = "Pubkey extraction"
    test_cases = []
    test_cases.append(test_case)
    return test_cases

def generate_unknown_segwit_ver_test():
    sender, recipient, test_case = new_test_case()

    msg = hashlib.sha256(b'message').digest()
    aux = hashlib.sha256(b'random auxiliary data').digest()
    outpoints = [
            ("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16", 0),
            ("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d", 0),
    ]
    sender_bip32_seed = 'deadbeef'
    recipient_bip32_seed = 'f00dbabe'
    scan, spend, Scan, Spend = reference.derive_silent_payment_key_pair(bytes.fromhex(recipient_bip32_seed))
    address = reference.encode_silent_payment_address(Scan, Spend, hrp=HRP)
    addresses = [(address, 1.0)]

    recipient['given']['key_material']['scan_priv_key'] = scan.get_bytes().hex()
    recipient['given']['key_material']['spend_priv_key'] = spend.get_bytes().hex()

    inputs = []
    input_priv_keys = []
    input_pub_keys = []

    ## included
    # p2pkh
    i = len(inputs)
    priv, pub = get_key_pair(i, seed=bytes.fromhex(sender_bip32_seed))
    inputs += [{
        'prevout': list(outpoints[i]) + [get_p2pkh_scriptsig(pub, priv), ""],
        'scriptPubKey': get_p2pkh_scriptPubKey(pub),
    }]
    input_priv_keys += [(priv, False)]
    input_pub_keys += [pub]

    # unknown segwit version 
    i = len(inputs)
    priv, pub = get_key_pair(i, seed=bytes.fromhex(sender_bip32_seed))
    sig = priv.sign_ecdsa(msg, low_s=False, rfc6979=True).hex()
    inputs += [{
        'prevout': list(outpoints[i]) + ["", serialize_witness_stack([sig, pub.get_bytes(False).hex()])],
        'scriptPubKey': "5214" + hash160(pub.get_bytes(False)),
    }]
    input_priv_keys += [(priv, False)]
    input_pub_keys += [pub]

    sender['given']['recipients'] = addresses
    sender['given']['inputs'] = add_private_keys(deepcopy(inputs), input_priv_keys)
    # TODO: encode failure of sending explicitly 
    test_case['sending'].extend([sender])

    recipient['given']['inputs'] = inputs
    # create plausible outputs
    # a) using all detected keys
    outputs_a = reference.create_outputs(input_priv_keys, reference.hash_outpoints(outpoints), addresses, hrp=HRP)
    # b) using only p2pkh input
    outputs_b = reference.create_outputs(input_priv_keys[:1], reference.hash_outpoints(outpoints), addresses, hrp=HRP)
    recipient['given']['outputs'] = [outputs_a[0][0], outputs_b[0][0]]
    test_case['receiving'].extend([recipient])

    test_case["comment"] = "Skipped tx: unknown segwit version input"
    return [test_case]

    # scanning negative cases
    # TODO: scanning no taproot output
    # TODO: scanning no inputs for ECDH

def generate_taproot_with_nums_point_test():

    msg = hashlib.sha256(b'message').digest()
    aux = hashlib.sha256(b'random auxiliary data').digest()
    G = ECKey().set(1).get_pubkey()
    outpoints = [
        ("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16", 0),
        ("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d", 0),
        ("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d", 1)
    ]

    sender_bip32_seed = 'deadbeef'
    recipient_bip32_seed = 'f00dbabe'
    i1, I1 = get_key_pair(0, seed=bytes.fromhex(sender_bip32_seed))
    i2, I2 = get_key_pair(1, seed=bytes.fromhex(sender_bip32_seed))
    i3, I3 = get_key_pair(2, seed=bytes.fromhex(sender_bip32_seed))

    if I1.get_y()%2 != 0:
        i1.negate()
        I1.negate()

    if I2.get_y()%2 != 0:
        i2.negate()
        I2.negate()
    
    if I3.get_y()%2 == 0:
        i3.negate()
        I3.negate()

    nums_point = [
        [(i1, True, NUMS_H, True), (i2, True, None, False), (i3, True, NUMS_H, False)],
        [I1, I2, I3]
    ]

    test_cases = []
    comments = [
        "Single receipient: taproot input with NUMS point"
    ]
    for i, inputs in enumerate([nums_point]):
        sender, recipient, test_case = new_test_case()

        inp = []
        for x, (key, is_taproot, internal_key, add_annex) in enumerate(inputs[0]):
            pub_key = inputs[1][x]
            if is_taproot:
                if (internal_key == None):
                    inp += [{
                        "txid": outpoints[x][0],
                        "vout": outpoints[x][1],
                        "scriptSig": "",
                        "txinwitness": get_p2tr_witness(key),
                        "prevout": {"scriptPubKey": {"hex": get_p2tr_scriptPubKey(pub_key)}},
                    }]
                else:
                    inp += [{
                        "txid": outpoints[x][0],
                        "vout": outpoints[x][1],
                        "scriptSig": "",
                        "txinwitness": get_leafp2tr_witness(key, internal_key, add_annex = add_annex),
                        "prevout": {"scriptPubKey": {"hex": get_p2tr_scriptPubKey(pub_key)}},
                    }]
            else:
                inp += [{
                    "txid": outpoints[x][0],
                    "vout": outpoints[x][1],
                    "scriptSig": get_p2pkh_scriptsig(pub_key, key),
                    "txinwitness": "",
                    "prevout": {"scriptPubKey": {"hex": get_p2pkh_scriptPubKey(pub_key)}},
                }]

        priv_keys = []
        for (priv_key, is_taproot, internal_key, add_annex) in inputs[0]:
            priv_keys += [priv_key.get_bytes().hex()]
            

        sender['given']['vin'] = add_private_keys(deepcopy(inp), inputs[0])
        recipient['given']['vin'] = inp

        b_scan, b_spend, B_scan, B_spend = reference.derive_silent_payment_key_pair(bytes.fromhex(recipient_bip32_seed))
        recipient['given']['key_material']['scan_priv_key'] = b_scan.get_bytes().hex()
        recipient['given']['key_material']['spend_priv_key'] = b_spend.get_bytes().hex()
        address = reference.encode_silent_payment_address(B_scan, B_spend, hrp=HRP)

        sender['given']['recipients'].extend([(address, 1.0)])
        recipient['expected']['addresses'].extend([address])

        # Excluded inputs with NUMS point internal key
        included_keys = [inp for i, inp in enumerate(inputs[0]) if inp[2] == None]
        included_pubkeys = [pubkey for i, pubkey in enumerate(inputs[1]) if inputs[0][i][2] == None]
        
        A_sum = sum([p if not inputs[0][i][1] or p.get_y()%2==0 else p * -1  for i, p in enumerate(included_pubkeys)])
        deterministic_nonce = reference.get_input_hash([COutPoint(deser_txid(o[0]), o[1]) for o in outpoints], A_sum)

        outputs = reference.create_outputs([(inp[0], inp[1]) for inp in included_keys], deterministic_nonce, [(address, 1.0)], hrp=HRP)
        sender['expected']['outputs'] = outputs
        output_pub_keys = [recipient[0] for recipient in outputs]
        recipient['given']['outputs'] = output_pub_keys

        add_to_wallet = reference.scanning(
            b_scan,
            B_spend,
            A_sum,
            deterministic_nonce,
            [ECPubKey().set(bytes.fromhex(pub)) for pub in output_pub_keys],
        )
        for o in add_to_wallet:

            pubkey = ECPubKey().set(bytes.fromhex(o['pub_key']))
            full_private_key = b_spend.add(
                bytes.fromhex(o['priv_key_tweak'])
            )
            if full_private_key.get_pubkey().get_y()%2 != 0:
                full_private_key.negate()

            sig = full_private_key.sign_schnorr(msg, aux)
            assert pubkey.verify_schnorr(sig, msg)
            o['signature'] = sig.hex()

        recipient['expected']['outputs'] = add_to_wallet
        test_case['sending'].extend([sender])
        test_case['receiving'].extend([recipient])
        test_case["comment"] = comments[i]
        test_cases.append(test_case)

    return test_cases

def generate_malleated_p2pkh_test():
    sender, recipient, test_case = new_test_case()

    msg = hashlib.sha256(b'message').digest()
    aux = hashlib.sha256(b'random auxiliary data').digest()

    outpoints = [
        ("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16", 0),
        ("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16", 1),
        ("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16", 2),
    ]
    sender_bip32_seed = 'deadbeef'
    recipient_bip32_seed = 'f00dbabe'
    scan, spend, Scan, Spend = reference.derive_silent_payment_key_pair(bytes.fromhex(recipient_bip32_seed))
    address = reference.encode_silent_payment_address(Scan, Spend, hrp=HRP)
    addresses = [(address, 1.0)]

    recipient['given']['key_material']['scan_priv_key'] = scan.get_bytes().hex()
    recipient['given']['key_material']['spend_priv_key'] = spend.get_bytes().hex()
    recipient['expected']['addresses'] = [address]

    inputs = []
    input_priv_keys = []
    input_pub_keys = []

    def add_input(inputs, input_priv_keys, input_pub_keys, get_script_sig):
        i = len(inputs)
        priv, pub = get_key_pair(i, seed=bytes.fromhex(sender_bip32_seed))
        inputs += [{
            'txid': outpoints[i][0],
            'vout': outpoints[i][1],
            'scriptSig': get_script_sig(pub, priv),
            'txinwitness': '',
            'prevout': {'scriptPubKey': {'hex': get_p2pkh_scriptPubKey(pub)}},
        }]
        input_priv_keys += [(priv, False)]
        input_pub_keys += [pub]

    ## All inputs should be included
        
    # p2pkh
    add_input(inputs, input_priv_keys, input_pub_keys, get_p2pkh_scriptsig)

    # Malleated p2pkh
    # Test OP_O OP_DROP <normal script sig>
    add_input(inputs, input_priv_keys, input_pub_keys, lambda pub, priv: "0075" + get_p2pkh_scriptsig(pub, priv))
    # Test make dummy key look like private key
    # Ensures that reference implementation p2pkh can extract correct key
    # 0P_1 OP_IF <real_script> ELSE <fake_script> ENDIF
    fake_priv, fake_pub = get_key_pair(0, seed=bytes.fromhex("faecaa"))
    fake_script = get_p2pkh_scriptsig(fake_pub, fake_priv)
    add_input(inputs, input_priv_keys, input_pub_keys, lambda pub, priv: "5163" + get_p2pkh_scriptsig(pub, priv) + "67" + fake_script + "68")

    sender['given']['recipients'] = addresses
    A_sum = sum([p if not input_priv_keys[i][1] or p.get_y()%2==0 else p * -1  for i, p in enumerate(input_pub_keys)])
    deterministic_nonce = reference.get_input_hash([COutPoint(deser_txid(o[0]), o[1]) for o in outpoints], A_sum)
    outputs = reference.create_outputs(input_priv_keys, deterministic_nonce, addresses, hrp=HRP)
    sender['expected']['outputs'] = outputs
    sender['given']['vin'] = add_private_keys(deepcopy(inputs), input_priv_keys)

    output_pub_keys = [recipient[0] for recipient in outputs]

    recipient['given']['vin'] = inputs
    recipient['given']['outputs'] = output_pub_keys

    add_to_wallet = reference.scanning(
        scan,
        Spend,
        A_sum,
        deterministic_nonce,
        [ECPubKey().set(bytes.fromhex(pub)) for pub in output_pub_keys],
        labels={},
    )
    for o in add_to_wallet:

        pubkey = ECPubKey().set(bytes.fromhex(o['pub_key']))
        full_private_key = spend.add(
            bytes.fromhex(o['priv_key_tweak'])
        )
        if full_private_key.get_pubkey().get_y()%2 != 0:
            full_private_key.negate()

        sig = full_private_key.sign_schnorr(msg, aux)
        assert pubkey.verify_schnorr(sig, msg)
        o['signature'] = sig.hex()

    recipient['expected']['outputs'] = add_to_wallet
    
    test_case['sending'].extend([sender])
    test_case['receiving'].extend([recipient])
    test_case["comment"] = "Pubkey extraction from malleated p2pkh"
    test_cases = []
    test_cases.append(test_case)
    return test_cases

def generate_uncompressed_keys_tests():
    sender, recipient, test_case = new_test_case()

    msg = hashlib.sha256(b'message').digest()
    aux = hashlib.sha256(b'random auxiliary data').digest()

    outpoints = [
        ("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16", 0),
        ("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d", 0),
        ("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d", 1),
        ("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d", 2),
    ]

    sender_bip32_seed = 'deadbeef'
    inputs = []
    input_priv_keys = []
    input_pub_keys = []

    recipient_bip32_seed = 'f00dbabe'
    scan, spend, Scan, Spend = reference.derive_silent_payment_key_pair(bytes.fromhex(recipient_bip32_seed))
    address = reference.encode_silent_payment_address(Scan, Spend, hrp=HRP)

    recipient['given']['key_material']['scan_priv_key'] = scan.get_bytes().hex()
    recipient['given']['key_material']['spend_priv_key'] = spend.get_bytes().hex()
    recipient['expected']['addresses'] = [address]
    addresses = [(address, 1.0)]

    # p2pkh compressed Key
    i = len(inputs)
    priv, pub = get_key_pair(i, seed=bytes.fromhex(sender_bip32_seed))
    inputs += [{
        'txid': outpoints[i][0],
        'vout': outpoints[i][1],
        'scriptSig': get_p2pkh_scriptsig(pub, priv),
        'txinwitness': '',
        'prevout': {'scriptPubKey': {'hex': get_p2pkh_scriptPubKey(pub)}},
    }]
    input_priv_keys += [(priv, False)]
    input_pub_keys += [pub]

    # p2pkh Uncompressed Key
    i = len(inputs)
    priv, pub = get_key_pair(i, seed=bytes.fromhex(sender_bip32_seed))
    pub.compressed = False
    inputs += [{
        'txid': outpoints[i][0],
        'vout': outpoints[i][1],
        'scriptSig': get_p2pkh_scriptsig(pub, priv),
        'txinwitness': '',
        'prevout': {'scriptPubKey': {'hex': get_p2pkh_scriptPubKey(pub)}},
    }]
    input_priv_keys += [(priv, False)]

    # p2wpkh Uncompressed Key
    i = len(inputs)
    priv, pub = get_key_pair(i, seed=bytes.fromhex(sender_bip32_seed))
    pub.compressed = False
    sig = priv.sign_ecdsa(msg, low_s=False, rfc6979=True).hex()
    inputs += [{
        'txid': outpoints[i][0],
        'vout': outpoints[i][1],
        'scriptSig': '', 
        'txinwitness': serialize_witness_stack([sig, pub.get_bytes(False).hex()]),
        'prevout': {'scriptPubKey': {'hex': "0014" + reference.hash160(pub.get_bytes()).hex()}},
    }]
    input_priv_keys += [(priv, False)]

    A_sum = sum([p for p in input_pub_keys])
    deterministic_nonce = reference.get_input_hash([COutPoint(deser_txid(o[0]), o[1]) for o in outpoints], A_sum)
    outputs = reference.create_outputs(input_priv_keys[:1], deterministic_nonce, addresses, hrp=HRP)
    sender['expected']['outputs'] = outputs
    sender['given']['vin'] = add_private_keys(deepcopy(inputs), input_priv_keys)
    sender['given']['recipients'] = addresses

    output_pub_keys = [recipient[0] for recipient in outputs]

    test_case['sending'].extend([sender])
    recipient['given']['vin'] = inputs
    recipient['given']['outputs'] = output_pub_keys

    add_to_wallet = reference.scanning(
        scan,
        Spend,
        A_sum,
        deterministic_nonce,
        [ECPubKey().set(bytes.fromhex(pub)) for pub in output_pub_keys],
        labels={},
    )
    for o in add_to_wallet:

        pubkey = ECPubKey().set(bytes.fromhex(o['pub_key']))
        full_private_key = spend.add(
            bytes.fromhex(o['priv_key_tweak'])
        )
        if full_private_key.get_pubkey().get_y()%2 != 0:
            full_private_key.negate()

        sig = full_private_key.sign_schnorr(msg, aux)
        assert pubkey.verify_schnorr(sig, msg)
        o['signature'] = sig.hex()

    recipient['expected']['outputs'] = add_to_wallet

    test_case['receiving'].extend([recipient])
    test_case["comment"] = "P2PKH and P2WPKH Uncompressed Keys are skipped"
    return [test_case]


with open("send_and_receive_test_vectors.json", "w") as f:
    json.dump(
        generate_single_output_outpoint_tests() +
        generate_single_output_input_tests() +
        generate_multiple_output_tests() +
        generate_labeled_output_tests() +
        generate_multiple_outputs_with_labels_tests() +
        generate_change_tests() +
        generate_taproot_with_nums_point_test() +
        generate_malleated_p2pkh_test() +
        generate_uncompressed_keys_tests(),
        # generate_all_inputs_test(),

        f,
        indent=4,
    )
