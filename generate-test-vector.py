#!/usr/bin/env python

import reference
import json
from secp256k1 import *
import bip32
from copy import deepcopy
from importlib import reload
reload(reference)

G = ECKey().set(1).get_pubkey()
sending_test_vectors = []

HRP="sp"

def get_key_pair(index, seed=b'deadbeef', derivation='m/0h'):

    master = bip32.BIP32.from_seed(seed)
    d = ECKey().set(master.get_privkey_from_path(f'{derivation}/{index}'))
    P = d.get_pubkey()

    return d, P

def read_sending_test_inputs(sender):

    outpoints = sender['given']['outpoints']
    input_priv_keys = [ECKey().set(bytes.fromhex(key)) for key in sender['given']['input_priv_keys']]
    addresses = sender['given']['recipients']

    return outpoints, input_priv_keys, addresses

def read_receiving_test_inputs(recipient):

    outpoints = recipient['given']['outpoints']
    input_pub_keys = [ECPubKey().set(bytes.fromhex(key)) for key in recipient['given']['input_pub_keys']]
    bip32_seed = recipient['given']['bip32_seed']
    labels = recipient['given']['labels']

    return outpoints, input_pub_keys, bip32_seed, labels

def new_test_case():
    recipient =  {
        "supports_labels": False,
        "given": {
            "outpoints": [],
            "input_pub_keys": [],
            "bip32_seed": "",
            "scan_priv_key": "",
            "spend_priv_key": "",
            "labels": {},
        },
        "expected": {
            "addresses": [],
            "outputs": [],
        }
    }
    sender = {
        "given": {
            "outpoints": [],
            "input_priv_keys": [],
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

    msg = reference.sha256(b'message')
    aux = reference.sha256(b'random auxiliary data')
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
    label_ints = [(2).to_bytes(32, 'big').hex(),(3).to_bytes(32, 'big').hex(),(1001337).to_bytes(32, 'big').hex()]
    recipient_labels = {(bytes.fromhex(label_int)*G).get_bytes(False).hex(): label_int for label_int in label_ints}
    b_scan, b_spend, B_scan, B_spend = reference.derive_silent_payment_key_pair(bytes.fromhex(recipient_bip32_seed))

    address = reference.encode_silent_payment_address(B_scan, B_spend, hrp=HRP)
    labeled_addresses = [
        reference.create_labeled_silent_payment_address(B_scan, B_spend, bytes.fromhex(case), hrp=HRP) for case in label_ints
    ]
    recipient_addresses = [address] + labeled_addresses
    comments = ["Receiving with labels: label with even parity", "Receiving with labels: label with odd parity", "Receiving with labels: large label integer"]
    for i, case in enumerate(label_ints):
        sender, recipient, test_case = new_test_case()
        address = reference.create_labeled_silent_payment_address(B_scan, B_spend, bytes.fromhex(case), hrp=HRP)
        addresses = [(address, 1.0)]

        sender['given']['outpoints'] = outpoints
        sender['given']['recipients'] = addresses
        recipient['given']['outpoints'] = outpoints
        recipient['given']['bip32_seed'] = recipient_bip32_seed
        recipient['given']['scan_priv_key'] = b_scan.get_bytes().hex()
        recipient['given']['spend_priv_key'] = b_spend.get_bytes().hex()
        recipient['expected']['addresses'] = recipient_addresses
        recipient['given']['labels'] = recipient_labels
        recipient['supports_labels'] = True
        sender['given']['input_priv_keys'].extend(
            [(i1.get_bytes().hex(), False), (i2.get_bytes().hex(), False)])
        recipient['given']['input_pub_keys'].extend([I1.get_bytes(False).hex(), I2.get_bytes(False).hex()])

        outpoints_hash = reference.hash_outpoints(outpoints)
        outputs = reference.create_outputs(input_priv_keys, outpoints_hash, addresses, hrp=HRP)
        sender['expected']['outputs'] = outputs
        output_pub_keys = [r[0] for r in outputs]
        recipient['given']['outputs'] = output_pub_keys

        A_sum = sum(input_pub_keys)
        add_to_wallet = reference.scanning(
            b_scan,
            B_spend,
            A_sum,
            outpoints_hash,
            [ECPubKey().set(bytes.fromhex(pub)) for pub in output_pub_keys],
            labels=recipient_labels,
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

    msg = reference.sha256(b'message')
    aux = reference.sha256(b'random auxiliary data')
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
        sender['given']['outpoints'] = outpoints
        recipient['given']['outpoints'] = outpoints
        sender['given']['input_priv_keys'].extend(
            [(i1.get_bytes().hex(), False),(i2.get_bytes().hex(), False)])
        recipient['given']['input_pub_keys'].extend([I1.get_bytes(False).hex(), I2.get_bytes(False).hex()])

        b_scan, b_spend, B_scan, B_spend = reference.derive_silent_payment_key_pair(bytes.fromhex(recipient_bip32_seed))
        recipient['given']['bip32_seed'] = recipient_bip32_seed
        recipient['given']['scan_priv_key'] = b_scan.get_bytes().hex()
        recipient['given']['spend_priv_key'] = b_spend.get_bytes().hex()
        address = reference.encode_silent_payment_address(B_scan, B_spend, hrp=HRP)

        sender['given']['recipients'].extend([(address, 1.0)])
        recipient['expected']['addresses'].extend([address])

        outpoints_hash = reference.hash_outpoints(outpoints)
        outputs = reference.create_outputs(input_priv_keys, outpoints_hash, [(address, 1.0)], hrp=HRP)
        sender['expected']['outputs'] = outputs
        output_pub_keys = [recipient[0] for recipient in outputs]
        recipient['given']['outputs'] = output_pub_keys

        A_sum = sum(input_pub_keys)
        add_to_wallet = reference.scanning(
            b_scan,
            B_spend,
            A_sum,
            reference.hash_outpoints(outpoints),
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

    msg = reference.sha256(b'message')
    aux = reference.sha256(b'random auxiliary data')
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


    sender['given']['outpoints'] = outpoints
    sender1['given']['outpoints'] = outpoints
    sender['given']['recipients'] = addresses1
    recipient1['given']['outpoints'] = outpoints
    recipient2['given']['outpoints'] = outpoints
    recipient1['given']['bip32_seed'] = recipient_one_bip32_seed
    recipient1['given']['scan_priv_key'] = scan1.get_bytes().hex()
    recipient1['given']['spend_priv_key'] = spend1.get_bytes().hex()
    recipient1['expected']['addresses'] = [address1]
    recipient2['given']['bip32_seed'] = recipient_two_bip32_seed
    recipient2['given']['scan_priv_key'] = scan2.get_bytes().hex()
    recipient2['given']['spend_priv_key'] = spend2.get_bytes().hex()
    recipient2['expected']['addresses'] = [address2]

    sender['given']['input_priv_keys'].extend(
        [(i1.get_bytes().hex(), False), (i2.get_bytes().hex(), False)]
    )
    sender1['given']['input_priv_keys'].extend(
        [(i1.get_bytes().hex(), False), (i2.get_bytes().hex(), False)]
    )
    recipient1['given']['input_pub_keys'].extend([I1.get_bytes(False).hex(), I2.get_bytes(False).hex()])
    recipient2['given']['input_pub_keys'].extend([I1.get_bytes(False).hex(), I2.get_bytes(False).hex()])

    outpoints_hash = reference.hash_outpoints(outpoints)
    outputs = reference.create_outputs(input_priv_keys, outpoints_hash, addresses1, hrp=HRP)
    sender['expected']['outputs'] = outputs
    output_pub_keys = [recipient[0] for recipient in outputs]
    recipient1['given']['outputs'] = output_pub_keys

    A_sum = sum(input_pub_keys)
    add_to_wallet = reference.scanning(
        scan1,
        Spend1,
        A_sum,
        reference.hash_outpoints(outpoints),
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
    outputs = reference.create_outputs(input_priv_keys, outpoints_hash, addresses1 + addresses2, hrp=HRP)
    sender1['expected']['outputs'] = outputs
    output_pub_keys = [recipient[0] for recipient in outputs]
    recipient1['given']['outputs'] = output_pub_keys
    recipient2['given']['outputs'] = output_pub_keys

    add_to_wallet = reference.scanning(
        scan2,
        Spend2,
        A_sum,
        reference.hash_outpoints(outpoints),
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

    msg = reference.sha256(b'message')
    aux = reference.sha256(b'random auxiliary data')
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

    outpoints_hash = reference.hash_outpoints(outpoints)
    outputs = reference.create_outputs(input_priv_keys, outpoints_hash, [(address, 1.0)], hrp=HRP)
    sender['expected']['outputs'] = outputs
    output_pub_keys = [recipient[0] for recipient in outputs]
    recipient['given']['outputs'] = output_pub_keys

    A_sum = sum(input_pub_keys)
    add_to_wallet = reference.scanning(
        b_scan,
        B_spend,
        A_sum,
        reference.hash_outpoints(outpoints),
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


# In[14]:


def generate_multiple_outputs_with_labels_tests():

    msg = reference.sha256(b'message')
    aux = reference.sha256(b'random auxiliary data')
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
    label_address_one = reference.create_labeled_silent_payment_address(Scan1, Spend1, m=(1).to_bytes(32, 'big'), hrp=HRP)
    label_address_two = reference.create_labeled_silent_payment_address(Scan1, Spend1, m=(1337).to_bytes(32,'big'), hrp=HRP)
    labels_one = {((1).to_bytes(32, 'big')*G).get_bytes(False).hex():(1).to_bytes(32, 'big').hex()}
    labels_three = {(1*G).get_bytes(False).hex():(1).to_bytes(32, 'big').hex(), (1337*G).get_bytes(False).hex(): (1337).to_bytes(32, 'big').hex()}
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
        sender['given']['outpoints'] = outpoints
        recipient['given']['outpoints'] = outpoints
        sender['given']['input_priv_keys'].extend([(i1.get_bytes().hex(), False), (i2.get_bytes().hex(), False)])
        recipient['given']['input_pub_keys'].extend([I1.get_bytes(False).hex(), I2.get_bytes(False).hex()])

        recipient['given']['bip32_seed'] = recipient_bip32_seed
        recipient['given']['scan_priv_key'] = scan1.get_bytes().hex()
        recipient['given']['spend_priv_key'] = spend1.get_bytes().hex()
        sender['given']['recipients'] = addrs
        recipient['expected']['addresses'] = sp_addresses[i]
        recipient['given']['labels'] = labels[i]
        recipient['supports_labels'] = True
        outpoints_hash = reference.hash_outpoints(outpoints)
        outputs = reference.create_outputs(input_priv_keys, outpoints_hash, addrs, hrp=HRP)
        sender['expected']['outputs'] = outputs
        output_pub_keys = [recipient[0] for recipient in outputs]
        recipient['given']['outputs'] = output_pub_keys

        A_sum = sum(input_pub_keys)
        add_to_wallet = reference.scanning(
            scan1,
            Spend1,
            A_sum,
            reference.hash_outpoints(outpoints),
            [ECPubKey().set(bytes.fromhex(pub)) for pub in output_pub_keys],
            labels=labels[i],
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


# In[ ]:





# In[15]:


def generate_single_output_input_tests():

    msg = reference.sha256(b'message')
    aux = reference.sha256(b'random auxiliary data')
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

    if I1.get_y()%2 != 0:
        i1.negate()
        I1.negate()

    if I2.get_y()%2 != 0:
        i2.negate()
        I2.negate()

    if I3.get_y()%2 == 0:
        i3.negate()
        I3.negate()

    address_reuse = [
        [(i1.get_bytes().hex(), False), (i1.get_bytes().hex(), False)],
        [I1.get_bytes(False).hex(), I1.get_bytes(False).hex()]
    ]
    taproot_only = [
        [(i1.get_bytes().hex(), True), (i2.get_bytes().hex(), True)],
        [I1.get_bytes().hex(), I2.get_bytes().hex()]
    ]

    i2.negate()
    I2.negate()

    taproot_only_with_odd_y = [
        [(i1.get_bytes().hex(), True), (i2.get_bytes().hex(), True)],
        [I1.get_bytes().hex(), I2.get_bytes().hex()]
    ]
    mixed = [
        [(i1.get_bytes().hex(), True), (i3.get_bytes().hex(), False)],
        [I1.get_bytes().hex(), I3.get_bytes(False).hex()]
    ]
    mixed_with_odd_y = [
        [(i2.get_bytes().hex(), True), (i3.get_bytes().hex(), False)],
        [I2.get_bytes().hex(), I3.get_bytes(False).hex()]
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
        sender['given']['outpoints'] = outpoints
        recipient['given']['outpoints'] = outpoints
        sender['given']['input_priv_keys'] = inputs[0]
        recipient['given']['input_pub_keys'] = inputs[1]

        b_scan, b_spend, B_scan, B_spend = reference.derive_silent_payment_key_pair(bytes.fromhex(recipient_bip32_seed))
        recipient['given']['bip32_seed'] = recipient_bip32_seed
        recipient['given']['scan_priv_key'] = b_scan.get_bytes().hex()
        recipient['given']['spend_priv_key'] = b_spend.get_bytes().hex()
        address = reference.encode_silent_payment_address(B_scan, B_spend, hrp=HRP)

        sender['given']['recipients'].extend([(address, 1.0)])
        recipient['expected']['addresses'].extend([address])

        outpoints_hash = reference.hash_outpoints(outpoints)
        outputs = reference.create_outputs([(ECKey().set(bytes.fromhex(k)), is_xonly) for k, is_xonly in inputs[0]], outpoints_hash, [(address, 1.0)], hrp=HRP)
        sender['expected']['outputs'] = outputs
        output_pub_keys = [recipient[0] for recipient in outputs]
        recipient['given']['outputs'] = output_pub_keys

        A_sum = sum([ECPubKey().set(bytes.fromhex(p)) for p in inputs[1]])
        add_to_wallet = reference.scanning(
            b_scan,
            B_spend,
            A_sum,
            reference.hash_outpoints(outpoints),
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


# In[16]:


def generate_change_tests():

    sender, recipient, test_case = new_test_case()

    msg = reference.sha256(b'message')
    aux = reference.sha256(b'random auxiliary data')
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
    change_label = reference.sha256(scan0.get_bytes())
    change_labels = {(change_label*G).get_bytes(False).hex(): change_label.hex()}
    change_address = reference.create_labeled_silent_payment_address(Scan0, Spend0, m=change_label, hrp=HRP)

    recipient_bip32_seed = 'f00dbabe'
    scan1, spend1, Scan1, Spend1 = reference.derive_silent_payment_key_pair(bytes.fromhex(recipient_bip32_seed))
    address = reference.encode_silent_payment_address(Scan1, Spend1, hrp=HRP)
    addresses = [(address, 1.0), (change_address, 2.0)]

    test_cases = []
    sp_recipients = [[address, change_address]]

    rec1, rec2 = deepcopy(recipient), deepcopy(recipient)
    rec1['given']['bip32_seed'] = sender_bip32_seed
    rec1['given']['scan_priv_key'] = scan0.get_bytes().hex()
    rec1['given']['spend_priv_key'] = spend0.get_bytes().hex()
    rec2['given']['bip32_seed'] = recipient_bip32_seed
    rec2['given']['scan_priv_key'] = scan1.get_bytes().hex()
    rec2['given']['spend_priv_key'] = spend1.get_bytes().hex()
    rec1['expected']['addresses'] = [sender_address, change_address]
    rec1['given']['labels'] = change_labels
    rec1['supports_labels'] = True
    rec2['expected']['addresses'] = [address]

    sender['given']['input_priv_keys'].extend(
        [(i1.get_bytes().hex(), False), (i2.get_bytes().hex(), False)])
    sender['given']['outpoints'] = outpoints
    sender['given']['recipients'] = addresses
    outputs = reference.create_outputs(input_priv_keys, reference.hash_outpoints(outpoints), addresses, hrp=HRP)
    sender['expected']['outputs'] = outputs

    output_pub_keys = [recipient[0] for recipient in outputs]

    test_case['sending'].extend([sender])
    labels = [change_labels, {}]
    for i, rec in enumerate([rec1, rec2]):
        rec['given']['outpoints'] = outpoints
        rec['given']['input_pub_keys'].extend([I1.get_bytes(False).hex(), I2.get_bytes(False).hex()])
        rec['given']['outputs'] = output_pub_keys

        A_sum = sum(input_pub_keys)
        scan, spend, Scan, Spend = reference.derive_silent_payment_key_pair(bytes.fromhex(rec['given']['bip32_seed']))
        add_to_wallet = reference.scanning(
            scan,
            Spend,
            A_sum,
            reference.hash_outpoints(outpoints),
            [ECPubKey().set(bytes.fromhex(pub)) for pub in output_pub_keys],
            labels=labels[i],
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


with open("send_and_receive_test_vectors.json", "w") as f:
    json.dump(
        generate_single_output_outpoint_tests() +
        generate_single_output_input_tests() +
        generate_multiple_output_tests() +
        generate_labeled_output_tests() +
        generate_multiple_outputs_with_labels_tests() +
        generate_change_tests(),
        f,
        indent=4,
    )
