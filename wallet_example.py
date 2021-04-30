from blspy import AugSchemeMPL, PrivateKey
from chia.util.ints import uint16, uint64
from chia.types.blockchain_format.program import Program, SerializedProgram
from chia.wallet.wallet import Wallet
from chia.types.blockchain_format.coin import Coin
from chia.types.coin_solution import CoinSolution
from chia.types.spend_bundle import SpendBundle
from chia.util.condition_tools import conditions_dict_for_solution, pkm_pairs_for_conditions_dict
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import (
    calculate_synthetic_secret_key,
    DEFAULT_HIDDEN_PUZZLE_HASH,
)

import json

from typing import Dict, List, Tuple, Optional
from chia.types.blockchain_format.sized_bytes import bytes32

from chia.util.keychain import mnemonic_to_seed
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import (
    puzzle_for_pk,
)
from chia.wallet.derive_keys import master_sk_to_wallet_sk
from chia.util.bech32m import encode_puzzle_hash, decode_puzzle_hash
from blspy import G1Element, AugSchemeMPL, G2Element

# pip install fire
import fire

def main(name):
    print(f"hello {name}")

def addr(sk):
    b = bytes.fromhex(sk)
    master_private_key = PrivateKey.from_bytes(b)
    child_public_key = master_private_key.get_g1()
    puzzle = puzzle_for_pk(child_public_key)
    puzzle_hash = puzzle.get_tree_hash()
    # xch
    address = encode_puzzle_hash(puzzle_hash, "txch")
    # print(address)
    return "{\"address\":\"" + address + "\", \"pubkey\":\"" + str(puzzle_hash) + "\"}"

def mnemonic():
    # mnemonic = "imitate obvious arch square fan bike thumb hedgehog crystal innocent shoe glare share father romance local size gloom hurt maid denial weapon wave bulb"
    mnemonic = "turn acquire ring mind empower ahead section often habit sick sail mountain pen repair catch drum insect file dry trend venue junk novel laptop"
    seed = mnemonic_to_seed(mnemonic, "")
    master_private_key = AugSchemeMPL.key_gen(seed)
    child_private_key = master_sk_to_wallet_sk(master_private_key, 0)
    child_public_key = child_private_key.get_g1()
    puzzle = puzzle_for_pk(child_public_key)
    puzzle_hash = puzzle.get_tree_hash()
    address = encode_puzzle_hash(puzzle_hash, "txch")

def puzzHash(pk):
    child_sk: PrivateKey = PrivateKey.from_bytes(bytes.fromhex(pk))
    child_public_key = child_sk.get_g1()
    puzzle = puzzle_for_pk(child_public_key)
    puzzle_hash = puzzle.get_tree_hash()
    # xch
    address = encode_puzzle_hash(puzzle_hash, "txch")
    return address

def puzzle():
    # public key --> puzzle
    pb = "b95e11eccf667b4312588094db0725257f4ce440835d808ed749c9ec39dc5c3afbfdfda7bbf24f2adb58335e848a7a94"
    g : G1Element = G1Element.from_bytes(bytes.fromhex(pb))
    puzzle = puzzle_for_pk(g)
    h = "ff02ffff01ff02ffff01ff02ffff03ff0bffff01ff02ffff03ffff09ff05ffff1dff0bffff1effff0bff0bffff02ff06ffff04ff02ffff04ff17ff8080808080808080ffff01ff02ff17ff2f80ffff01ff088080ff0180ffff01ff04ffff04ff04ffff04ff05ffff04ffff02ff06ffff04ff02ffff04ff17ff80808080ff80808080ffff02ff17ff2f808080ff0180ffff04ffff01ff32ff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff06ffff04ff02ffff04ff09ff80808080ffff02ff06ffff04ff02ffff04ff0dff8080808080ffff01ff0bffff0101ff058080ff0180ff018080ffff04ffff01b0a76f5e6a0fdb34124b18b492de6cb6ba637571df77c7e8be29a8e9127c4b94cee5cf385ad0c867b67d762fece5993a7eff018080"
    return str(puzzle) == h

def solution():
    primaries = []
    primaries.append({"puzzlehash": decode_puzzle_hash("txch1wc3xkqtf9a8u3cqkyeftnwz5rkqvvxpy2hyd0ctxe2p2d63mmurs95szsd"), "amount": uint64(1 * 10 ** 10)})
    primaries.append({"puzzlehash": decode_puzzle_hash("txch1uagpz8ma9g4ee2hhncjw5pscly2dpr5phve25d5gluarfwaxze3q2n8mfn"), "amount": uint64(3 * 10 ** 10)})

    first_spend: bool = True
    if first_spend:
        solution: Program = Wallet().make_solution(primaries=primaries)
        first_spend = False
    else:
        solution = Wallet().make_solution()
    s = "ff80ffff01ffff33ffa076226b01692f4fc8e0162652b9b8541d80c6182455c8d7e166ca82a6ea3bdf07ff8502540be40080ffff33ffa0e750111f7d2a2b9caaf79e24ea0618f914d08e81bb32aa3688ff3a34bba61662ff8506fc23ac008080ff8080"
    return str(solution) == s


def tx(info):
    j = json.dumps(info)
    m: Dict = eval(j)
    inputs: List = m.get("inputs")
    outputs: List = m.get("outputs")

    primaries = []
    for o in outputs:
        output: Dict = o
        address: str = output.get("address")
        value: float = output.get("value")
        primaries.append({"puzzlehash": decode_puzzle_hash(address), "amount": value})

    spends: List[CoinSolution] = []
    pks: List[str] = []
    first_spend = True
    for i in inputs:
        input: Dict = i
        pk: str = input.get("pk")
        pks.append(pk)
        txid: Dict = eval(input.get("txId"))
        parentCoinInfo = txid.get("parentCoinInfo")
        puzzleHash = txid.get("puzzleHash")
        amount = txid.get("amount")

        pa = bytes32(bytes.fromhex(parentCoinInfo[2:]))
        pu = bytes32(bytes.fromhex(puzzleHash[2:]))
        a = uint64(amount)
        coin: Coin = Coin(pa, pu, a)
        child_sk: PrivateKey = PrivateKey.from_bytes(bytes.fromhex(pk))
        child_public_key = child_sk.get_g1()
        puzzle = puzzle_for_pk(child_public_key)

        if first_spend:
            solution: Program = Wallet().make_solution(primaries=primaries)
            first_spend = False
        else:
            solution = Wallet().make_solution()
        spends.append(CoinSolution(coin, puzzle, solution))

    spend_bundle: SpendBundle = SpendBundle(spends, G2Element())
    # return json.dumps(spend_bundle.to_json_dict())
    return sign_tx(pks, spend_bundle)


def sign_tx(pks: List[str], spend_bundle: SpendBundle):
    # This field is the ADDITIONAL_DATA found in the constants
    additional_data: bytes = bytes.fromhex("ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb")
    puzzle_hash_to_sk: Dict[bytes32, PrivateKey] = {}

    for p in pks:
        child_sk: PrivateKey = PrivateKey.from_bytes(bytes.fromhex(p))
        # master_private_key = PrivateKey.from_bytes(
        #     bytes.fromhex(p))
        # child_sk = master_sk_to_wallet_sk(master_private_key, 242)
        child_pk: G1Element = child_sk.get_g1()
        puzzle = puzzle_for_pk(child_pk)
        puzzle_hash = puzzle.get_tree_hash()
        puzzle_hash_to_sk[puzzle_hash] = child_sk

    aggregate_signature: G2Element = G2Element()
    for coin_solution in spend_bundle.coin_solutions:
        if coin_solution.coin.puzzle_hash not in puzzle_hash_to_sk:
            return
        sk: PrivateKey = puzzle_hash_to_sk[coin_solution.coin.puzzle_hash]
        synthetic_secret_key: PrivateKey = calculate_synthetic_secret_key(sk, DEFAULT_HIDDEN_PUZZLE_HASH)

        err, conditions_dict, cost = conditions_dict_for_solution(
            coin_solution.puzzle_reveal, coin_solution.solution, 11000000000
        )

        if err or conditions_dict is None:
            print(f"Sign transaction failed, con:{conditions_dict}, error: {err}")
            return

        pk_msgs = pkm_pairs_for_conditions_dict(conditions_dict, bytes(coin_solution.coin.name()), additional_data)
        assert len(pk_msgs) == 1
        _, msg = pk_msgs[0]
        signature = AugSchemeMPL.sign(synthetic_secret_key, msg)

        aggregate_signature = AugSchemeMPL.aggregate([aggregate_signature, signature])

    new_spend_bundle = SpendBundle(spend_bundle.coin_solutions, aggregate_signature)
    # print(json.dumps(new_spend_bundle.to_json_dict()))
    return json.dumps(new_spend_bundle.to_json_dict())

if __name__ == '__main__':
    fire.Fire()
