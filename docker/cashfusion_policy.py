"""Version-bound deployment limits at CashFusion's native decision boundaries.

No transaction builder/signing replacement, spending database or preference reset.
"""
from collections import Counter

from cashfusion_defaults import cashfusion_config_from_environment, MAX_POLICY_SATOSHIS


def limits_from_environment():
    values = cashfusion_config_from_environment()['limits']
    return values['fee_budget_satoshis'], values['minimum_input_satoshis']


def _reject(message):
    from electroncash_plugins.fusion.util import FusionError
    raise FusionError('CashFusion deployment limit: ' + message)


def _amount(value):
    if type(value) is not int or not 0 <= value <= MAX_POLICY_SATOSHIS:
        _reject('invalid satoshi amount; cannot safely authorize round')
    return value


def filter_address_buckets(eligible, ineligible):
    """Keep whole native buckets; never sever linkage to include a larger coin."""
    _budget, minimum = limits_from_environment()
    if not minimum:
        return eligible, ineligible
    kept = []
    rejected = list(ineligible)
    for address, coins in eligible:
        if any(_amount(coin['value']) < minimum for coin in coins):
            rejected.append((address, coins))
        else:
            kept.append((address, coins))
    return kept, rejected


def validate_raw_inputs(fusion, coins):
    _budget, minimum = fusion._ecd_safety_limits
    if minimum and any(_amount(value) < minimum for _pubkey, value in coins.values()):
        _reject('selected input is below CASHFUSION_MIN_UTXO')


def validate_wallet_inputs(fusion, wallet, coins):
    """Reject before native key extraction/freezing; use original eligibility."""
    _budget, minimum = fusion._ecd_safety_limits
    if not minimum:
        return
    from electroncash_plugins.fusion.plugin import select_coins
    eligible, _ineligible, _total, _unconfirmed, _coinbase = select_coins(wallet)
    permitted = {(coin['prevout_hash'], coin['prevout_n'])
                 for _address, bucket in eligible for coin in bucket}
    if any(_amount(coin['value']) < minimum or
           (coin['prevout_hash'], coin['prevout_n']) not in permitted for coin in coins):
        _reject('input/address bucket violates minimum or native eligibility')


def enforce_signing(fusion, transaction, input_indices, components, own_indices):
    """Check actual final transaction before native Schnorr signing/submission.

    For one fully attributed source wallet, the player's own actual inputs minus
    own actual outputs is its exact fee contribution (component rounding + excess).
    Multi-source/raw provenance is rejected when a positive cap is enabled.
    Every native retry re-enters this boundary; no state is shared across rounds.
    """
    budget, minimum = fusion._ecd_safety_limits
    if not budget and not minimum:
        return
    from electroncash_plugins.fusion import fusion_pb2 as pb
    from electroncash.transaction import TYPE_ADDRESS
    indices = set(own_indices)
    if len(indices) != len(own_indices) or any(type(i) is not int or not 0 <= i < len(components) for i in indices):
        _reject('cannot identify own final components')
    inputs = transaction.inputs()
    if len(input_indices) != len(inputs):
        _reject('final input/component mapping is inconsistent')
    selected_inputs = {}
    for component_index, entry in zip(input_indices, inputs):
        if component_index not in indices:
            continue
        key = (entry['prevout_hash'], entry['prevout_n'])
        value = _amount(entry['value'])
        expected = fusion.coins.get(key)
        if expected is None or value != expected[1] or entry['pubkeys'] != [expected[0].hex()] or key in selected_inputs:
            _reject('own final input differs from selected native input')
        if minimum and value < minimum:
            _reject('final input is below CASHFUSION_MIN_UTXO')
        selected_inputs[key] = value
    if set(selected_inputs) != set(fusion.coins):
        _reject('own input attribution is incomplete')
    outputs = transaction.outputs()
    output_position = 1  # native CashFusion OP_RETURN precedes component outputs
    own_outputs = []
    for i, serialized in enumerate(components):
        component = pb.Component(); component.ParseFromString(serialized)
        if component.WhichOneof('component') != 'output':
            continue
        if output_position >= len(outputs):
            _reject('final outputs missing')
        kind, address, amount = outputs[output_position]; output_position += 1
        if i in indices:
            amount = _amount(amount)
            if kind != TYPE_ADDRESS or address.to_script() != component.output.scriptpubkey or amount != component.output.amount:
                _reject('own final output differs from committed component')
            own_outputs.append((amount, address.to_script()))
    if output_position != len(outputs):
        _reject('final output/component mapping is inconsistent')
    if Counter(own_outputs) != Counter((_amount(amount), address.to_script()) for amount, address in fusion.outputs):
        _reject('own final outputs differ from native allocation')
    contribution = sum(selected_inputs.values()) - sum(value for value, _script in own_outputs)
    if contribution < 0:
        _reject('negative contribution; cannot safely attribute fee')
    if budget:
        if len(fusion.source_wallet_info) != 1:
            _reject('positive fee cap requires one attributable source wallet per player')
        wallet, source = next(iter(fusion.source_wallet_info.items()))
        attributed = {txid + ':' + str(index) for txid, index in selected_inputs}
        if source[0] != attributed:
            _reject('positive fee cap cannot safely attribute raw or mixed inputs')
        # A wallet can natively self-fuse as several players in the same round.
        # Do not grant each player a separate copy of this per-wallet cap.
        # Without joint output provenance, conservatively reject such a round.
        for entry in inputs:
            key = (entry['prevout_hash'], entry['prevout_n'])
            if key not in selected_inputs and wallet.is_mine(entry['address']):
                _reject('positive fee cap cannot bound multiple players from the same wallet in one round')
        if contribution > budget:
            _reject('final wallet fee contribution exceeds CASHFUSION_FEE_BUDGET')
    fusion._ecd_last_checked_fee = contribution
