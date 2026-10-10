"""Apply identifiable safety call sites to the verified, pinned 4.4.6 source."""
import hashlib
import sys
from pathlib import Path

root = Path(sys.argv[1]) / 'electroncash_plugins/fusion'
patches = {
    'fusion.py': ('3aa23d37763e5ba545a780d5ae4056a3f5036d42f35d6bec28976d1b883b6299', [
        ('        self.coins = dict() # full input info',
         "        from cashfusion_policy import limits_from_environment\n        self._ecd_safety_limits = limits_from_environment()\n        self.coins = dict() # full input info"),
        ("        assert self.status[0] == 'setup'\n        for hpub, priv in keypairs.items():",
         "        assert self.status[0] == 'setup'\n        from cashfusion_policy import validate_raw_inputs\n        validate_raw_inputs(self, coins)\n        for hpub, priv in keypairs.items():"),
        ('        assert can_fuse_from(wallet)\n        if len(self.source_wallet_info)',
         '        assert can_fuse_from(wallet)\n        from cashfusion_policy import validate_wallet_inputs\n        coins = tuple(coins)\n        validate_wallet_inputs(self, wallet, coins)\n        if len(self.source_wallet_info)'),
        ('            tx, input_indices = tx_from_components(all_components, session_hash)',
         '            tx, input_indices = tx_from_components(all_components, session_hash)\n            from cashfusion_policy import enforce_signing\n            enforce_signing(self, tx, input_indices, all_components, mycomponent_idxes)'),
    ]),
    'plugin.py': ('a595ebc92221e6f5b866df059d2ceb5f6f884325485030943be1320a264b3112', [
        ('        fusion.add_coins_from_wallet(source_wallet, password, coins)',
         '        from .util import FusionError\n        try:\n            fusion.add_coins_from_wallet(source_wallet, password, coins)\n        except FusionError as error:\n            # Native Qt/manual and automatic setup consumers display RuntimeError.\n            raise RuntimeError(str(error)) from error'),
        ('    return eligible, ineligible, int(sum_value), bool(has_unconfirmed), bool(has_coinbase)',
         '    from cashfusion_policy import filter_address_buckets\n    eligible, ineligible = filter_address_buckets(eligible, ineligible)\n    return eligible, ineligible, int(sum_value), bool(has_unconfirmed), bool(has_coinbase)'),
    ]),
}
for filename, (digest, replacements) in patches.items():
    path = root / filename
    original = path.read_bytes()
    if hashlib.sha256(original).hexdigest() != digest:
        raise SystemExit('unexpected pinned CashFusion source: ' + filename)
    text = original.decode()
    for before, after in replacements:
        if text.count(before) != 1:
            raise SystemExit('unexpected CashFusion enforcement structure: ' + filename)
        text = text.replace(before, after, 1)
    path.write_text(text)
    print('Applied pinned CashFusion decision/signing-boundary patch:', filename)
