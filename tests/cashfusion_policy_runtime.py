"""Executed inside the candidate venv: real pinned consumers, synthetic data only."""
import ast
import inspect
import os
import threading
from collections import defaultdict

from cashfusion_defaults import CashFusionConfigurationError, cashfusion_config_from_environment
from cashfusion_policy import enforce_signing, filter_address_buckets
from electroncash import schnorr
from electroncash.address import Address
from electroncash.wallet import Standard_Wallet
from electroncash_plugins.fusion import fusion_pb2 as pb
from electroncash_plugins.fusion.fusion import Fusion, gen_components
from electroncash_plugins.fusion.plugin import FusionPlugin, select_coins
from electroncash_plugins.fusion.protocol import Protocol
from electroncash_plugins.fusion.util import FusionError, component_fee, size_of_input, tx_from_components, gen_keypair


class FixtureWallet(Standard_Wallet):
    def __init__(self, addresses=()):
        self.addresses=list(addresses);self.frozen_addresses=set();self.lock=threading.RLock()
        self.transactions={};self.txi={};self.utxos={};self.storage=type('Storage',(),{'get':lambda self,k,d=None:d})()
    def is_mine(self,address):return address in self.addresses
    def get_addresses(self):return self.addresses
    def get_addr_utxo(self,address):return self.utxos.get(address,{})
    def get_local_height(self):return 1000
    def is_watching_only(self):return False
    def is_hardware(self):return False
    def can_fully_sign_for_all_addresses(self):return True
    def diagnostic_name(self):return 'synthetic-policy-fixture'


def fixture(fee, budget, minimum=1000, input_value=100000, extra_wallet_input=False):
    secret, _uncompressed, public=gen_keypair()
    address=Address.from_pubkey(public);wallet=FixtureWallet([address])
    key=('11'*32,0)
    f=Fusion.__new__(Fusion);f._ecd_safety_limits=(budget,minimum)
    f.coins={key:(public,input_value)};f.inputs=tuple(f.coins.items())
    f.outputs=[(input_value-fee,address)];f.keypairs={public.hex():(secret,True)}
    f.source_wallet_info={wallet:({key[0]+':0'},set(),set())}
    components,_amount,_nonce=gen_components(0,f.inputs,f.outputs,1000)
    _commitments,_slots,serialized,_proofs,_keys=components
    own=list(range(len(serialized)))
    if extra_wallet_input:
        item=pb.Component(salt_commitment=b'\x23'*32);item.input.prev_txid=bytes.fromhex('22'*32);item.input.prev_index=1;item.input.pubkey=public;item.input.amount=10000
        serialized=tuple(serialized)+(item.SerializeToString(),)
    tx,indices=tx_from_components(serialized,b'\x42'*32)
    return f,tx,indices,serialized,own,wallet


def reject(call):
    try:call()
    except FusionError:return
    raise AssertionError('protected operation was not rejected')


def amounts_and_selection():
    defaults=cashfusion_config_from_environment({})
    assert defaults['limits']=={'fee_budget_satoshis':0,'minimum_input_satoshis':1000}
    for key in ('CASHFUSION_FEE_BUDGET','CASHFUSION_MIN_UTXO'):
        for value in ('','-1','1.2','1e3','nan','true','1_000','2100000000000001'):
            try:cashfusion_config_from_environment({key:value})
            except CashFusionConfigurationError:pass
            else:raise AssertionError((key,value,'accepted'))
    class LocalPlugin:pass
    plugin=LocalPlugin();target=Standard_Wallet.__new__(Standard_Wallet);target.network=object()
    os.environ['CASHFUSION_FEE_BUDGET']='500';os.environ['CASHFUSION_MIN_UTXO']='1000'
    first=Fusion(plugin,target,'localhost',8787,False,None,None)
    assert first._ecd_safety_limits==(500,1000)
    os.environ['CASHFUSION_FEE_BUDGET']='600'
    second=Fusion(plugin,target,'localhost',8787,False,None,None)
    assert second._ecd_safety_limits==(600,1000) and first._ecd_safety_limits==(500,1000)
    secret,_u,pub=gen_keypair();key=('33'*32,0);keys={pub.hex():(secret,True)}
    reject(lambda:first.add_coins({key:(pub,999)},keys))
    assert not first.coins and not first.keypairs
    first.add_coins({key:(pub,1000)},keys);assert first.coins[key][1]==1000
    os.environ['CASHFUSION_FEE_BUDGET']='0'
    for fee,budget in ((399,400),(400,400),(1000,0)):
        f,tx,indices,components,own,_wallet=fixture(fee,budget)
        enforce_signing(f,tx,indices,components,own)
        assert f._ecd_last_checked_fee==fee
    f,tx,indices,components,own,_=fixture(401,400)
    reject(lambda:enforce_signing(f,tx,indices,components,own))
    f,tx,indices,components,own,_=fixture(399,400)
    outputs=tx.outputs();kind,address,value=outputs[1]
    # Real transaction mutation after an acceptable estimate must not authorize.
    tx.set_outputs([(outputs[0]),(kind,address,value-2)])
    reject(lambda:enforce_signing(f,tx,indices,components,own))
    f,tx,indices,components,own,_=fixture(400,400,extra_wallet_input=True)
    reject(lambda:enforce_signing(f,tx,indices,components,own))
    f,tx,indices,components,own,wallet=fixture(400,400)
    f.source_wallet_info[FixtureWallet()] = (set(),set(),set())
    reject(lambda:enforce_signing(f,tx,indices,components,own))
    # Independent objects/rounds/wallets hold their own bound policy and result.
    f1,t1,i1,c1,o1,_=fixture(200,200);f2,t2,i2,c2,o2,_=fixture(500,500)
    enforce_signing(f1,t1,i1,c1,o1);enforce_signing(f2,t2,i2,c2,o2)
    assert f1._ecd_last_checked_fee==200 and f2._ecd_last_checked_fee==500
    os.environ['CASHFUSION_MIN_UTXO']='1000'
    addresses=[Address(os.urandom(20),Address.ADDR_P2PKH) for _ in range(6)]
    w=FixtureWallet(addresses)
    def coin(value,n,**extra):
        return dict(value=value,prevout_hash=f'{n:064x}',prevout_n=0,token_data=None,slp_token=False,is_frozen_coin=False,coinbase=False,height=1,**extra)
    for n,address in enumerate(addresses):w.utxos[address]={str(n):coin(1000+n,n)}
    w.utxos[addresses[0]]['dust']=coin(999,100)
    w.utxos[addresses[2]][str(2)]['is_frozen_coin']=True
    w.utxos[addresses[3]][str(3)]['token_data']=object()
    w.utxos[addresses[4]][str(4)]['height']=0
    w.frozen_addresses.add(addresses[5])
    eligible,ineligible,total,unconfirmed,coinbase=select_coins(w)
    assert [a for a,_ in eligible]==[addresses[1]] and len(ineligible)==5 and unconfirmed
    assert len(next(bucket for address,bucket in ineligible if address==addresses[0]))==2
    os.environ['CASHFUSION_MIN_UTXO']='2000'
    assert select_coins(w)[0]==[]
    os.environ['CASHFUSION_MIN_UTXO']='0'
    assert addresses[0] in [a for a,_ in select_coins(w)[0]]
    print('PASS native final-transaction fee boundaries, provenance/concurrency, integer validation and native address-bucket eligibility',flush=True)


def real_signing_segment():
    # Compile the exact installed native signing block, including its inserted
    # policy call. Crypto signing, tx builder and policy are real, not replaced.
    source=inspect.getsource(Fusion.run_round)
    tree=ast.parse('class Native:\n'+source)
    assert isinstance(tree.body[0],ast.ClassDef)
    function=tree.body[0].body[0]
    assert isinstance(function, ast.FunctionDef)
    branch=next(node for node in function.body if isinstance(node,ast.If) and ast.unparse(node.test)=='not skip_signatures')
    segment=[]
    for node in branch.body:
        segment.append(node)
        if isinstance(node,ast.Expr) and isinstance(node.value,ast.Call) and ast.unparse(node.value.func)=='covert.schedule_submissions':break
    compiled=ast.Module(body=segment,type_ignores=[]);ast.fix_missing_locations(compiled)
    native=__import__('electroncash_plugins.fusion.fusion',fromlist=['Fusion'])
    for fee,budget,allowed in ((399,400,True),(400,400,True),(401,400,False),(1000,0,True)):
        f,tx,indices,components,own,wallet=fixture(fee,budget)
        class Peer:
            def __init__(self):self.submissions=[]
            def schedule_submissions(self,when,messages):self.submissions.append(messages)
        peer=Peer();f.print_error=lambda *args:None;f.mycomponentslots=list(range(len(components)))
        scope=dict(vars(native),self=f,all_components=components,mycomponent_idxes=own,mycomponents=components,
                   mycomponentslots=list(range(len(components))),session_hash=b'\x42'*32,covert=peer,covert_T0=0)
        try:exec(compile(compiled,'<installed pinned native signing block>','exec'),scope)
        except FusionError:
            assert not allowed and not peer.submissions
        else:
            assert allowed and len(peer.submissions)==1
            signatures=[m for m in peer.submissions[0] if m is not None]
            assert signatures and all(len(m.txsignature)==64 for m in signatures)
    print('PASS actual installed native signing block enforces before genuine Schnorr signing/submission',flush=True)


def native_setup_and_auto():
    """Real native setup/auto consumers; synthetic wallet/network, no peer/funds."""
    from electroncash_plugins.fusion import plugin as native
    from unittest.mock import patch
    os.environ['CASHFUSION_FEE_BUDGET']='400'
    os.environ['CASHFUSION_MIN_UTXO']='1000'
    secret,_u,public=gen_keypair();address=Address.from_pubkey(public)
    wallet=FixtureWallet([address]);wallet.network=object()
    wallet._fusions=set();wallet._fusions_auto=set();wallet.up_to_date=True
    wallet.cashfusion_tag=b'synthetic-wallet'
    calls=[]
    class Keys:
        def get_pubkey_derivation(self,key):return 0
        def get_private_key(self,derivation,password):calls.append('key');return secret,True
    wallet.keystore=Keys()
    wallet.add_input_info=lambda coin:coin.update(x_pubkeys=[public.hex()])
    wallet.set_frozen_coin_state=lambda coins,state,**kw:calls.append(('freeze',state,set(coins)))
    def coin(value,n):
        return dict(value=value,prevout_hash=f'{n:064x}',prevout_n=0,address=address,token_data=None,
                    slp_token=False,is_frozen_coin=False,coinbase=False,height=1)
    plugin=FusionPlugin.__new__(FusionPlugin);plugin.lock=threading.RLock();plugin.fusions={}
    plugin.get_server=lambda:('localhost',8787,False)
    wallet.utxos[address]={'small':coin(999,1),'large':coin(2000,2)}
    try:plugin.start_fusion(wallet,None,[wallet.utxos[address]['large']])
    except RuntimeError as error:assert 'deployment limit' in str(error)
    else:raise AssertionError('native manual setup bypassed whole-bucket limit')
    assert calls==[] and not plugin.fusions and not wallet._fusions
    # Equality and multiple inputs travel through real key extraction/add/freeze.
    wallet.utxos[address]={'one':coin(1000,3),'two':coin(2000,4)}
    f=Fusion(plugin,wallet,'localhost',8787,False,None,None)
    f.notify_coins_ui=lambda wallet:None
    f.add_coins_from_wallet(wallet,None,wallet.utxos[address].values())
    assert len(f.coins)==2 and len(f.source_wallet_info[wallet][0])==2
    assert calls[0]=='key' and calls[1][0:2]==('freeze',True)
    # Native automatic path selects no coins and never invokes start_fusion.
    wallet.utxos[address]={'small':coin(999,5)}
    plugin._run_iter=49;plugin.active=True;plugin.autofusing_wallets={wallet:None}
    plugin.t_last_net_ok=0;messages=[];plugin.print_error=lambda *args:messages.append(args)
    plugin.start_fusion=lambda *args,**kw:(_ for _ in ()).throw(AssertionError('auto started ineligible coins'))
    class Connected:
        def is_connected(self):return True
    assert native.limiter.count==0
    with patch.object(native.Network,'get_instance',return_value=Connected()):
        plugin.run()
    assert any('lack of coins' in str(message) for message in messages)
    # Re-entering the actual signing boundary on a retry must re-evaluate fees.
    f,tx,indices,components,own,_=fixture(400,400)
    enforce_signing(f,tx,indices,components,own)
    f.outputs[0]=(f.outputs[0][0]-1,f.outputs[0][1])
    reject(lambda:enforce_signing(f,tx,indices,components,own))
    # Simultaneous independent wallet rounds cannot share or overwrite caps.
    def check(item):
        fee,budget=item;f,tx,indices,components,own,_=fixture(fee,budget)
        if fee>budget:reject(lambda:enforce_signing(f,tx,indices,components,own));return 'reject'
        enforce_signing(f,tx,indices,components,own);return f._ecd_last_checked_fee
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(check,[(200,200),(401,400),(500,500)]))==[200,'reject',500]
    print('PASS real native manual setup rejection before keys/freezing, multiple/equal inputs, automatic no-eligible path, retries and concurrent wallets',flush=True)


def main():
    amounts_and_selection();real_signing_segment();native_setup_and_auto()


if __name__=='__main__':main()
