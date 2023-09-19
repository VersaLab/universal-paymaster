import os
import re
import time
import json
import environ
import logging
import requests
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse
from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware
from eth_account.messages import defunct_hash_message
from jsonrpcserver import method, Result, Success, dispatch, Error
from .models import ApprovedTokens
from .serializers import OperationSerialzer


env = environ.Env()
logger = logging.getLogger(__name__)
w3 = Web3(HTTPProvider(env('RPC_URL')))
w3.middleware_onion.inject(geth_poa_middleware, layer=0)
chainid = str(w3.eth.chain_id)
approved_tokens = ApprovedTokens.objects.filter(chains__has_key=chainid)
pattern = re.compile(f'\"price\":\"(\d+\.\d+)\"')

entrypoint_address = env('ENTRYPOINT_CONTRACT_ADDRESS')
paymaster_address = env('PAYMASTER_CONTRACT_ADDRESS')
paymaster_verifier = w3.eth.account.from_key(env('PAYMASTER_VERIFYER_PRIVATE_KEY'))
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "abis/PaymasterABI.json")) as f:
    paymaster_abi = json.load(f)
    paymaster = w3.eth.contract(address=paymaster_address, abi=paymaster_abi)
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "abis/VersaWalletABI.json")) as f:
    versawallet_abi = json.load(f)
    versawallet = w3.eth.contract(abi=versawallet_abi)
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "abis/IERC20ABI.json")) as f:
    ierc20_abi = json.load(f)


class TempError:
    def __init__(self, code, message, data=None):
        self.code = code
        self.message = message
        self.data = data


@method
def pm_sponsorUserOperation(user_operation, token_address) -> Result:
    start_time = time.time()
    token_object = approved_tokens.filter(chains__icontains=token_address)
    if len(token_object) < 1:
        return Error(2, "Unsupported token", data="Unsupported token")
    token = token_object.first().chains[chainid]
    if token["address"] != token_address or not token["enabled"]:
        return Error(2, "Unsupported token", data="Unsupported token")
    serialzer = OperationSerialzer(data=user_operation)
    if not serialzer.is_valid():
        return Error(400, "BAD REQUEST", data="BAD REQUEST")

    op = dict(serialzer.data)
    op["nonce"] = int(op["nonce"], 16)
    op["callGasLimit"] = int(op["callGasLimit"], 16)
    op["verificationGasLimit"] = int(op["verificationGasLimit"], 16)
    op["preVerificationGas"] = int(op["preVerificationGas"], 16)
    op["maxFeePerGas"] = int(op["maxFeePerGas"], 16)
    op["maxPriorityFeePerGas"] = int(op["maxPriorityFeePerGas"], 16)

    token_rate = _get_token_rate(token)

    res = _check_balance_and_allowance(op, token_address, token_rate)
    if isinstance(res, TempError):
        return Error(res.code, res.message, data=res.data)

    paymasterData = [
        token["address"],
        1,  # SponsorMode (GAS ONLY)
        round(time.time()) + 900,  # validUntil 15 minutes in the future
        0,  # Fee (in case mode == 0)
        token_rate,
        b'',
    ]
    paymasterData[5] = paymaster_verifier.signHash(defunct_hash_message(paymaster.functions.getHash(op, paymasterData).call())).signature.hex()
    paymasterAndData = f"{paymaster_address}{paymasterData[0][2:]}{paymasterData[1]:0>2x}{paymasterData[2]:0>12x}{paymasterData[3]:0>64x}{paymasterData[4]:0>64x}{paymasterData[5][2:]}".lower()
    end_time = time.time()
    duration = round((end_time - start_time), 3) * 1000
    logger.info(f"pm_sponsorUserOperation {duration}ms user_operation:{user_operation} token_address:{token_address} paymasterAndData:{paymasterAndData}")
    return Success(paymasterAndData)


@method
def pm_getApprovedTokens() -> Result:
    start_time = time.time()
    result = []
    for approved_token in approved_tokens:
        token = approved_token.chains[chainid]
        if (token["enabled"]):
            result.append({
                "tokenName": approved_token.name,
                "tokenAddress": token["address"],
                "tokenDecimals": token["decimals"],
                "exchangeRateToNative": _get_token_rate(token),
                "entryPointAddress": entrypoint_address,
                "paymasterAddress": paymaster_address
            })
    end_time = time.time()
    duration = round((end_time - start_time), 3) * 1000
    logger.info(f"pm_getApprovedTokens {duration}ms")
    return Success(result)


def _get_token_rate(token):
    data = requests.get(token["exchangeRateSource"]).content.decode()
    rate = round(float(pattern.search(data).group(1)) * (10 ** token["decimals"]))
    return rate


def _get_max_token_cost(op, token_rate) -> int:
    max_gas_cost = op["callGasLimit"] + op["verificationGasLimit"] * 3 + op["preVerificationGas"]
    if (op["maxFeePerGas"] == op["maxPriorityFeePerGas"]):
        gas_price = op["maxFeePerGas"]
    else:
        gas_price = min(op["maxFeePerGas"], op["maxPriorityFeePerGas"] + w3.eth.get_block("latest").baseFeePerGas)
    actual_token_cost = int((max_gas_cost + 35000) * gas_price * token_rate / 1e18)
    return actual_token_cost


def _check_balance_and_allowance(op, token_address, token_rate) -> Result:
    ierc20 = w3.eth.contract(address=token_address, abi=ierc20_abi)
    max_token_cost = _get_max_token_cost(op, token_rate)

    balance = ierc20.functions.balanceOf(op["sender"]).call()
    if (balance < max_token_cost):
        return TempError(3, "Insufficient erc20 token to pay for gas", data=f"balance: {balance}, max_token_cost: {max_token_cost}")

    allowance = ierc20.functions.allowance(op["sender"], paymaster_address).call()
    # if current allowance is not enough, we need to check the calldata to see if the operation
    # will give the paymaster enough allowance
    if (allowance < max_token_cost):
        # require the second operation of the userOp to be a call to approve the paymaster
        calldata = op["callData"]
        function_selector = calldata[:10]
        # function selector of batchNormalExecute
        expected_selector_1 = "0x520237d1"
        # function selector of batchSudoExecute
        expected_selector_2 = "0x7e5f1c3f"
        if (function_selector != expected_selector_1 and function_selector != expected_selector_2):
            return TempError(4, "Invalid calldata", data="Invalid calldata")

        try:
            decodedCalldata = versawallet.decode_function_input(calldata)
            to = decodedCalldata[1]["to"]
            data = decodedCalldata[1]["data"]
            operation = decodedCalldata[1]["operation"]
            if len(to) < 2 or operation[1] != 0:
                return TempError(4, "Invalid calldata", data="Invalid calldata")

            # function selector of approve
            approve_selector = "0x095ea7b3"
            # the second operation must be a call to approve the paymaster
            approve_data = data[1]
            if approve_data.hex()[:8] != approve_selector[2:10]:
                return TempError(4, "Invalid calldata", data="Invalid calldata")

            decodedApproveData = ierc20.decode_function_input(approve_data)
            spender = decodedApproveData[1]["spender"]
            amount = decodedApproveData[1]["amount"]
            if (to[1] != token_address or spender != paymaster_address or amount < max_token_cost):
                return TempError(4, "Invalid calldata", data="Invalid calldata")
        except Exception as e:
            logger.info(f"_check_balance_and_allowance exception: {e}")
            return TempError(4, "Invalid calldata", data="Invalid calldata")
    return Success()


@csrf_exempt
def jsonrpc(request):
    return HttpResponse(
        dispatch(request.body.decode()), content_type="application/json"
    )
