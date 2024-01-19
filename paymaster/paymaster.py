import base64
import environ
import json
import logging
import os
import re
import requests
import time
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from eth_account import Account
from eth_account.messages import defunct_hash_message, encode_defunct
from jsonrpcserver import method, dispatch, Result, Success, Error
from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware
from .models import ApprovedTokens
from .serializers import OperationSerialzer


env = environ.Env()
logger = logging.getLogger(__name__)
w3 = Web3(HTTPProvider(env('RPC_URL')))
w3.middleware_onion.inject(geth_poa_middleware, layer=0)
chainid = str(w3.eth.chain_id)
approved_tokens = ApprovedTokens.objects.filter(chains__has_key=chainid)
pattern = re.compile(f'\"price\":\"(\d+\.\d+)\"')

free_privilege_flag = "0x0000000000000000000000000000000000000001"
free_privilege_signer_address = env('FREE_PRIVILEGE_SIGNER_ADDRESS')
entrypoint_address = env('ENTRYPOINT_CONTRACT_ADDRESS')
paymaster_address = env('PAYMASTER_CONTRACT_ADDRESS')
paymaster_verifier = w3.eth.account.from_key(env('PAYMASTER_VERIFYER_PRIVATE_KEY'))
paymaster_fee_percentage = int(env('PAYMASTER_FEE_PERCENTAGE'))

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "abis/PaymasterABI.json")) as f:
    paymaster_abi = json.load(f)
    paymaster = w3.eth.contract(address=paymaster_address, abi=paymaster_abi)
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "abis/VersaWalletABI.json")) as f:
    versawallet_abi = json.load(f)
    versawallet = w3.eth.contract(abi=versawallet_abi)
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "abis/IERC20ABI.json")) as f:
    ierc20_abi = json.load(f)


@method
def pm_sponsorUserOperation(context, user_operation, additional_data) -> Result:
    if len(additional_data) != 42:
        return Error(1, "additional data length mismatch", data="additional data length mismatch")
    token_address = Web3.to_checksum_address(additional_data)
    if token_address != free_privilege_flag:
        start_time = time.time()
        token_object = approved_tokens.filter(chains__icontains=token_address)
        if len(token_object) < 1:
            return Error(2, "unsupported token", data="unsupported token")
        token = token_object.first().chains[chainid]
        if token["address"] != token_address or not token["enabled"]:
            return Error(2, "unsupported token", data="unsupported token")
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

        payWithTokenModeData = [
            round(time.time()) + 300,  # validUntil 5 minutes in the future
            token["address"],
            token_rate,
            b''
        ]
        payWithTokenModeData[3] = paymaster_verifier.signHash(defunct_hash_message(paymaster.functions.getPayWithTokenModeHash(op, payWithTokenModeData).call())).signature.hex()
        paymasterAndData = f"{paymaster_address}01{payWithTokenModeData[0]:0>12x}{payWithTokenModeData[1][2:]}{payWithTokenModeData[2]:0>64x}{payWithTokenModeData[3][2:]}".lower()
        end_time = time.time()
        duration = round((end_time - start_time), 3) * 1000
        logger.info(f"pm_sponsorUserOperation {duration}ms sponsor_mode:PAY_WITH_TOKEN\nuser_operation:{user_operation}\ntoken_address:{token_address}\npaymasterAndData:{paymasterAndData}")
        return Success(paymasterAndData)
    else:
        start_time = time.time()
        free_privilege_signature = context.META.get('HTTP_AUTHORIZATION_VERSA_BACKEND', None)
        if not free_privilege_signature:
            return Error(3, "authorization header is missing", data="authorization header is missing")
        json_str = json.dumps(json.loads(context.body.decode()), separators=(',', ':'))
        message = base64.b64encode(json_str.encode()).decode()
        if _validate_free_privilege_signature(message, free_privilege_signature):
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

            freePrivilegeModeData = [
                round(time.time()) + 300,  # validUntil 5 minutes in the future
                b''
            ]
            freePrivilegeModeData[1] = paymaster_verifier.signHash(defunct_hash_message(paymaster.functions.getFreePrivilegeModeHash(op, freePrivilegeModeData).call())).signature.hex()
            paymasterAndData = f"{paymaster_address}00{freePrivilegeModeData[0]:0>12x}{freePrivilegeModeData[1][2:]}".lower()
            end_time = time.time()
            duration = round((end_time - start_time), 3) * 1000
            logger.info(f"pm_sponsorUserOperation {duration}ms sponsor_mode:FREE_PRIVILEGE\nuser_operation:{user_operation}\ntoken_address:{token_address}\npaymasterAndData:{paymasterAndData}")
            return Success(paymasterAndData)
        else:
            return Error(4, "validate signature failed", data="validate signature failed")


@method
def pm_getApprovedTokens(context) -> Result:
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
    rate = round(float(pattern.search(data).group(1)) * float(1 + paymaster_fee_percentage/100) * (10 ** token["decimals"]))
    return rate


def _validate_free_privilege_signature(message, signature):
    try:
        recovered_address = Account.recover_message(encode_defunct(text=message), signature=signature)
        logger.info(recovered_address)
        if Web3.to_checksum_address(recovered_address) == Web3.to_checksum_address(free_privilege_signer_address):
            return True
        else:
            return False
    except Exception as e:
        logger.error(f"_validate_free_privilege_signature exception:{e}")
        return False


@csrf_exempt
def jsonrpc(request):
    return HttpResponse(
        dispatch(request.body.decode(), context=request), content_type="application/json"
    )
