#!/usr/bin/env python
import argparse
import os


def main():
    parser = argparse.ArgumentParser(description='Overwrite values in os.environ with optional command-line arguments')
    parser.add_argument('--port', help='Port Number', type=int)
    parser.add_argument('--rpc', help='The Ethereum Network RPC Url', type=str)
    parser.add_argument('--chainid', help='The Ethereum Network Chain ID', type=int)
    parser.add_argument('--entrypoint', help='The entrypoint address', type=str)
    parser.add_argument('--paymaster', help='The paymaster address', type=str)
    args, remaining_argv = parser.parse_known_args()

    if args.port:
        os.environ["PORT"] = str(args.port)
    if args.rpc:
        os.environ["RPC"] = args.rpc
    if args.chainid:
        os.environ["CHAINID"] = str(args.chainid)
    if args.entrypoint:
        os.environ["ENTRYPOINT_CONTRACT_ADDRESS"] = args.entrypoint
    if args.paymaster:
        os.environ["PAYMASTER_CONTRACT_ADDRESS"] = args.paymaster

    if 'runserver' in remaining_argv:
        if args.port:
            remaining_argv += ['{}'.format(args.port)]

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "paymaster.settings")

    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc

    execute_from_command_line(['manage.py'] + remaining_argv)


if __name__ == "__main__":
    main()
