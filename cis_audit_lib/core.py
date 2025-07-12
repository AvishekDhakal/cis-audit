import paramiko
from .checks import get_checks
import argparse
import json
import logging

# Configure module-level logger
logger = logging.getLogger(__name__)


def scan_host(host, user='root', key=None, port=22, timeout=10):
    """
    Connects via SSH to the target, runs all checks, and aggregates results.
    Returns a dict with:
      - findings: list of check result dicts
      - overall_compliance: float percentage of PASS controls
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=host, username=user, key_filename=key,
                       port=port, timeout=timeout)
    except Exception as e:
        logger.exception("SSH connection failed to %s", host)
        return {
            'findings': [],
            'overall_compliance': 0.0,
            'error': f'SSH connection failed: {e}'
        }

    findings = []
    total = 0
    passed = 0

    for check_func in get_checks():
        try:
            result = check_func(client)
        except Exception as e:
            logger.exception("Error during check %s", check_func.__name__)
            result = {
                'control_id': getattr(check_func, '__name__', 'unknown'),
                'description': '',
                'status': 'FAIL',
                'details': f'Exception: {e}'
            }
        findings.append(result)
        total += 1
        if result.get('status') == 'PASS':
            passed += 1

    client.close()

    overall = round((passed / total * 100), 2) if total else 0.0
    return {
        'findings': findings,
        'overall_compliance': overall
    }


def scan_cli():
    """
    CLI entry point for cis-scan.
    """
    parser = argparse.ArgumentParser(description="CIS Audit Scanner")
    parser.add_argument("--host", required=True, help="Target hostname or IP")
    parser.add_argument("--user", default="root", help="SSH user")
    parser.add_argument("--key", help="Path to SSH private key")
    parser.add_argument("--port", type=int, default=22, help="SSH port")
    parser.add_argument("--timeout", type=int, default=10, help="SSH timeout seconds")
    args = parser.parse_args()

    result = scan_host(
        host=args.host,
        user=args.user,
        key=args.key,
        port=args.port,
        timeout=args.timeout
    )
    print(json.dumps(result, indent=2))
