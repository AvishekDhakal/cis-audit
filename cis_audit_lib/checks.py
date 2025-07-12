import logging

# Configure module-level logger
logger = logging.getLogger(__name__)


def check_ssh_root_login(ssh_client):
    """
    Control ID: 1.1.1
    Disable SSH root login by ensuring 'PermitRootLogin no'.
    """
    control_id = "1.1.1"
    description = "Disable SSH root login (PermitRootLogin no)"
    try:
        stdin, stdout, stderr = ssh_client.exec_command(
            "grep -E '^PermitRootLogin' /etc/ssh/sshd_config || echo 'MISSING'"
        )
        line = stdout.read().decode().strip()
        if line == 'MISSING':
            status = 'FAIL'
            details = 'Directive not found'
        elif 'no' in line:
            status = 'PASS'
            details = line
        else:
            status = 'FAIL'
            details = line
    except Exception as e:
        status = 'FAIL'
        details = f'Error executing SSH command: {e}'
        logger.exception("check_ssh_root_login failed")
    return {"control_id": control_id, "description": description, "status": status, "details": details}


def check_ssh_protocol(ssh_client):
    """
    Control ID: 1.2.2
    Ensure SSH uses Protocol 2 only.
    """
    control_id = "1.2.2"
    description = "Use SSH Protocol 2 only"
    try:
        stdin, stdout, stderr = ssh_client.exec_command(
            "grep -E '^Protocol' /etc/ssh/sshd_config || echo 'MISSING'"
        )
        line = stdout.read().decode().strip()
        if line == 'MISSING':
            status = 'FAIL'
            details = 'Directive not found'
        elif line.endswith('2'):
            status = 'PASS'
            details = line
        else:
            status = 'FAIL'
            details = line
    except Exception as e:
        status = 'FAIL'
        details = f'Error executing SSH command: {e}'
        logger.exception("check_ssh_protocol failed")
    return {"control_id": control_id, "description": description, "status": status, "details": details}


def check_ufw_installed(ssh_client):
    """
    Control ID: FW-1
    Ensure UFW firewall package is installed.
    """
    control_id = "FW-1"
    description = "UFW must be installed"
    try:
        stdin, stdout, stderr = ssh_client.exec_command("which ufw || echo 'MISSING'")
        path = stdout.read().decode().strip()
        if path == 'MISSING' or not path:
            status = 'FAIL'
            details = 'ufw not found'
        else:
            status = 'PASS'
            details = path
    except Exception as e:
        status = 'FAIL'
        details = f'Error checking ufw install: {e}'
        logger.exception("check_ufw_installed failed")
    return {"control_id": control_id, "description": description, "status": status, "details": details}


def check_ufw_enabled(ssh_client):
    """
    Control ID: FW-2
    Ensure UFW firewall is enabled (status 'active').
    """
    control_id = "FW-2"
    description = "UFW must be enabled"
    try:
        # The first line of `ufw status` shows its status
        stdin, stdout, stderr = ssh_client.exec_command("ufw status | head -n1")
        status_line = stdout.read().decode().strip().lower()
        if 'active' in status_line:
            status = 'PASS'
            details = status_line
        else:
            status = 'FAIL'
            details = status_line
    except Exception as e:
        status = 'FAIL'
        details = f'Error checking ufw status: {e}'
        logger.exception("check_ufw_enabled failed")
    return {"control_id": control_id, "description": description, "status": status, "details": details}


def check_password_expiration(ssh_client):
    """
    Control ID: PP-1
    Ensure password expiration (PASS_MAX_DAYS <= 90).
    """
    control_id = "PP-1"
    description = "Password max days must be <= 90"
    try:
        cmd = "grep ^PASS_MAX_DAYS /etc/login.defs | awk '{print $2}' || echo 'MISSING'"
        stdin, stdout, stderr = ssh_client.exec_command(cmd)
        val = stdout.read().decode().strip()
        if val == 'MISSING' or not val.isdigit():
            status = 'FAIL'
            details = f'Invalid or missing value: {val}'
        else:
            days = int(val)
            if days <= 90:
                status = 'PASS'
            else:
                status = 'FAIL'
            details = f'PASS_MAX_DAYS = {days}'
    except Exception as e:
        status = 'FAIL'
        details = f'Error checking PASS_MAX_DAYS: {e}'
        logger.exception("check_password_expiration failed")
    return {"control_id": control_id, "description": description, "status": status, "details": details}


def check_password_complexity(ssh_client):
    """
    Control ID: PP-2
    Ensure password complexity, min length >= 14.
    """
    control_id = "PP-2"
    description = "Password min length must be >= 14"
    try:
        cmd = "grep ^minlen /etc/security/pwquality.conf | awk -F'=' '{print $2}' || echo 'MISSING'"
        stdin, stdout, stderr = ssh_client.exec_command(cmd)
        val = stdout.read().decode().strip()
        if val == 'MISSING' or not val.isdigit():
            status = 'FAIL'
            details = f'Invalid or missing minlen: {val}'
        else:
            length = int(val)
            if length >= 14:
                status = 'PASS'
            else:
                status = 'FAIL'
            details = f'minlen = {length}'
    except Exception as e:
        status = 'FAIL'
        details = f'Error checking password complexity: {e}'
        logger.exception("check_password_complexity failed")
    return {"control_id": control_id, "description": description, "status": status, "details": details}


def check_apache_dir_listing(ssh_client):
    """
    Control ID: AP-1
    Ensure Apache directory listing is disabled (Options -Indexes).
    """
    control_id = "AP-1"
    description = "Disable Apache directory listing (Options -Indexes)"
    try:
        cmd = "grep -R 'Options.*Indexes' /etc/apache2 || echo 'NOT FOUND'"
        stdin, stdout, stderr = ssh_client.exec_command(cmd)
        result = stdout.read().decode().strip()
        if result == 'NOT FOUND':
            status = 'PASS'
            details = 'No directory listing directive found'
        else:
            status = 'FAIL'
            details = result
    except Exception as e:
        status = 'FAIL'
        details = f'Error checking Apache directory listing: {e}'
        logger.exception("check_apache_dir_listing failed")
    return {"control_id": control_id, "description": description, "status": status, "details": details}


def check_mysql_root_password(ssh_client):
    """
    Control ID: DB-1
    Ensure MySQL root user has a password set.
    """
    control_id = "DB-1"
    description = "MySQL root user must have a password"
    try:
        # Attempt to retrieve authentication_string for root user
        cmd = ("mysql -e \"SELECT authentication_string FROM mysql.user "
               "WHERE User='root' AND Host='localhost';\" 2>/dev/null || echo 'ERROR' ")
        stdin, stdout, stderr = ssh_client.exec_command(cmd)
        output = stdout.read().decode().strip()
        if not output or 'ERROR' in output:
            status = 'FAIL'
            details = 'Unable to retrieve root password status'
        else:
            lines = output.splitlines()
            # Skip header line if present
            val = lines[1].strip() if len(lines) > 1 else ''
            if val:
                status = 'PASS'
            else:
                status = 'FAIL'
            details = f'authentication_string = "{val}"'
    except Exception as e:
        status = 'FAIL'
        details = f'Error checking MySQL root password: {e}'
        logger.exception("check_mysql_root_password failed")
    return {"control_id": control_id, "description": description, "status": status, "details": details}


# Export list of checks
def get_checks():
    """
    Return a list of all available check functions.
    """
    return [
        check_ssh_root_login,
        check_ssh_protocol,
        check_ufw_installed,
        check_ufw_enabled,
        check_password_expiration,
        check_password_complexity,
        check_apache_dir_listing,
        check_mysql_root_password,
    ]
