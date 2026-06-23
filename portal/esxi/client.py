"""
ESXi standalone REST API client.
Compatible ESXi 7.0 / 8.0 sans vCenter.

Note : le certificat TLS ESXi est auto-signé par défaut → verify=False.
Les avertissements SSL sont supprimés intentionnellement (réseau lab interne).

Limites ESXi standalone (licence free) :
  - Pas de clonage VM (nécessite vCenter ou licence Standard+)
  - CPU/RAM en temps réel non exposés dans le listing REST
  - Suppression de VM possible uniquement si la VM est éteinte
"""

import base64
import requests
import urllib3

import config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _base(host):
    return f"https://{host}/api"


def _basic_header(user, password):
    creds = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {creds}", "Content-Type": "application/json"}


def _session_header(session_id):
    return {"vmware-api-session-id": session_id}


def get_session(host=None, user=None, password=None):
    """
    Crée une session ESXi et retourne (host, session_id).
    Utilise config.ESXI_* si les paramètres ne sont pas fournis.
    """
    host = host or config.ESXI_HOST
    user = user or config.ESXI_USER
    password = password or config.ESXI_PASSWORD
    r = requests.post(
        f"{_base(host)}/session",
        headers=_basic_header(user, password),
        verify=False,
        timeout=5,
    )
    r.raise_for_status()
    return host, r.json()


def list_vms(host, session_id):
    """
    Liste les VMs avec le format unifié compatible Proxmox :
    {vmid, name, status, cpu, maxmem, mem, uptime, tags, hypervisor}
    """
    r = requests.get(
        f"{_base(host)}/vcenter/vm",
        headers=_session_header(session_id),
        verify=False,
        timeout=8,
    )
    r.raise_for_status()
    result = []
    for vm in r.json():
        powered = vm.get("power_state", "POWERED_OFF") == "POWERED_ON"
        mem_mib = vm.get("memory_size_MiB", 0)
        result.append({
            "vmid":       vm["vm"],
            "name":       vm.get("name", vm["vm"]),
            "status":     "running" if powered else "stopped",
            "cpu":        0,
            "cpu_count":  vm.get("cpu_count", 0),
            "maxmem":     mem_mib * 1024 * 1024,
            "mem":        0,
            "uptime":     0,
            "tags":       "",
            "hypervisor": "esxi",
        })
    return result


def get_host_info(host, session_id):
    """Informations basiques sur le nœud ESXi (name, connection_state)."""
    try:
        r = requests.get(
            f"{_base(host)}/vcenter/host",
            headers=_session_header(session_id),
            verify=False,
            timeout=5,
        )
        if r.ok and r.json():
            h = r.json()[0]
            return {
                "name":             h.get("name", host),
                "connection_state": h.get("connection_state", "CONNECTED"),
                "power_state":      h.get("power_state", "POWERED_ON"),
            }
    except Exception:
        pass
    return {"name": host, "connection_state": "CONNECTED", "power_state": "POWERED_ON"}


def vm_action(host, session_id, vm_id, action):
    """
    Actions de contrôle de puissance.
    action : start | stop | reset | suspend
    Alias : shutdown → stop, reboot → reset (compat Proxmox)
    """
    action = {"shutdown": "stop", "reboot": "reset"}.get(action, action)
    if action not in {"start", "stop", "reset", "suspend"}:
        raise ValueError(f"Action ESXi non autorisée : {action}")
    r = requests.post(
        f"{_base(host)}/vcenter/vm/{vm_id}/power?action={action}",
        headers=_session_header(session_id),
        verify=False,
        timeout=10,
    )
    r.raise_for_status()
    return True
