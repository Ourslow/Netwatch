from proxmoxer import ProxmoxAPI
import config


def get_client():
    return ProxmoxAPI(
        config.PROXMOX_HOST,
        user=config.PROXMOX_USER,
        password=config.PROXMOX_PASSWORD,
        verify_ssl=config.PROXMOX_VERIFY_SSL,
        timeout=5,
    )


def get_node_status(px):
    """Ressources globales du nœud Proxmox."""
    node = config.PROXMOX_NODE
    status = px.nodes(node).status.get()
    return {
        "cpu_pct":  round(status["cpu"] * 100, 1),
        "ram_used": status["memory"]["used"],
        "ram_total": status["memory"]["total"],
        "ram_pct":  round(status["memory"]["used"] / status["memory"]["total"] * 100, 1),
        "disk_used": status["rootfs"]["used"],
        "disk_total": status["rootfs"]["total"],
        "uptime":   status["uptime"],
    }


def list_vms(px):
    """Liste toutes les VMs (QEMU) du nœud."""
    node = config.PROXMOX_NODE
    vms = px.nodes(node).qemu.get()
    result = []
    for vm in sorted(vms, key=lambda v: v["vmid"]):
        result.append({
            "vmid":       vm["vmid"],
            "name":       vm.get("name", f"vm-{vm['vmid']}"),
            "status":     vm["status"],
            "cpu":        vm.get("cpu", 0),
            "maxmem":     vm.get("maxmem", 0),
            "mem":        vm.get("mem", 0),
            "uptime":     vm.get("uptime", 0),
            "tags":       vm.get("tags", ""),
            "hypervisor": "proxmox",
        })
    return result


def vm_action(px, vmid, action):
    """start | stop | shutdown | reboot | reset."""
    node = config.PROXMOX_NODE
    allowed = {"start", "stop", "shutdown", "reboot", "reset"}
    if action not in allowed:
        raise ValueError(f"Action non autorisée : {action}")
    return px.nodes(node).qemu(vmid).status(action).post()


def create_vm_from_template(px, template_vmid, name, ram_mb, cpu, disk_gb, tags=""):
    """Clone un template et configure la nouvelle VM."""
    node = config.PROXMOX_NODE

    # Trouver un VMID libre (à partir de 200)
    existing_ids = {vm["vmid"] for vm in px.nodes(node).qemu.get()}
    new_vmid = next(i for i in range(200, 999) if i not in existing_ids)

    px.nodes(node).qemu(template_vmid).clone.post(
        newid=new_vmid,
        name=name,
        full=1,
    )

    # Attendre que le clone soit prêt (le clone est asynchrone)
    import time
    for _ in range(30):
        try:
            config_data = px.nodes(node).qemu(new_vmid).config.get()
            break
        except Exception:
            time.sleep(2)

    # Appliquer la config
    px.nodes(node).qemu(new_vmid).config.put(
        memory=ram_mb,
        cores=cpu,
        tags=tags,
    )

    return new_vmid


def delete_vm(px, vmid):
    node = config.PROXMOX_NODE
    # Arrêter d'abord si la VM tourne
    vm_list = list_vms(px)
    vm = next((v for v in vm_list if v["vmid"] == int(vmid)), None)
    if vm and vm["status"] == "running":
        px.nodes(node).qemu(vmid).status.stop.post()
        import time; time.sleep(3)
    return px.nodes(node).qemu(vmid).delete()
