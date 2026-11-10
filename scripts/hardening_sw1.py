#!/usr/bin/env python3
"""hardening_sw1.py

Aplica al switch SW1 reglas del CIS Benchmark de Cisco IOS y genera un informe
posterior a la aplicación en informes/informe-posterior-<fecha-hora>.md.

Uso:
    python3 hardening_sw1.py
"""
import getpass
import re
from datetime import datetime
from pathlib import Path

from netmiko import ConnectHandler

HOST = "10.7.30.3"
MGMT_HOSTS = ("10.7.30.4", "10.7.30.253")
BANNER = "ACCESO RESTRINGIDO. Solo personal autorizado. Toda actividad es registrada."

_enable_secret = None


def enable_secret():
    global _enable_secret
    if _enable_secret is None:
        _enable_secret = getpass.getpass("Nuevo enable secret: ")
    return _enable_secret


def has(cfg, pattern):
    return re.search(pattern, cfg, re.M) is not None


def blocks(cfg, header):
    """Devuelve las líneas hijas de cada bloque cuyo encabezado coincide."""
    out, cur = [], None
    for line in cfg.splitlines():
        if re.match(header, line):
            cur = []
            out.append(cur)
        elif cur is not None and line.startswith(" "):
            cur.append(line.strip())
        else:
            cur = None
    return out


def timeout_ok(lines):
    m = re.search(r"exec-timeout (\d+)(?: (\d+))?", " ".join(lines))
    return bool(m) and 0 < int(m.group(1)) * 60 + int(m.group(2) or 0) <= 300


def unused_ports(brief):
    pattern = r"^((?:Gi|Fa|Te|Et)\S+)\s+\S+\s+\S+\s+\S+\s+down\s+down\s*$"
    return re.findall(pattern, brief, re.M)


def vty_ok(ctx):
    bl = blocks(ctx["cfg"], r"^line vty")
    return bool(bl) and all(
        "transport input ssh" in b
        and timeout_ok(b)
        and any(x.startswith("access-class") for x in b)
        for b in bl
    )


def vty_fix(ctx):
    cmds = ["no ip access-list standard MGMT-SSH", "ip access-list standard MGMT-SSH"]
    cmds += [f"permit host {h}" for h in MGMT_HOSTS]
    cmds += ["deny any log", "exit"]
    for rng in re.findall(r"^line vty (\d+ \d+)", ctx["cfg"], re.M) or ["0 4"]:
        cmds += [f"line vty {rng}", "transport input ssh", "exec-timeout 5 0",
                 "access-class MGMT-SSH in", "exit"]
    return cmds


def unused_fix(ctx):
    cmds = []
    for port in unused_ports(ctx["brief"]):
        cmds += [f"interface {port}", "shutdown", "exit"]
    return cmds


# (id, sección, descripción, verificación, remediación)
RULES = [
    ("R01", "Management Plane", "Cifrado de contraseñas",
     lambda c: has(c["cfg"], r"^service password-encryption"),
     lambda c: ["service password-encryption"]),
    ("R02", "Management Plane", "enable secret robusto, sin enable password",
     lambda c: has(c["cfg"], r"^enable secret 9 ") and not has(c["cfg"], r"^enable password"),
     lambda c: ["no enable password", f"enable algorithm-type scrypt secret {enable_secret()}"]),
    ("R03", "Management Plane", "Banners de advertencia (login y exec)",
     lambda c: has(c["cfg"], r"^banner login") and has(c["cfg"], r"^banner exec"),
     lambda c: [f"banner login #{BANNER}#", f"banner exec #{BANNER}#"]),
    ("R04", "Management Plane", "SSH v2, time-out de 60 s y 3 reintentos",
     lambda c: has(c["cfg"], r"^ip ssh version 2")
     and has(c["cfg"], r"^ip ssh time-out 60")
     and has(c["cfg"], r"^ip ssh authentication-retries 3"),
     lambda c: ["ip ssh version 2", "ip ssh time-out 60", "ip ssh authentication-retries 3"]),
    ("R05", "Management Plane", "VTY: solo SSH, inactividad de 5 min y ACL de gestión",
     vty_ok, vty_fix),
    ("R06", "Management Plane", "Consola con tiempo de inactividad de 5 min",
     lambda c: bool(blocks(c["cfg"], r"^line con 0"))
     and all(timeout_ok(b) for b in blocks(c["cfg"], r"^line con 0")),
     lambda c: ["line con 0", "exec-timeout 5 0", "logging synchronous", "exit"]),
    ("R07", "Management Plane", "Servidor HTTP/HTTPS apagado",
     lambda c: not has(c["cfg"], r"^ip http (server|secure-server)"),
     lambda c: ["no ip http server", "no ip http secure-server"]),
    ("R08", "Management Plane", "Registro con marca de tiempo y buffer",
     lambda c: has(c["cfg"], r"^service timestamps log datetime")
     and has(c["cfg"], r"^logging buffered"),
     lambda c: ["service timestamps log datetime msec localtime show-timezone",
                "service timestamps debug datetime msec localtime show-timezone",
                "logging buffered 64000 informational"]),
    ("R09", "Control Plane", "Servicios innecesarios apagados (pad, source-route, bootp, CDP)",
     lambda c: all(has(c["cfg"], p) for p in (
         r"^no service pad", r"^no ip source-route", r"^no ip bootp server", r"^no cdp run")),
     lambda c: ["no service pad", "no ip source-route", "no ip bootp server", "no cdp run"]),
    ("R10", "Complementaria", "Puertos sin uso apagados",
     lambda c: not unused_ports(c["brief"]),
     unused_fix),
]


def get_ctx(conn):
    return {
        "cfg": conn.send_command("show running-config"),
        "brief": conn.send_command("show ip interface brief"),
    }


def evaluate(ctx):
    return [bool(rule[3](ctx)) for rule in RULES]


def write_report(antes, despues, observaciones):
    ahora = datetime.now()
    estado = lambda ok: "Cumple" if ok else "No cumple"
    lines = [
        "# Informe posterior a la aplicación de hardening: SW1",
        "",
        f"Fecha: {ahora:%Y-%m-%d %H:%M:%S}",
        f"Equipo: SW1 ({HOST})",
        "",
        "| ID | Sección | Regla | Antes | Después | Observación |",
        "|---|---|---|---|---|---|",
    ]
    for rule, a, d in zip(RULES, antes, despues):
        obs = observaciones.get(rule[0], "")
        lines.append(f"| {rule[0]} | {rule[1]} | {rule[2]} | {estado(a)} | {estado(d)} | {obs} |")
    lines += ["", f"Cumplimiento antes: {sum(antes)}/{len(RULES)}",
              f"Cumplimiento después: {sum(despues)}/{len(RULES)}"]
    folder = Path("informes")
    folder.mkdir(exist_ok=True)
    path = folder / f"informe-posterior-{ahora:%Y%m%d-%H%M%S}.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))
    print(f"\nInforme guardado en {path}")


def main():
    user = input("Usuario [admin-local]: ") or "admin-local"
    password = getpass.getpass("Contraseña: ")
    conn = ConnectHandler(device_type="cisco_ios", host=HOST, username=user, password=password)

    ctx = get_ctx(conn)
    antes = evaluate(ctx)
    observaciones = {}

    for rule, ok in zip(RULES, antes):
        if ok:
            continue
        print(f"[*] Aplicando {rule[0]}: {rule[2]}")
        cmds = rule[4](ctx)
        if not cmds:
            continue
        salida = conn.send_config_set(cmds)
        errores = [l.strip() for l in salida.splitlines() if l.startswith("%")]
        if errores:
            observaciones[rule[0]] = "; ".join(errores)

    conn.save_config()
    despues = evaluate(get_ctx(conn))
    conn.disconnect()
    write_report(antes, despues, observaciones)


if __name__ == "__main__":
    main()
